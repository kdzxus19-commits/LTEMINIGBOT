// LTE Mining Edge Function
// Deploy with: supabase functions deploy lte-mining-api
// Required Edge Function secrets:
//   TELEGRAM_BOT_TOKEN
//   SERVICE_ROLE_KEY
// Never expose either secret in the frontend.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function constantTimeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

function hex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)].map((v) => v.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(key: Uint8Array, message: string) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign(
    "HMAC", cryptoKey, new TextEncoder().encode(message),
  ));
}

async function verifyTelegramInitData(initData: string, botToken: string) {
  if (!initData || initData.length > 10000) throw new Error("Missing or invalid Telegram initData");
  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  const authDate = Number(params.get("auth_date"));
  const userRaw = params.get("user");
  if (!receivedHash || !/^\d+$/.test(String(authDate)) || !userRaw) {
    throw new Error("Telegram initData is incomplete");
  }

  const now = Math.floor(Date.now() / 1000);
  if (authDate > now + 60 || now - authDate > 86400) {
    throw new Error("Telegram session expired. Reopen the Mini App.");
  }

  const checkString = [...params.entries()]
    .filter(([key]) => key !== "hash")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = await hmacSha256(new TextEncoder().encode("WebAppData"), botToken);
  const calculatedHash = hex(await crypto.subtle.sign(
    "HMAC",
    await crypto.subtle.importKey("raw", secretKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    new TextEncoder().encode(checkString),
  ));

  if (!constantTimeEqual(calculatedHash, receivedHash)) {
    throw new Error("Telegram signature verification failed");
  }

  const user = JSON.parse(userRaw);
  if (!user.id || !Number.isSafeInteger(Number(user.id))) throw new Error("Invalid Telegram user");
  return user;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  if (req.method === "GET") {
    return json({ success: true, project: "LTE Mining", message: "Backend connected successfully" });
  }

  if (req.method !== "POST") return json({ success: false, error: "Method not allowed" }, 405);

  try {
    const botToken = Deno.env.get("TELEGRAM_BOT_TOKEN");
    const serviceRoleKey = Deno.env.get("SERVICE_ROLE_KEY");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    if (!botToken || !serviceRoleKey || !supabaseUrl) {
      return json({ success: false, error: "Server secrets are not configured" }, 500);
    }

    const body = await req.json();
    const user = await verifyTelegramInitData(body?.initData, botToken);
    const telegramId = Number(user.id);
    const supabase = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    if (body?.action === "sync-profile") {
      const { error } = await supabase.from("profiles").upsert({
        telegram_id: telegramId,
        username: user.username ?? null,
      }, { onConflict: "telegram_id", ignoreDuplicates: false });
      if (error) {
        console.error("Profile upsert failed:", error.message);
        return json({ success: false, error: "Could not save Telegram profile" }, 500);
      }

      const referralCode = String(body?.referralCode ?? "").trim().toUpperCase();
      if (referralCode) {
        const { data: inviter } = await supabase.from("profiles")
          .select("telegram_id").eq("referral_code", referralCode).maybeSingle();
        if (inviter && Number(inviter.telegram_id) !== telegramId) {
          const { error: bindError } = await supabase.from("profiles").update({ referred_by: Number(inviter.telegram_id) })
            .eq("telegram_id", telegramId).is("referred_by", null);
          if (bindError) console.error("Referral binding failed:", bindError.message);
        }
      }

      const { data: profile } = await supabase.from("profiles")
        .select("referral_code, wallet_address").eq("telegram_id", telegramId).single();
      return json({
        success: true,
        message: "Telegram account verified and profile synchronized",
        telegram_id: telegramId,
        username: user.username ?? null,
        referral_code: profile?.referral_code ?? null,
        wallet_address: profile?.wallet_address ?? null,
      });
    }

    if (body?.action === "link-wallet") {
      const address = String(body?.address ?? "").trim();
      const validTonAddress =
        /^(?:-1|0):[0-9a-fA-F]{64}$/.test(address) ||
        /^(?:EQ|UQ|kQ|0Q)[A-Za-z0-9_-]{46,50}$/.test(address);
      if (!validTonAddress) return json({ success: false, error: "Invalid TON wallet address" }, 400);

      const { data: profile, error: profileError } = await supabase
        .from("profiles").select("telegram_id, wallet_address")
        .eq("telegram_id", telegramId).maybeSingle();
      if (profileError || !profile) return json({ success: false, error: "Telegram profile not found. Reopen the app." }, 404);
      if (profile.wallet_address && profile.wallet_address !== address) {
        return json({ success: false, error: "A wallet is already linked to this account. Contact support to change it." }, 409);
      }

      const { error: saveError } = await supabase.from("profiles")
        .update({ wallet_address: address, wallet_linked_at: new Date().toISOString() })
        .eq("telegram_id", telegramId);
      if (saveError) {
        if (saveError.code === "23505") return json({ success: false, error: "This wallet is already linked to another account." }, 409);
        console.error("Wallet save failed:", saveError.message);
        return json({ success: false, error: "Could not save wallet address" }, 500);
      }

      // Linking a wallet alone no longer qualifies a referral.
      // Referral rewards are issued only after a confirmed 0.05 GRAM payment.
      return json({
        success: true,
        wallet_address: address,
        referral_rewarded: false,
        referral_status: "payment_required",
        message: "Wallet address linked. A confirmed 0.05 GRAM payment is required to qualify the referral.",
      });
    }

    if (body?.action === "get-referrals") {
      const { data: profile, error: profileError } = await supabase.from("profiles")
        .select("referral_code, wallet_address").eq("telegram_id", telegramId).maybeSingle();
      if (profileError || !profile) return json({ success: false, error: "Profile not found" }, 404);
      const { count, error: countError } = await supabase.from("lte_referrals")
        .select("id", { count: "exact", head: true })
        .eq("inviter_telegram_id", telegramId).eq("status", "qualified");
      if (countError) return json({ success: false, error: "Could not load referrals" }, 500);
      return json({ success: true, referral_code: profile.referral_code, qualified_count: count ?? 0, wallet_address: profile.wallet_address });
    }

    return json({ success: false, error: "Unknown action" }, 400);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed";
    return json({ success: false, error: message }, 401);
  }
});
