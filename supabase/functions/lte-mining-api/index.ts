// LTE Mining Edge Function
// Deploy with: supabase functions deploy lte-mining-api
// Required Edge Function secrets:
//   TELEGRAM_BOT_TOKEN
//   SERVICE_ROLE_KEY
// Never expose either secret in the frontend.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { Address } from "https://esm.sh/@ton/core@0.59.1";

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


function rawTonAddress(value: string) {
  try { return Address.parse(value).toRawString().toLowerCase(); }
  catch { return ""; }
}

async function findConfirmedPayment(sourceAddress: string, createdAt: string) {
  const destination = "UQDt-rCzwylBWPzIx8toN3jNuvTnSzVh_NPxhQUSjsN1zWgY";
  const response = await fetch("https://toncenter.com/api/v2/getTransactions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({ address: destination, limit: 30 }),
  });
  if (!response.ok) throw new Error("Could not check the TON network. Try again shortly.");
  const payload = await response.json();
  if (!payload?.ok || !Array.isArray(payload.result)) throw new Error("TON network returned an invalid response.");
  const expectedSource = rawTonAddress(sourceAddress);
  const expectedDestination = rawTonAddress(destination);
  const notBefore = Math.floor(new Date(createdAt).getTime() / 1000) - 90;
  for (const tx of payload.result) {
    const msg = tx?.in_msg;
    if (!msg || msg.bounced === true || tx?.description?.aborted === true) continue;
    if (Number(msg.value) !== 50000000) continue;
    if (Number(tx.utime) < notBefore) continue;
    if (rawTonAddress(msg.source || "") !== expectedSource) continue;
    if (rawTonAddress(msg.destination || "") !== expectedDestination) continue;
    const hash = String(tx?.transaction_id?.hash || "");
    if (hash) return hash;
  }
  return null;
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

      const { data: profile } = await supabase.from("profiles")
        .select("wallet_address").eq("telegram_id", telegramId).single();
      return json({
        success: true,
        message: "Telegram account verified and profile synchronized",
        telegram_id: telegramId,
        username: user.username ?? null,
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

      return json({ success: true, wallet_address: address, message: "TON wallet address linked." });
    }


    if (body?.action === "create-payment") {
      const { data: profile, error: profileError } = await supabase.from("profiles")
        .select("wallet_address").eq("telegram_id", telegramId).maybeSingle();
      if (profileError || !profile) return json({ success: false, error: "Profile not found" }, 404);
      if (!profile.wallet_address) return json({ success: false, error: "Link your TON wallet first." }, 400);

      const { data: alreadyPaid, error: paidError } = await supabase.from("lte_payments")
        .select("id").eq("telegram_id", telegramId).eq("status", "confirmed").limit(1);
      if (paidError) return json({ success: false, error: "Could not check previous payment." }, 500);
      if (alreadyPaid?.length) return json({ success: false, error: "A payment is already confirmed for this account." }, 409);

      const { data: existing, error: existingError } = await supabase.from("lte_payments")
        .select("id, created_at").eq("telegram_id", telegramId).eq("status", "pending")
        .order("created_at", { ascending: false }).limit(1).maybeSingle();
      if (existingError) return json({ success: false, error: "Could not create payment request." }, 500);
      if (existing) return json({ success: true, payment_id: existing.id, amount_nano: 50000000 });

      const { data: payment, error: insertError } = await supabase.from("lte_payments")
        .insert({
          telegram_id: telegramId,
          amount_nano: 50000000,
          destination_address: "UQDt-rCzwylBWPzIx8toN3jNuvTnSzVh_NPxhQUSjsN1zWgY",
          status: "pending",
        }).select("id").single();
      if (insertError || !payment) {
        console.error("Payment request insert failed:", insertError?.message);
        return json({ success: false, error: "Could not create payment request. Please retry." }, 500);
      }
      return json({ success: true, payment_id: payment.id, amount_nano: 50000000 });
    }

    if (body?.action === "verify-payment") {
      const { data: profile, error: profileError } = await supabase.from("profiles")
        .select("wallet_address").eq("telegram_id", telegramId).maybeSingle();
      if (profileError || !profile) return json({ success: false, error: "Profile not found" }, 404);
      if (!profile.wallet_address) return json({ success: false, error: "Link your TON wallet first." }, 400);

      const { data: payment, error: paymentError } = await supabase.from("lte_payments")
        .select("id, created_at, status, transaction_hash")
        .eq("telegram_id", telegramId).eq("status", "pending")
        .order("created_at", { ascending: false }).limit(1).maybeSingle();
      if (paymentError) return json({ success: false, error: "Could not load payment request." }, 500);
      if (!payment) {
        const { data: confirmed } = await supabase.from("lte_payments")
          .select("id, transaction_hash").eq("telegram_id", telegramId)
          .eq("status", "confirmed").limit(1).maybeSingle();
        if (confirmed) {
          return json({ success: true, status: "confirmed", already_confirmed: true, message: "Activation payment already confirmed." });
        }
        return json({ success: false, error: "No pending payment was found. Start the payment first." }, 404);
      }

      const txHash = await findConfirmedPayment(profile.wallet_address, payment.created_at);
      if (!txHash) return json({ success: true, status: "pending", message: "Payment not found yet. Wait for network confirmation and try again." });

      const { error: updateError } = await supabase.from("lte_payments")
        .update({ status: "confirmed", transaction_hash: txHash, confirmed_at: new Date().toISOString() })
        .eq("id", payment.id).eq("status", "pending");
      if (updateError) {
        console.error("Payment confirmation update failed:", updateError.message);
        return json({ success: false, error: "Could not record payment confirmation. Please retry." }, 500);
      }

      return json({
        success: true,
        status: "confirmed",
        transaction_hash: txHash,
        message: "Activation payment confirmed on the TON network.",
      });
    }

    if (body?.action === "get-payment-status") {
      const { data: profile, error: profileError } = await supabase.from("profiles")
        .select("wallet_address").eq("telegram_id", telegramId).maybeSingle();
      if (profileError || !profile) return json({ success: false, error: "Profile not found" }, 404);
      const { data: confirmed, error: confirmedError } = await supabase.from("lte_payments")
        .select("id, transaction_hash").eq("telegram_id", telegramId)
        .eq("status", "confirmed").limit(1).maybeSingle();
      if (confirmedError) return json({ success: false, error: "Could not check activation status." }, 500);
      const { data: pending, error: pendingError } = await supabase.from("lte_payments")
        .select("id, created_at").eq("telegram_id", telegramId).eq("status", "pending")
        .order("created_at", { ascending: false }).limit(1).maybeSingle();
      if (pendingError) return json({ success: false, error: "Could not check pending payment." }, 500);
      return json({
        success: true,
        status: confirmed ? "confirmed" : pending ? "pending" : "unpaid",
        wallet_address: profile.wallet_address,
        transaction_hash: confirmed?.transaction_hash ?? null,
      });
    }


    return json({ success: false, error: "Unknown action" }, 400);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed";
    return json({ success: false, error: message }, 401);
  }
});
