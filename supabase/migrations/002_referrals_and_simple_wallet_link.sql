-- LTE Mining: simple TON wallet linking and one-time referral rewards.
-- Run once in the Supabase SQL Editor before deploying the updated Edge Function.

alter table public.profiles
  add column if not exists referral_code text,
  add column if not exists referred_by bigint references public.profiles(telegram_id) on delete set null;

alter table public.profiles
  alter column referral_code set default upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10));

update public.profiles
set referral_code = upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10))
where referral_code is null or referral_code = '';

create unique index if not exists profiles_referral_code_uidx
  on public.profiles(referral_code);
create unique index if not exists profiles_wallet_address_uidx
  on public.profiles(wallet_address)
  where wallet_address is not null and wallet_address <> '';

create table if not exists public.lte_referrals (
  id uuid primary key default gen_random_uuid(),
  inviter_telegram_id bigint not null references public.profiles(telegram_id) on delete cascade,
  invitee_telegram_id bigint not null unique references public.profiles(telegram_id) on delete cascade,
  status text not null default 'qualified' check (status in ('qualified')),
  reward_amount numeric(20,8) not null default 50,
  qualified_at timestamptz not null default now(),
  constraint lte_referrals_no_self check (inviter_telegram_id <> invitee_telegram_id)
);
alter table public.lte_referrals enable row level security;

create or replace function public.qualify_lte_referral(p_invitee_telegram_id bigint)
returns table(rewarded boolean)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_inviter bigint;
  v_inserted integer;
begin
  select referred_by into v_inviter
  from public.profiles
  where telegram_id = p_invitee_telegram_id and wallet_address is not null
  for update;

  if v_inviter is null or v_inviter = p_invitee_telegram_id then
    return query select false;
    return;
  end if;

  insert into public.lte_referrals(inviter_telegram_id, invitee_telegram_id, status, reward_amount)
  values (v_inviter, p_invitee_telegram_id, 'qualified', 50)
  on conflict (invitee_telegram_id) do nothing;
  get diagnostics v_inserted = row_count;

  if v_inserted = 1 then
    update public.profiles
    set balance = coalesce(balance, 0) + 50,
        total_earned = coalesce(total_earned, 0) + 50
    where telegram_id = v_inviter;
    return query select true;
  else
    return query select false;
  end if;
end;
$$;

revoke all on function public.qualify_lte_referral(bigint) from public, anon, authenticated;
grant execute on function public.qualify_lte_referral(bigint) to service_role;
