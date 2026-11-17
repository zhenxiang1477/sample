-- =====================================================================
-- Order follow-up system: database (step 1)
-- Paste the whole file into Supabase > SQL Editor and click Run.
-- Safe to run more than once.
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- Helper: today's date in Malaysia
-- ---------------------------------------------------------------------
create or replace function public.today_my()
returns date
language sql
stable
set search_path = ''
as $$
  select (now() at time zone 'Asia/Kuala_Lumpur')::date;
$$;

-- ---------------------------------------------------------------------
-- profiles: one row per user
-- New users start NOT active; the owner must approve them.
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text,
  full_name   text,
  role        text not null default 'staff' check (role in ('owner','manager','staff')),
  active      boolean not null default false,
  created_at  timestamptz not null default now()
);

-- my_role(): the current user's role, only if active. Used in every policy.
create or replace function public.my_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select p.role from public.profiles p
  where p.id = auth.uid() and p.active = true;
$$;

-- ---------------------------------------------------------------------
-- settings: rule numbers (owner edits, everyone logged in reads)
-- ---------------------------------------------------------------------
create table if not exists public.settings (
  key         text primary key,
  value       text not null,
  note        text,
  updated_at  timestamptz not null default now(),
  updated_by  uuid default auth.uid()
);

insert into public.settings (key, value, note) values
  ('red_flag_days',       '30', 'Overdue more than this many days = red'),
  ('default_credit_days', '30', 'Credit days for a customer with none set'),
  ('staff_alert_days',    '3',  'Staff see status changes from the last N days')
on conflict (key) do nothing;

-- ---------------------------------------------------------------------
-- audit_log: who did what (written only by triggers)
-- ---------------------------------------------------------------------
create table if not exists public.audit_log (
  id          bigint generated always as identity primary key,
  at          timestamptz not null default now(),
  who         uuid default auth.uid(),
  who_email   text,
  action      text not null,
  table_name  text not null,
  record_id   text,
  details     jsonb
);

create or replace function public.write_audit(p_action text, p_table text, p_record text, p_details jsonb)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.audit_log (who, who_email, action, table_name, record_id, details)
  values (
    auth.uid(),
    (select p.email from public.profiles p where p.id = auth.uid()),
    p_action, p_table, p_record, p_details
  );
end;
$$;
revoke execute on function public.write_audit(text, text, text, jsonb) from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- customers (business table 1)
-- ---------------------------------------------------------------------
create table if not exists public.customers (
  id           uuid primary key default gen_random_uuid(),
  created_at   timestamptz not null default now(),
  created_by   uuid default auth.uid(),
  name         text not null,
  phone        text,
  credit_days  integer check (credit_days is null or credit_days >= 0),
  notes        text
);
create unique index if not exists customers_name_unique on public.customers (lower(name));

-- ---------------------------------------------------------------------
-- orders (business table 2)
-- ---------------------------------------------------------------------
create sequence if not exists public.order_no_seq;

create table if not exists public.orders (
  id                 uuid primary key default gen_random_uuid(),
  created_at         timestamptz not null default now(),
  created_by         uuid default auth.uid(),
  order_no           text not null unique default ('SO-' || lpad(nextval('public.order_no_seq')::text, 5, '0')),
  customer_id        uuid not null references public.customers(id) on delete restrict,
  item               text not null,
  qty                numeric(12,2) not null check (qty > 0),
  unit_price         numeric(12,2) not null check (unit_price >= 0),
  amount             numeric(12,2) generated always as (round(qty * unit_price, 2)) stored,
  promised_date      date not null,
  status             text not null default 'New'
                     check (status in ('New','Confirmed','Out for delivery','Delivered','Cancelled')),
  delivered_date     date,
  payment_status     text not null default 'Unpaid'
                     check (payment_status in ('Unpaid','Partial','Paid')),
  due_date           date,
  notes              text,
  status_changed_at  timestamptz,
  status_changed_by  uuid,
  updated_at         timestamptz not null default now()
);
create index if not exists orders_created_by_idx on public.orders (created_by);
create index if not exists orders_customer_idx   on public.orders (customer_id);

grant usage on sequence public.order_no_seq to authenticated;

-- ---------------------------------------------------------------------
-- ai_briefs: saved AI morning briefs (must be ticked "checked")
-- ---------------------------------------------------------------------
create table if not exists public.ai_briefs (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  created_by  uuid default auth.uid(),
  prompt      text not null,
  result      text not null,
  checked     boolean not null default false check (checked = true)
);

-- =====================================================================
-- Triggers
-- =====================================================================

-- New sign-up -> create profile (not active) + log it
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'full_name', ''))
  on conflict (id) do nothing;

  insert into public.audit_log (who, who_email, action, table_name, record_id, details)
  values (new.id, new.email, 'sign up', 'profiles', new.id::text, null);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Only the owner (or the SQL Editor) can change role / active
create or replace function public.guard_profile_changes()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (new.role is distinct from old.role or new.active is distinct from old.active) then
    if auth.uid() is not null and coalesce(public.my_role(), '') <> 'owner' then
      raise exception 'Only the owner can change a user''s role or approval.';
    end if;
    perform public.write_audit(
      'role change', 'profiles', new.id::text,
      jsonb_build_object('email', new.email,
                         'old_role', old.role, 'new_role', new.role,
                         'old_active', old.active, 'new_active', new.active));
  end if;
  new.id := old.id;
  new.email := old.email;
  return new;
end;
$$;

drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard
  before update on public.profiles
  for each row execute function public.guard_profile_changes();

-- Orders: staff limits, auto delivered date / due date, status stamp
create or replace function public.orders_before_write()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_role text := public.my_role();
  v_credit integer;
begin
  if tg_op = 'INSERT' then
    if v_role = 'staff' then
      new.status := 'New';
      new.payment_status := 'Unpaid';
      new.delivered_date := null;
      new.due_date := null;
    end if;
    new.created_by := coalesce(auth.uid(), new.created_by);
  else
    if auth.uid() is not null and v_role = 'staff' then
      if new.status is distinct from old.status
         or new.payment_status is distinct from old.payment_status
         or new.due_date is distinct from old.due_date
         or new.delivered_date is distinct from old.delivered_date then
        raise exception 'Only a manager can change the delivery or payment status.';
      end if;
    end if;
    new.created_by := old.created_by;
    new.created_at := old.created_at;
    new.order_no   := old.order_no;
    new.updated_at := now();

    if new.status is distinct from old.status then
      new.status_changed_at := now();
      new.status_changed_by := auth.uid();
    end if;
  end if;

  -- When delivered: record the date and work out the payment due date
  if new.status = 'Delivered' then
    new.delivered_date := coalesce(new.delivered_date, public.today_my());
    if new.due_date is null then
      select c.credit_days into v_credit from public.customers c where c.id = new.customer_id;
      if v_credit is null then
        select s.value::integer into v_credit from public.settings s where s.key = 'default_credit_days';
      end if;
      new.due_date := new.delivered_date + coalesce(v_credit, 30);
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists orders_before_write on public.orders;
create trigger orders_before_write
  before insert or update on public.orders
  for each row execute function public.orders_before_write();

-- Orders: log create and status changes
create or replace function public.orders_after_write()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    perform public.write_audit('create', 'orders', new.order_no,
      jsonb_build_object('item', new.item, 'amount', new.amount));
  else
    if new.status is distinct from old.status then
      perform public.write_audit('status change', 'orders', new.order_no,
        jsonb_build_object('from', old.status, 'to', new.status));
    end if;
    if new.payment_status is distinct from old.payment_status then
      perform public.write_audit('payment change', 'orders', new.order_no,
        jsonb_build_object('from', old.payment_status, 'to', new.payment_status));
    end if;
  end if;
  return null;
end;
$$;

drop trigger if exists orders_after_write on public.orders;
create trigger orders_after_write
  after insert or update on public.orders
  for each row execute function public.orders_after_write();

-- Customers: log create
create or replace function public.customers_after_insert()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform public.write_audit('create', 'customers', new.id::text,
    jsonb_build_object('name', new.name));
  return null;
end;
$$;

drop trigger if exists customers_after_insert on public.customers;
create trigger customers_after_insert
  after insert on public.customers
  for each row execute function public.customers_after_insert();

-- =====================================================================
-- Row Level Security
-- =====================================================================
alter table public.profiles  enable row level security;
alter table public.settings  enable row level security;
alter table public.audit_log enable row level security;
alter table public.customers enable row level security;
alter table public.orders    enable row level security;
alter table public.ai_briefs enable row level security;

-- profiles
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() in ('manager','owner'));

drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.my_role() = 'owner')
  with check (id = auth.uid() or public.my_role() = 'owner');

-- settings
drop policy if exists settings_select on public.settings;
create policy settings_select on public.settings for select to authenticated
  using (public.my_role() is not null);

drop policy if exists settings_owner_write on public.settings;
create policy settings_owner_write on public.settings for all to authenticated
  using (public.my_role() = 'owner')
  with check (public.my_role() = 'owner');

-- audit_log (read only, manager + owner)
drop policy if exists audit_select on public.audit_log;
create policy audit_select on public.audit_log for select to authenticated
  using (public.my_role() in ('manager','owner'));

-- customers
drop policy if exists customers_select on public.customers;
create policy customers_select on public.customers for select to authenticated
  using (public.my_role() is not null);

drop policy if exists customers_insert on public.customers;
create policy customers_insert on public.customers for insert to authenticated
  with check (public.my_role() is not null and created_by = auth.uid());

drop policy if exists customers_update on public.customers;
create policy customers_update on public.customers for update to authenticated
  using (public.my_role() in ('manager','owner'))
  with check (public.my_role() in ('manager','owner'));

drop policy if exists customers_delete on public.customers;
create policy customers_delete on public.customers for delete to authenticated
  using (public.my_role() = 'owner');

-- orders
drop policy if exists orders_select on public.orders;
create policy orders_select on public.orders for select to authenticated
  using (public.my_role() in ('manager','owner')
         or (public.my_role() = 'staff' and created_by = auth.uid()));

drop policy if exists orders_insert on public.orders;
create policy orders_insert on public.orders for insert to authenticated
  with check (public.my_role() is not null and created_by = auth.uid());

drop policy if exists orders_update on public.orders;
create policy orders_update on public.orders for update to authenticated
  using (public.my_role() in ('manager','owner')
         or (public.my_role() = 'staff' and created_by = auth.uid() and status = 'New'))
  with check (public.my_role() in ('manager','owner')
         or (public.my_role() = 'staff' and created_by = auth.uid() and status = 'New'));

drop policy if exists orders_delete on public.orders;
create policy orders_delete on public.orders for delete to authenticated
  using (public.my_role() = 'owner');

-- ai_briefs (manager + owner)
drop policy if exists ai_briefs_select on public.ai_briefs;
create policy ai_briefs_select on public.ai_briefs for select to authenticated
  using (public.my_role() in ('manager','owner'));

drop policy if exists ai_briefs_insert on public.ai_briefs;
create policy ai_briefs_insert on public.ai_briefs for insert to authenticated
  with check (public.my_role() in ('manager','owner') and created_by = auth.uid() and checked = true);

drop policy if exists ai_briefs_delete on public.ai_briefs;
create policy ai_briefs_delete on public.ai_briefs for delete to authenticated
  using (public.my_role() = 'owner');
