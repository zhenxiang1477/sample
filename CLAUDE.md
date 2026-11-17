# House rules for Claude

## How to talk to me
- I am a business user, not a programmer. Use simple, non-technical words.
- After each change, tell me in 2-3 sentences what you did and what I should test.
- If my request is unclear, ask me up to 3 questions first.
- Do one change per request. Don't change things I didn't ask for.
- After each change: commit with a clear message and push to main. Then tell me to wait 1 minute and refresh my Vercel link.
- Whenever I must do something outside this folder (Supabase, Vercel, GitHub), give me numbered click-by-click steps.

## Technical rules (I don't need to understand these; you follow them)
- Stack: plain HTML + CSS + JavaScript, one file per page, shared code in app.js. Supabase JS v2 from https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2 and Chart.js from a CDN. No npm, no build step, no framework. Hosted on Vercel as a static site.
- config.js holds SUPABASE_URL and SUPABASE_KEY (the publishable/anon key only). Never use or ask for the service_role or secret key.
- Database changes: SQL files in supabase/ (schema.sql first, then 02_..., 03_...), safe to run twice. Tell me to paste the file into the Supabase SQL Editor and click Run.
- Roles: public.profiles (id references auth.users, email, full_name, role owner/manager/staff with default staff, active default true). Create the profile automatically on sign-up with a SECURITY DEFINER trigger (search_path ''). Use a SECURITY DEFINER function public.my_role() (returns the role only if active) in every policy; never query profiles inside a policy. Only the owner can change role or active: enforce with a trigger that also allows it when auth.uid() is null (the SQL Editor).
- Security: Row Level Security on every table. Staff see, add and edit only their own rows (created_by = auth.uid()); manager sees and edits all rows; owner can do everything including delete. Every page checks the role at the top and sends people who aren't allowed back to index.html, but the real protection is RLS.
- Every business table has id, created_at and created_by default auth.uid(). Also: settings (key, value; everyone logged in reads, only the owner edits) and audit_log (who, when, action, table, record, details; manager and owner read). Log every create, status change and role change.
- Rule numbers (thresholds) live in the settings table, never hard-coded.
- AI: never put an AI API key in the browser. The AI brief = build a prompt from the visible rows; the user runs it in Claude, checks it, ticks "I have checked this", then saves it to an ai_briefs table.
- Notifications: an Alerts box per role inside the app. WhatsApp = a wa.me link with the message pre-typed, which a human sends. Never send anything to customers automatically.
- SPEC.md format: A Purpose · B Who can see/add/edit/delete what · C Data tables and columns (max 2 business tables, plus profiles, settings, audit_log) · D Screens per role · E Rules with exact numbers · F KPIs (max 5), each with an action · G AI feature + never-do list · H Not today · I Notifications (who, when, how). Write it in simple words.
- Sample data only. Money in RM with 2 decimals, dates like 17 Nov 2026, friendly error messages, works on a phone.
