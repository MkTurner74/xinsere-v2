# Xinsere — Supabase project (auth + app metadata)

Dedicated Supabase project for Xinsere (separate from the ETI project, for entity
hygiene). Holds **auth + app metadata**; the pipeline file/fragment index stays in
DynamoDB. See `projects/Xinsere/ADR-2026-07-06-vercel-aws-production-build.md` (ADR-006).

## What lives here
- **Supabase Auth** (`auth.users`) — signup, login, email verification, password
  reset, OAuth. `auth.uid()` **is** the on-chain `grantee_id`.
- **`profiles`** — display name / username / email mirror; auto-created on signup.
- **`nodes`** — folder tree + file nodes; `file_id` references the DynamoDB record.
- **`shares`** — owner→grantee grants, with the on-chain tx hash.
- **`has_node_access()`** — recursive ancestry check powering RLS.

All tables have **RLS enabled**. The blockchain `verify()` remains the authoritative
gate on file bytes; RLS governs metadata listing only.

## Auth integration model
- Frontend uses `supabase-js` → user gets a Supabase JWT.
- The FastAPI backend verifies the JWT and issues **RLS-scoped** queries as that user
  (PostgREST or pg with the JWT), so RLS enforces isolation — no service_role on the
  request path except for admin/seed scripts.
- AWS pipeline ops (S3/KMS/DynamoDB) use the backend's IAM creds, independent of Supabase.

## Deploy
```bash
# 1. Create the project (needs a Supabase Personal Access Token):
supabase projects create xinsere --org-id <ORG> --db-password <PW> --region us-east-1

# 2. Link + push the schema:
supabase link --project-ref <REF>
supabase db push          # applies migrations/0001_init.sql

# 3. Enable email auth (confirmations on) in Auth settings; add OAuth later.
```

## What I need from Mark to create + deploy this
Either **(a)** a **Supabase Personal Access Token** (supabase.com/dashboard/account/tokens)
— then I create the project + push the schema myself; or **(b)** you create an empty
project named `xinsere` in the dashboard and share the **project ref**, **DB password**,
and **service_role key** — then I link and push.

Nothing else here is blocked: the schema/migration and RLS are ready to apply as soon
as the project exists.
