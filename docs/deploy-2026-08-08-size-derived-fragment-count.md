# Deploy runbook — size-derived fragment count

**Branch:** `feature/size-derived-fragment-count` (commit `f51237b`, pushed 2026-08-08)
**Deploying from:** Sedona desktop
**What this deploys:** fragment count derived from file size instead of a fixed 7.
**Full context:** `docs/session-2026-08-08-size-derived-fragment-count.md`

> Merging to `main` **is** the production release — `app.xinsere.com` auto-deploys on push. There
> is no separate deploy step and no staging gate. Everything below assumes that.

---

## 0. Before you start — the one thing that would make this a no-op

Checked from the travel laptop on 2026-08-08: **`XINSERE_FRAGMENT_COUNT` is not set** in the Vercel
production environment, so the new default (size-derived) takes effect on deploy. If someone adds
that variable between now and the deploy, every file gets pinned to that number and this change
does nothing visible. Re-check with:

```bash
npx vercel env ls production | grep FRAGMENT     # expect: no output
```

## 1. Pre-flight on Sedona

```bash
cd <repo>/xinsere-v2
git fetch origin
git checkout feature/size-derived-fragment-count
git pull --ff-only
```

Run both suites. Sedona has the full dependency set, so unlike the travel laptop no stubbing is
needed:

```bash
cd lambdas/pipeline && python tests/test_matrix.py     # expect: 52 passed, 0 failed
cd ../../demo && python -m pytest tests/ -q            # expect: green, incl. 21 in test_fragment_sizing.py
```

If `test_matrix.py` group H fails, **stop** — the sizing curve is wrong and nothing downstream is
worth deploying. If only the demo suite fails, check it isn't a pre-existing failure unrelated to
this branch (`git stash` isn't enough — compare against `main`).

## 2. Merge and release

```bash
git checkout main
git pull --ff-only                    # if this won't fast-forward, STOP and reconcile
git merge --no-ff feature/size-derived-fragment-count
git push                              # <-- this is the production release
```

`--no-ff` keeps the change as one identifiable merge, which matters here because the rollback
option in §5 is "revert the merge."

## 3. Verify the deploy itself

This is the check that was missing on 2026-08-03, when production sat 404-ing on every route with
nothing flagging it. **The keep-warm workflow still cannot catch that** — it pings with
`curl ... || true`, so a total outage is swallowed silently. Do this by hand:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://app.xinsere.com/        # expect 200
curl -s https://app.xinsere.com/api/warm                                  # expect the line below
# {"ok":true,"warmed":{"pipeline":"ok","chain":"ok"}}
```

`warmed` proving both `pipeline` and `chain` is what tells you the S3/KMS/DynamoDB clients and the
web3 signer all constructed. A 200 on `/` alone is not sufficient.

If every path returns `{"detail":"Not Found"}`, that is the Vercel FastAPI auto-detection failure,
not this change — compare `vercel inspect <url>` build output between deployments (`λ fastapi` =
current builder, `λ index` = old). Do **not** re-add a catch-all rewrite to `vercel.json`.

## 4. Verify the change actually did something

**In the app** — upload three files of deliberately different sizes and open the details panel on
each. "Encrypted fragments" should differ:

| Upload | Expect |
|---|---|
| 500 KB | **3** |
| 5 MB | **5** |
| 10 MB | **7** |
| 200 MB (staged upload path) | **12** |
| 500 MB (the staged ceiling) | **30** |

(Exact figures, decimal MB as a file manager reports them — 200 MB is 12, not 13; the round
numbers in the sales table are MiB-based. If you want to check any other size before deploying:
`python -c "from xinsere_pipeline import fragmenter as f; print(f.plan_fragment_count(<bytes>))"`
from `lambdas/pipeline`.)

Then download each one and confirm it opens. That round-trip is the check that matters — the count
is cosmetic if reassembly is broken.

**Existing files must be untouched.** Open a file uploaded before this deploy: it should still
report **7** and still download cleanly. Its count comes from its own index record, not the current
policy. If an old file now reports something else, something is very wrong — roll back.

**On the API:**

```bash
curl -s -H "Authorization: Bearer xin_..." https://app.xinsere.com/v1/ping
# expect: "fragment_count":{"mode":"auto","pinned":null,"min":3,"max":64}

# auto:
curl -s -H "Authorization: Bearer xin_..." -F file=@small.txt https://app.xinsere.com/v1/files
# expect "fragments":3

# pinned for one file:
curl -s -H "Authorization: Bearer xin_..." -F file=@small.txt -F fragment_count=11 \
     https://app.xinsere.com/v1/files
# expect "fragments":11

# rejected:
curl -s -H "Authorization: Bearer xin_..." -F file=@small.txt -F fragment_count=99 \
     https://app.xinsere.com/v1/files
# expect HTTP 400, "fragment_count must be between 3 and 64" — NOT a 500
```

**TAMS** (`/tams`) — ingest a flow. The summary should read "3 fragments each (sized to the
segment, not a fixed 7)", and the segment table's Fragments column should show 3 per row.

## 5. Rollback

Two levers, in order of preference:

**a) Pin the count back to 7 — config only, no code change.**

```bash
npx vercel env add XINSERE_FRAGMENT_COUNT production      # value: 7
npx vercel --prod                                          # env changes need a redeploy to apply
```

Every new file goes back to 7. Files already written under the new policy keep their own counts and
still read back fine — the read path always follows the file. This is the right lever if the counts
look wrong but nothing is broken.

**b) Revert the merge.**

```bash
git revert -m 1 <merge-sha>
git push
```

Use this if something is actually broken rather than merely undesirable. Same caveat: files written
in the interim keep their recorded counts and remain readable, because the revert only changes how
*new* files are sized.

Nothing here requires a data migration in either direction.

## 6. What to expect, and what not to claim

- **The web app tops out at 32 fragments.** `MAX_STAGED_BYTES` is 500 MB, so 64 is unreachable
  through the browser — it needs the EC2/Fargate bulk-ingest path. Don't try to demo 64 via
  app.xinsere.com.
- **Fragment count ≠ number of storage locations.** Per-bucket exposure is set by the size of the
  bucket pool (`XINSERE_S3_BUCKETS`), not by N. Worth confirming how many buckets that variable
  actually lists — as of the 2026-07-26 audit the live config wired **7 of the 12** provisioned
  cac1 buckets, and going to all 12 is a zero-cost change that genuinely improves exposure
  (14.3% → 8.3% max per bucket). That is a separate deploy from this one.
- **Throughput numbers in the July benchmark were measured with a pinned count.** Re-run
  `scripts/fragment_benchmark` from inside AWS before quoting fresh figures against the new default.

## 7. After the deploy

- Send the email to Max, JC, Jeremy and Joshua —
  `Ai Companion Docs/projects/Xinsere/draft-email-fragment-scaling-2026-08-08.md`. It currently
  reads as though the change is already live, which becomes true at this point. Addresses still
  need filling in.
- JC's deck material is
  `Ai Companion Docs/projects/Xinsere/Fragment-Scaling-Sales-Summary-2026-08-08.md`.
- Delete the feature branch once merged: `git push origin --delete feature/size-derived-fragment-count`.
