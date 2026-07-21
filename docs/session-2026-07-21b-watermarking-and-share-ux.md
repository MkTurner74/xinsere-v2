# Session 2026-07-21 (part 2) — team-testing fixes, forensic watermarking, share UX

Continuation of the grant-window session. All commits on `main`, deployed to
app.xinsere.com. Range: `2f59db2` → `eb5e957`.

## Shipped this session

**Grant windows / cutover** (earlier part — see session-2026-07-21-grant-windows-*):
windowed contract `0xF4a2f8d6…`, pending-invite windows (0021), share dialog rework.

**Team-testing fixes**
- Inherited-share display: folder shares now show on the folder's contents
  ("via <folder>", no Revoke on inherited).
- Post-cutover re-share 409 fixed (permission_batches/batch_grants on_conflict).
- Dead Amoy RPC → publicnode; read-back retry for the load-balanced RPC's
  read-after-write lag.
- Rename-from-preview, group revoke (bulk + "Revoke everyone"), view-aware
  refresh (stay in Shared-by-me after actions), co-owner Share icons,
  folder-header actions, admin status-pill contrast, owner rights in the
  viewer provenance pane.

**Forensic watermarking — the honest state**
- Confirmed DONE + ACTIVE (not roadmap): PDF (invisible render-mode-3 text +
  metadata), text (zero-width), **Office docx/xlsx/pptx (custom document
  property)** — all embed on serve and read back in Trace-a-file; Office
  survives an edit/re-save. Round-trip re-verified 2026-07-21.
- Image pixel-domain mark (Phase 2, `demo/wm_pixel.py`): built, then found
  **(a) visibly imperfect** on flat backgrounds and **(b) NOT screenshot-robust**
  — the global-DCT detector desyncs at ~0.5% edge crop (proven), and every real
  screen grab is cropped/misaligned. The "screenshot" tests only rescaled, never
  cropped — that gap hid the flaw. A DFT-magnitude prototype (translation-
  invariant in theory) ALSO failed crop tests, so no third blind attempt.
- **Resolution (eb5e957 + migration 0022):** the VISIBLE pixel layer is now
  **org opt-in, default OFF** (`organizations.watermark_pixel_images`), separate
  admin toggle under Security with a pre-res warning. Invisible marks (which
  survive file copying, not screenshots) always apply. Production no longer
  emits the visible artifact by default.

## What survives what (state the team should hear)
- File copy / forward / re-save → invisible marks on PDF, Office, text, and
  image metadata all trace. This is the common leak and it works.
- Screen grab / re-photograph → nothing reliably traces yet. The audit log
  (who previewed, when) is the backstop.

### Office (docx/xlsx/pptx) trace — verified scope (2026-07-21)
The mark is an OOXML **custom document property** (a first-class Office feature,
File > Info > Properties > Advanced), chosen because editors preserve it where a
foreign zip entry would be dropped.

IN scope — trace survives (verified via a real python-docx edit+save that
rebuilds the package the way Word does; the property + XIN-FWM mark round-trip):
- Forwarding / copying the file unchanged.
- **Editing and re-saving in the NATIVE format** in Word / Excel / PowerPoint.

OUT of scope / not guaranteed:
- **Save-As to a different format** (.doc, .odt, .pdf, Pages) — property can be
  dropped/transformed. NOT verified against real MS Word in this env
  (reasonable-confidence claim, not proven).
- **Editing in a different app** (LibreOffice, Google Docs, Pages) — round-trip
  varies by app.
- **Explicit deletion** of the custom property by the user.
- **Screenshot / print-to-image** of the document — the mark is in the file
  structure, not the rendered pixels (same screenshot limit as everything else).

Headline for the team: "survives normal editing and re-saving; NOT format
conversion or screen capture."

### Known follow-up (fold into the policy-matrix session)
- **Duplicate-property on re-serve:** each serve appends another `XinsereFWM`
  custom property, so a file downloaded twice carries two marks. `extract()`
  handles it (returns both IDs), but de-dupe on embed (update-in-place if a
  Xinsere property already exists) for cleanliness. Also aligns the pid used by
  the new-file path (pid=2) vs the append-to-existing path (pid=99).

## NEXT SESSION — definitive scope (Mark, 2026-07-21)
1. **Marking-policy matrix** (admin): previews vs downloads × per-format defaults
   (production formats — ProRes/DNxHD/EXR/uncompressed, and pre-res stills —
   default unmarked; distribution formats marked) + per-share "serve unmarked"
   override. Extends the 0017/0022 org flags into a matrix. Small, high-value:
   gives studios the exact control they ask for and the sales story
   ("masters bit-perfect, distribution traceable").
2. **Deep-research spike on robust watermarking** — screenshot/crop/re-encode
   survival for images AND video: Fourier-Mellin / log-polar template sync,
   spread-spectrum with synchronization, A/B segment switching for video, and
   the build-vs-license question (Digimarc-class engines). Video also needs
   Xinsere's own H.264 licensing look (ETI's MPEG-LA arrangement doesn't carry).
   Deliverable: a scoped recommendation, not a blind build.

## Migrations
- 0021 pending-share windows (applied).
- 0022 org visible-watermark flag (applied 2026-07-21).
