# C5-01 — Upstream Monitor Foundation

## Target repository

Apply this patch at the repository root of `VidMax-Software/vidmax-engine-releases`. The uploaded VidMax source bundle did not contain that separate GitHub repository, so this patch is staged for that repository and does not modify the Desktop, Worker, Admin or Native Host source trees.

## Scope

This milestone adds a daily, read-only upstream release monitor and the public `upstream-status.json` v1 contract. It does **not** download engine binaries, package or sign VidMax component releases, write to Worker/D1, change release feeds, enable channels, or deploy any service.

## Upstream sources and security semantics

### yt-dlp

- Reads the official `yt-dlp/yt-dlp` latest published release API response.
- Requires exactly one each of `yt-dlp.exe`, `SHA2-256SUMS`, and `SHA2-256SUMS.sig`.
- Downloads only the checksum file and detached signature, not `yt-dlp.exe`.
- Verifies the detached signature using the public key copied from the audited Desktop `UpstreamEngineReleaseVerifier` and pins the primary key fingerprint to `AC0CBBE6848D6A873464AF4E57CF65933B5A7581`.
- Extracts the executable hash from the signed checksum file and compares GitHub's SHA-256 asset digest when GitHub supplies one.
- Fails closed on missing/duplicate assets, invalid signature, unexpected signer, malformed checksum, invalid release metadata, or inconsistent GitHub digest.

### FFmpeg

- Reads `release-version` and `ffmpeg-release-full.7z.sha256` from the existing Gyan.dev metadata endpoints.
- Queries the matching `GyanD/codexffmpeg` GitHub release and accepts only the exact `{version}` `ffmpeg-{version}-full_build.7z` asset from author `GyanD`.
- Requires the GitHub asset SHA-256 digest to match Gyan.dev's sidecar.
- Preserves the existing GitHub mirror download URL. It does not download the archive.
- Reports `publisher_signature_verified: false` deliberately. GitHub's asset digest plus the independent Gyan.dev sidecar is a cross-check, not a detached Gyan publisher signature and not proof that either publisher/build system is uncompromised.

## Public JSON contract

- Schema: `schemas/upstream-status.schema.json` (JSON Schema Draft 2020-12).
- Public snapshot: `upstream-status.json` (created by the first successful monitor run). Expected public raw URL: `https://raw.githubusercontent.com/VidMax-Software/vidmax-engine-releases/main/upstream-status.json`.
- Each component includes version, release date, published timestamp, release page, binary source URL, asset name/size/SHA-256, metadata sources, last-check timestamp, and explicit security evidence.
- Both component checks must succeed before the snapshot is atomically replaced. A failed upstream check leaves the previous last-known-good snapshot untouched; its `last_checked_at` therefore remains an honest indicator of age.
- Unknown or missing upstream evidence is not converted into a successful status.

## Workflow

- Runs daily at 03:17 UTC and supports manual `workflow_dispatch`. Scheduled events execute from the repository default branch; the job is intentionally restricted to `main`. Keep `main` as the repository default branch.
- Uses `ubuntu-24.04`, the current Node.js 22 release line and GnuPG.
- Uses only the repository-scoped `GITHUB_TOKEN` available to the checkout/publish action; the monitor script does not read or forward that token to upstream requests.
- `GITHUB_TOKEN` requires `contents: write` for the snapshot commit. No PAT, GitHub App private key, Cloudflare secret, D1 access or Worker secret is required.
- The workflow pins `actions/checkout` v7.0.1 and `actions/setup-node` v7.1.0 to reviewed full commit SHAs (Node 24-compatible action runtimes).
- The job writes only `upstream-status.json` to the repository's checked-out branch after both checks and schema validation pass.

The repository/organization Actions policy must allow the workflow token to write repository contents. If an organization policy blocks write tokens, the commit step will fail rather than falling back to a PAT.

## Local validation

Requirements: Node.js 22+ and GnuPG. Python 3 plus the `jsonschema` package is optional when you also want an independent Draft 2020-12 schema check.

From the target repo root:

```bash
node --test tests/upstream-monitor.test.mjs
node scripts/validate-upstream-status.mjs upstream-status.json
```

For an independent standards-based JSON Schema check (optional; requires Python `jsonschema`):

```bash
python -m jsonschema -i upstream-status.json schemas/upstream-status.schema.json
```

To run a live read-only preflight (requires network access):

```bash
node scripts/monitor-upstream.mjs --output /tmp/upstream-status.json
node scripts/validate-upstream-status.mjs /tmp/upstream-status.json
```

The live preflight does not commit or push. `--output` may point to a path outside the repository. It only retrieves release metadata, signed checksum evidence and the Gyan checksum sidecar; it does not fetch either binary.

## Activation checklist (GitHub web interface; no clone required)

1. Open `https://github.com/VidMax-Software/vidmax-engine-releases` while signed into an account with repository write access.
2. Select **Add file → Upload files**.
3. From the extracted patch's `Repository_Root` folder, upload the five top-level folders (`.github`, `docs`, `schemas`, `scripts`, and `tests`) so GitHub preserves the repository-relative paths. Do not upload the outer `Repository_Root` folder itself.
4. Confirm the upload preview lists exactly the seven paths in the patch manifest. If GitHub shows any unexpected wrapper directory, replacement, or existing path conflict, cancel and investigate rather than committing.
5. Choose **Create a new branch and start a pull request**, using `c5-01-upstream-monitor`. Review the proposed file list and merge only after confirming this patch adds the seven expected files and changes no existing feed document, release asset, or channel state.
6. After the PR is merged into the default `main` branch, open Actions → `VidMax upstream release monitor` and run it once manually.
7. Verify the workflow commits `upstream-status.json` and that the raw public URL returns HTTP 200. Confirm its timestamp, yt-dlp signer fingerprint, and FFmpeg cross-check semantics.

This patch deliberately does not use the existing GitHub App. The repository web UI commit is performed by the signed-in repository user, so no new App permission or private-key handling is needed. The workflow itself uses the repository-scoped `GITHUB_TOKEN` with `contents: write`; the repository/organization Actions policy must permit that token permission.

Do not enable either component channel as part of C5-01. Do not treat a successful upstream monitor run as permission to publish/install a new VidMax release.

## Later milestone boundaries

- C5-02 will integrate the public snapshot and the existing Admin manual-check quota with Worker/Admin status UI. The current Worker counts **reserved attempts**, not completed successful checks; that quota semantics discrepancy must be reviewed separately in C5-02. This patch does not change the Worker.
- C5-03 will add Ultra's notification-only Engine Updates view. This patch does not change Desktop.
- C5-04 will add cross-component regression and operational tests.
