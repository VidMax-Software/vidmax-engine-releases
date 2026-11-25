#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, rename, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const YTDLP_SIGNING_KEY_FINGERPRINT = 'AC0CBBE6848D6A873464AF4E57CF65933B5A7581';
export const SOURCE_URLS = Object.freeze({
  ytdlpReleaseApi: 'https://api.github.com/repos/yt-dlp/yt-dlp/releases/latest',
  ytdlpReleaseBase: 'https://github.com/yt-dlp/yt-dlp/releases/download/',
  gyanReleaseVersion: 'https://www.gyan.dev/ffmpeg/builds/release-version',
  gyanFullChecksum: 'https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-full.7z.sha256',
  ffmpegGitHubReleaseApiPrefix: 'https://api.github.com/repos/GyanD/codexffmpeg/releases/tags/',
});

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PUBLIC_KEY = resolve(SCRIPT_DIR, 'keys', 'yt-dlp-signing-public.asc');
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_TEXT_BYTES = 1024 * 1024;
const MAX_SIGNATURE_BYTES = 64 * 1024;
const MAX_YTDLP_EXE_BYTES = 100 * 1024 * 1024;
const MAX_FFMPEG_ARCHIVE_BYTES = 600 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;
const ALLOWED_HOSTS = new Set(['api.github.com', 'github.com', 'www.gyan.dev', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com']);
const HEX_256 = /^[a-f0-9]{64}$/;
const SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$/;

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${label} is missing or invalid.`);
  return value.trim();
}

function requireHttpsUrl(value, label, expectedUrl = undefined) {
  const raw = requireString(value, label);
  let url;
  try { url = new URL(raw); } catch { throw new Error(`${label} is not a valid URL.`); }
  if (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname.toLowerCase()) || url.username || url.password)
    throw new Error(`${label} is outside the HTTPS upstream allowlist.`);
  if (expectedUrl && raw !== expectedUrl) throw new Error(`${label} does not match the expected upstream path.`);
  return raw;
}

function parsePublishedAt(value, label) {
  const raw = requireString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(raw))
    throw new Error(`${label} is not a valid RFC 3339 timestamp.`);
  assertIsoDate(raw.slice(0, 10), `${label} date`);
  const date = new Date(raw);
  if (!Number.isFinite(date.getTime())) throw new Error(`${label} is not a valid timestamp.`);
  return date.toISOString();
}

async function readResponseLimited(response, maxBytes, label) {
  const contentLength = response.headers?.get?.('content-length');
  if (contentLength && Number(contentLength) > maxBytes) throw new Error(`${label} exceeds its permitted size.`);
  if (!response.body?.getReader) {
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > maxBytes) throw new Error(`${label} exceeds its permitted size.`);
    return buffer;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxBytes) {
        await reader.cancel();
        throw new Error(`${label} exceeds its permitted size.`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, length);
}

async function fetchBytes(urlValue, {
  fetchImpl = fetch,
  maxBytes = MAX_TEXT_BYTES,
  label = 'Upstream response',
  accept = '*/*',
  attempts = 3,
} = {}) {
  let currentUrl = requireHttpsUrl(urlValue, `${label} URL`);
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      let response;
      // Follow only the narrowly expected GitHub release-asset CDN redirects.
      // Browser download URLs commonly redirect from github.com to
      // release-assets.githubusercontent.com; arbitrary redirects are rejected.
      for (let redirectCount = 0; redirectCount <= 3; redirectCount++) {
        response = await fetchImpl(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          headers: {
            'user-agent': 'VidMax-Upstream-Monitor/1.0',
            accept,
          },
        });
        if (response.status >= 300 && response.status < 400) {
          if (redirectCount === 3) throw new Error(`${label} exceeded the permitted redirect count.`);
          const location = response.headers?.get?.('location');
          if (!location) throw new Error(`${label} returned a redirect without a Location header.`);
          const next = new URL(location, currentUrl);
          requireHttpsUrl(next.toString(), `${label} redirect URL`);
          const originHost = new URL(urlValue).hostname.toLowerCase();
          const redirectHost = next.hostname.toLowerCase();
          const permitted = originHost === 'github.com'
            ? ['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com']
            : [originHost];
          if (!permitted.includes(redirectHost)) throw new Error(`${label} redirected to an unapproved host: ${redirectHost}.`);
          await response.body?.cancel?.();
          currentUrl = next.toString();
          continue;
        }
        break;
      }
      if (response.status === 429 || response.status >= 500) {
        if (attempt < attempts) {
          const retryAfter = Number(response.headers?.get?.('retry-after'));
          const waitMs = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 5000) : attempt * 500;
          await response.body?.cancel?.();
          await new Promise(resolveWait => setTimeout(resolveWait, waitMs));
          continue;
        }
      }
      if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}.`);
      if (response.url) requireHttpsUrl(response.url, `${label} final URL`, currentUrl);
      return await readResponseLimited(response, maxBytes, label);
    } catch (error) {
      lastError = error;
      if (attempt === attempts || (error?.name === 'AbortError' || error?.name === 'TimeoutError')) break;
      if (/HTTP 4\d\d|unapproved host|outside the HTTPS upstream allowlist|redirect count|without a Location/i.test(String(error?.message))) break;
      currentUrl = requireHttpsUrl(urlValue, `${label} retry URL`);
      await new Promise(resolveWait => setTimeout(resolveWait, attempt * 250));
    }
  }
  throw new Error(`${label} could not be retrieved safely: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}

async function fetchJson(url, options = {}) {
  const bytes = await fetchBytes(url, { ...options, maxBytes: options.maxBytes ?? MAX_JSON_BYTES, accept: 'application/vnd.github+json' });
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { throw new Error(`${options.label ?? 'Upstream JSON'} is not valid JSON.`); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${options.label ?? 'Upstream JSON'} must be a JSON object.`);
  return value;
}

export function parseYtDlpChecksumFile(text, assetName = 'yt-dlp.exe') {
  if (typeof text !== 'string' || text.length === 0 || Buffer.byteLength(text, 'utf8') > MAX_TEXT_BYTES)
    throw new Error('The yt-dlp SHA2-256SUMS file is empty or too large.');
  const matches = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([a-fA-F0-9]{64})\s+[* ]?(.+?)\s*$/);
    if (!match) continue;
    const filename = match[2].replaceAll('\\', '/').split('/').at(-1);
    if (filename === assetName) matches.push(match[1].toLowerCase());
  }
  if (matches.length !== 1) throw new Error(`The signed yt-dlp checksum file must contain exactly one ${assetName} entry.`);
  return matches[0];
}

export function parseGyanChecksumSidecar(text) {
  if (typeof text !== 'string' || text.length === 0 || Buffer.byteLength(text, 'utf8') > 64 * 1024)
    throw new Error('The Gyan FFmpeg checksum sidecar is empty or too large.');
  const matches = [...text.matchAll(/(?:^|\s)([a-fA-F0-9]{64})(?=\s|$)/gm)];
  if (matches.length !== 1) throw new Error('The Gyan FFmpeg sidecar must contain exactly one SHA-256 checksum.');
  return matches[0][1].toLowerCase();
}

function oneAsset(assets, expectedName, label) {
  if (!Array.isArray(assets)) throw new Error(`${label} release does not contain an asset list.`);
  const found = assets.filter(asset => asset && asset.name === expectedName);
  if (found.length !== 1) throw new Error(`${label} release must contain exactly one ${expectedName} asset.`);
  const asset = found[0];
  if (asset.state !== 'uploaded') throw new Error(`${label} ${expectedName} asset is not fully uploaded.`);
  if (!Number.isSafeInteger(asset.size) || asset.size <= 0) throw new Error(`${label} ${expectedName} asset has an invalid size.`);
  return asset;
}

function parseGitHubDigest(digest, label, { required = false } = {}) {
  if ((digest === null || digest === undefined || digest === '') && !required) return null;
  if (typeof digest !== 'string' || !digest.toLowerCase().startsWith('sha256:')) throw new Error(`${label} did not provide a valid SHA-256 GitHub asset digest.`);
  const hash = digest.slice(7).toLowerCase();
  if (!HEX_256.test(hash)) throw new Error(`${label} returned a malformed SHA-256 GitHub asset digest.`);
  return hash;
}

function validateReleaseEnvelope(release, tag, label) {
  if (release.tag_name !== tag) throw new Error(`${label} release tag does not match the selected version.`);
  if (release.draft !== false || release.prerelease !== false) throw new Error(`${label} release must be published and not a prerelease.`);
  const publishedAt = parsePublishedAt(release.published_at, `${label} published_at`);
  const releaseUrl = requireHttpsUrl(release.html_url, `${label} release URL`);
  return { publishedAt, releaseUrl };
}

export async function verifyYtDlpDetachedSignature({
  checksumBytes,
  signatureBytes,
  publicKeyPath = DEFAULT_PUBLIC_KEY,
  expectedFingerprint = YTDLP_SIGNING_KEY_FINGERPRINT,
  gpgExecutable = 'gpg',
}) {
  if (!Buffer.isBuffer(checksumBytes) || checksumBytes.length === 0 || checksumBytes.length > MAX_TEXT_BYTES)
    throw new Error('The yt-dlp checksum bytes are empty or too large.');
  if (!Buffer.isBuffer(signatureBytes) || signatureBytes.length === 0 || signatureBytes.length > MAX_SIGNATURE_BYTES)
    throw new Error('The yt-dlp detached signature is empty or too large.');
  if (expectedFingerprint !== YTDLP_SIGNING_KEY_FINGERPRINT && !/^[A-Fa-f0-9]{40}$/.test(expectedFingerprint))
    throw new Error('The expected OpenPGP primary fingerprint is malformed or is not the pinned upstream key.');

  const home = await mkdtemp(resolve(tmpdir(), 'vidmax-upstream-gpg-'));
  const runGpg = (args, label) => {
    const result = spawnSync(gpgExecutable, ['--batch', '--yes', '--no-tty', '--homedir', home, ...args], {
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 2 * 1024 * 1024,
      timeout: 20_000,
    });
    if (result.error) throw new Error(`${label}: ${result.error.message}`);
    if (result.status !== 0) throw new Error(`${label}: ${String(result.stderr || result.stdout).slice(0, 1200)}`);
    return result;
  };

  try {
    const publicKey = await readFile(publicKeyPath);
    if (publicKey.length === 0 || publicKey.length > 64 * 1024) throw new Error('Pinned yt-dlp public key is empty or too large.');
    runGpg(['--import', publicKeyPath], 'Could not import the pinned yt-dlp public key');
    const listing = runGpg(['--with-colons', '--fingerprint', '--list-keys'], 'Could not inspect the imported yt-dlp public key');
    const fingerprints = listing.stdout.split(/\r?\n/).filter(line => line.startsWith('fpr:')).map(line => line.split(':')[9]).filter(Boolean);
    if (fingerprints.length < 1 || fingerprints[0].toUpperCase() !== expectedFingerprint.toUpperCase())
      throw new Error('The imported yt-dlp public key does not match the pinned fingerprint.');

    const checksumPath = resolve(home, 'SHA2-256SUMS');
    const signaturePath = resolve(home, 'SHA2-256SUMS.sig');
    await writeFile(checksumPath, checksumBytes, { mode: 0o600 });
    await writeFile(signaturePath, signatureBytes, { mode: 0o600 });
    const verify = runGpg(['--status-fd=1', '--verify', signaturePath, checksumPath], 'GnuPG rejected the yt-dlp detached checksum signature');
    const validSignatures = verify.stdout.split(/\r?\n/).filter(line => line.startsWith('[GNUPG:] VALIDSIG '));
    if (validSignatures.length !== 1) throw new Error('GnuPG did not report exactly one valid detached signature.');
    const signatureFields = validSignatures[0].trim().split(/\s+/);
    const signatureFingerprint = signatureFields[2]?.toUpperCase();
    const hashAlgorithm = Number(signatureFields[9]);
    const signatureClass = signatureFields[10]?.toLowerCase();
    // Match the audited Desktop verifier: detached binary-document signatures
    // only, with SHA-256 or SHA-512. Do not silently accept weaker hashes.
    if (![8, 10].includes(hashAlgorithm)) throw new Error('The yt-dlp OpenPGP signature must use SHA-256 or SHA-512.');
    if (signatureClass !== '00') throw new Error('The yt-dlp OpenPGP signature must be a detached binary-document signature.');
    if (signatureFingerprint !== expectedFingerprint.toUpperCase())
      throw new Error('The yt-dlp signature signer does not match the pinned fingerprint.');
    return { fingerprint: expectedFingerprint.toUpperCase(), signerFingerprint: signatureFingerprint };
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

async function checkYtDlp({ fetchImpl, now, verifySignature, publicKeyPath }) {
  const release = await fetchJson(SOURCE_URLS.ytdlpReleaseApi, { fetchImpl, label: 'yt-dlp latest release API' });
  const tag = requireString(release.tag_name, 'yt-dlp release tag');
  if (!SAFE_VERSION.test(tag)) throw new Error('yt-dlp release tag contains unsupported characters.');
  const envelope = validateReleaseEnvelope(release, tag, 'yt-dlp');
  const expectedReleaseUrl = `https://github.com/yt-dlp/yt-dlp/releases/tag/${encodeURIComponent(tag)}`;
  if (envelope.releaseUrl !== expectedReleaseUrl) throw new Error('yt-dlp release page URL does not match the official repository and tag.');

  const exe = oneAsset(release.assets, 'yt-dlp.exe', 'yt-dlp');
  const sums = oneAsset(release.assets, 'SHA2-256SUMS', 'yt-dlp');
  const sig = oneAsset(release.assets, 'SHA2-256SUMS.sig', 'yt-dlp');
  if (exe.size > MAX_YTDLP_EXE_BYTES || sums.size > MAX_TEXT_BYTES || sig.size > MAX_SIGNATURE_BYTES)
    throw new Error('One or more yt-dlp release evidence assets exceed their permitted size.');

  const expectedExeUrl = `${SOURCE_URLS.ytdlpReleaseBase}${encodeURIComponent(tag)}/yt-dlp.exe`;
  const expectedSumsUrl = `${SOURCE_URLS.ytdlpReleaseBase}${encodeURIComponent(tag)}/SHA2-256SUMS`;
  const expectedSigUrl = `${SOURCE_URLS.ytdlpReleaseBase}${encodeURIComponent(tag)}/SHA2-256SUMS.sig`;
  const exeUrl = requireHttpsUrl(exe.browser_download_url, 'yt-dlp executable asset URL', expectedExeUrl);
  requireHttpsUrl(sums.browser_download_url, 'yt-dlp checksum asset URL', expectedSumsUrl);
  requireHttpsUrl(sig.browser_download_url, 'yt-dlp signature asset URL', expectedSigUrl);

  const [checksumBytes, signatureBytes] = await Promise.all([
    fetchBytes(expectedSumsUrl, { fetchImpl, maxBytes: MAX_TEXT_BYTES, label: 'yt-dlp signed checksum file' }),
    fetchBytes(expectedSigUrl, { fetchImpl, maxBytes: MAX_SIGNATURE_BYTES, label: 'yt-dlp detached signature' }),
  ]);
  const checksumHash = parseYtDlpChecksumFile(checksumBytes.toString('utf8'));
  const githubDigest = parseGitHubDigest(exe.digest, 'yt-dlp GitHub asset digest');
  if (githubDigest && githubDigest !== checksumHash)
    throw new Error('yt-dlp GitHub asset digest disagrees with its upstream-signed SHA2-256SUMS entry.');
  const verified = await verifySignature({ checksumBytes, signatureBytes, publicKeyPath, expectedFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT });
  if (verified.fingerprint?.toUpperCase() !== YTDLP_SIGNING_KEY_FINGERPRINT || verified.signerFingerprint?.toUpperCase() !== YTDLP_SIGNING_KEY_FINGERPRINT)
    throw new Error('yt-dlp detached signature verifier did not return the pinned signer identity.');

  const checkedAt = now().toISOString();
  return {
    component: 'YtDlp',
    display_name: 'yt-dlp',
    version: tag,
    release_date: envelope.publishedAt.slice(0, 10),
    published_at: envelope.publishedAt,
    release_url: envelope.releaseUrl,
    source_url: exeUrl,
    asset_name: 'yt-dlp.exe',
    size_bytes: exe.size,
    sha256: checksumHash,
    last_checked_at: checkedAt,
    metadata_sources: [SOURCE_URLS.ytdlpReleaseApi, expectedSumsUrl, expectedSigUrl],
    security: {
      status: 'verified',
      verification_method: 'openpgp_detached_signature',
      publisher_signature_verified: true,
      signing_key_fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT,
      signer_fingerprint: verified.signerFingerprint.toUpperCase(),
      signed_checksum_file: 'SHA2-256SUMS',
      signature_file: 'SHA2-256SUMS.sig',
      signed_checksum_sha256: sha256(checksumBytes),
      signature_file_sha256: sha256(signatureBytes),
      github_asset_digest_sha256: githubDigest,
      github_asset_digest_match: githubDigest === null ? null : true,
      assurance_note: 'The exact upstream SHA2-256SUMS bytes were verified against one detached OpenPGP signature from the pinned primary signing key. The executable SHA-256 was read from that signed file. GitHub asset digest is an additional cross-check when present; no executable binary was downloaded by this monitor.',
    },
  };
}

async function checkFfmpeg({ fetchImpl, now }) {
  const versionBytes = await fetchBytes(SOURCE_URLS.gyanReleaseVersion, { fetchImpl, maxBytes: 4096, label: 'Gyan FFmpeg release version' });
  const versionText = versionBytes.toString('utf8').trim();
  if (!/^\d+(?:\.\d+){1,2}$/.test(versionText)) throw new Error('Gyan FFmpeg release-version did not contain a valid numeric version.');
  const version = versionText;
  const expectedAssetName = `ffmpeg-${version}-full_build.7z`;
  const releaseApi = `${SOURCE_URLS.ffmpegGitHubReleaseApiPrefix}${encodeURIComponent(version)}`;

  const [sidecarBytes, release] = await Promise.all([
    fetchBytes(SOURCE_URLS.gyanFullChecksum, { fetchImpl, maxBytes: 64 * 1024, label: 'Gyan FFmpeg checksum sidecar' }),
    fetchJson(releaseApi, { fetchImpl, label: 'Gyan FFmpeg matching GitHub release API' }),
  ]);
  const gyanHash = parseGyanChecksumSidecar(sidecarBytes.toString('utf8'));
  const envelope = validateReleaseEnvelope(release, version, 'Gyan FFmpeg');
  const expectedReleaseUrl = `https://github.com/GyanD/codexffmpeg/releases/tag/${encodeURIComponent(version)}`;
  if (envelope.releaseUrl !== expectedReleaseUrl) throw new Error('Gyan FFmpeg release page URL does not match the expected repository and tag.');
  if (!release.author || typeof release.author.login !== 'string' || release.author.login.toLowerCase() !== 'gyand')
    throw new Error('The FFmpeg release was not published by the expected GyanD GitHub account.');

  const asset = oneAsset(release.assets, expectedAssetName, 'Gyan FFmpeg');
  if (asset.size > MAX_FFMPEG_ARCHIVE_BYTES) throw new Error('The Gyan FFmpeg Full archive exceeds the permitted 600 MiB size.');
  const expectedAssetUrl = `https://github.com/GyanD/codexffmpeg/releases/download/${encodeURIComponent(version)}/${expectedAssetName}`;
  const assetUrl = requireHttpsUrl(asset.browser_download_url, 'Gyan FFmpeg archive URL', expectedAssetUrl);
  const githubDigest = parseGitHubDigest(asset.digest, 'Gyan FFmpeg GitHub asset digest', { required: true });
  if (githubDigest !== gyanHash) throw new Error('The Gyan FFmpeg sidecar SHA-256 does not match the GitHub Release asset digest.');

  const checkedAt = now().toISOString();
  return {
    component: 'FFmpeg',
    display_name: 'FFmpeg (Gyan.dev Full build)',
    version,
    release_date: envelope.publishedAt.slice(0, 10),
    published_at: envelope.publishedAt,
    release_url: envelope.releaseUrl,
    source_url: assetUrl,
    asset_name: expectedAssetName,
    size_bytes: asset.size,
    sha256: githubDigest,
    last_checked_at: checkedAt,
    metadata_sources: [SOURCE_URLS.gyanReleaseVersion, SOURCE_URLS.gyanFullChecksum, releaseApi],
    security: {
      status: 'cross_checked',
      verification_method: 'github_asset_digest_vs_gyan_sidecar',
      publisher_signature_verified: false,
      github_asset_digest_sha256: githubDigest,
      gyan_sidecar_sha256: gyanHash,
      checksums_match: true,
      sidecar_source_url: SOURCE_URLS.gyanFullChecksum,
      assurance_note: 'The GitHub Release asset SHA-256 digest matches the independently retrieved Gyan.dev checksum sidecar. This is a checksum cross-check, not a detached Gyan publisher signature or proof that either publisher/build system is uncompromised. The archive was not downloaded by this monitor.',
    },
  };
}

function assertExactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index]))
    throw new Error(`${label} has missing or unexpected properties (expected: ${wanted.join(', ')}).`);
}

function assertIsoUtc(value, label) {
  requireString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value))
    throw new Error(`${label} must be a valid UTC ISO-8601 timestamp ending in Z.`);
  assertIsoDate(value.slice(0, 10), `${label} date`);
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${label} must be a valid UTC ISO-8601 timestamp ending in Z.`);
}

function assertIsoDate(value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value))
    throw new Error(`${label} must be a valid YYYY-MM-DD date.`);
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day)
    throw new Error(`${label} must be a real calendar date.`);
}

function assertUrl(value, label) {
  requireString(value, label);
  let url;
  try { url = new URL(value); } catch { throw new Error(`${label} must be a valid URL.`); }
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error(`${label} must be an HTTPS URL without credentials.`);
}

function assertHash(value, label) {
  if (typeof value !== 'string' || !HEX_256.test(value)) throw new Error(`${label} must be a lowercase SHA-256 digest.`);
}

function validateCommonRelease(item, label, expectedComponent) {
  assertExactKeys(item, ['component', 'display_name', 'version', 'release_date', 'published_at', 'release_url', 'source_url', 'asset_name', 'size_bytes', 'sha256', 'last_checked_at', 'metadata_sources', 'security'], `${label} component`);
  if (item.component !== expectedComponent) throw new Error(`${label}.component must be ${expectedComponent}.`);
  for (const key of ['display_name', 'version', 'asset_name']) requireString(item[key], `${label}.${key}`);
  assertIsoDate(item.release_date, `${label}.release_date`);
  assertIsoUtc(item.published_at, `${label}.published_at`);
  assertIsoUtc(item.last_checked_at, `${label}.last_checked_at`);
  assertUrl(item.release_url, `${label}.release_url`);
  assertUrl(item.source_url, `${label}.source_url`);
  assertHash(item.sha256, `${label}.sha256`);
  if (!Number.isSafeInteger(item.size_bytes) || item.size_bytes <= 0) throw new Error(`${label}.size_bytes must be a positive safe integer.`);
  if (!Array.isArray(item.metadata_sources) || item.metadata_sources.length !== 3) throw new Error(`${label}.metadata_sources must contain exactly three URLs.`);
  item.metadata_sources.forEach((url, index) => assertUrl(url, `${label}.metadata_sources[${index}]`));
}

export function validateUpstreamStatus(snapshot) {
  assertExactKeys(snapshot, ['schema_version', 'status', 'generated_at', 'last_checked_at', 'monitor', 'components'], 'upstream-status snapshot');
  if (snapshot.schema_version !== 1 || snapshot.status !== 'success') throw new Error('Snapshot schema_version/status is unsupported.');
  assertIsoUtc(snapshot.generated_at, 'generated_at');
  assertIsoUtc(snapshot.last_checked_at, 'last_checked_at');
  if (snapshot.last_checked_at !== snapshot.generated_at) throw new Error('last_checked_at must match the completed snapshot generation time.');
  assertExactKeys(snapshot.monitor, ['name', 'workflow', 'repository', 'commit_sha', 'run_id', 'run_attempt', 'trigger'], 'monitor');
  if (snapshot.monitor.name !== 'VidMax upstream release monitor') throw new Error('Unexpected monitor name.');
  for (const key of ['workflow', 'repository', 'commit_sha', 'run_id']) requireString(snapshot.monitor[key], `monitor.${key}`);
  if (!Number.isSafeInteger(snapshot.monitor.run_attempt) || snapshot.monitor.run_attempt < 1) throw new Error('monitor.run_attempt must be a positive integer.');
  if (!['schedule', 'workflow_dispatch', 'local'].includes(snapshot.monitor.trigger)) throw new Error('monitor.trigger is unsupported.');
  if (snapshot.monitor.trigger !== 'local') {
    if (snapshot.monitor.repository !== 'VidMax-Software/vidmax-engine-releases') throw new Error('Remote monitor repository identity is not the approved release repository.');
    if (!/^[a-fA-F0-9]{40}$/.test(snapshot.monitor.commit_sha)) throw new Error('Remote monitor commit_sha must be a full Git commit SHA.');
    if (!/^\d+$/.test(snapshot.monitor.run_id)) throw new Error('Remote monitor run_id must be numeric.');
  }
  assertExactKeys(snapshot.components, ['ytdlp', 'ffmpeg'], 'components');

  const yt = snapshot.components.ytdlp;
  validateCommonRelease(yt, 'ytdlp', 'YtDlp');
  if (yt.display_name !== 'yt-dlp' || yt.asset_name !== 'yt-dlp.exe' || yt.size_bytes > MAX_YTDLP_EXE_BYTES || !SAFE_VERSION.test(yt.version))
    throw new Error('yt-dlp release identity or asset size is invalid.');
  const expectedYtRelease = `https://github.com/yt-dlp/yt-dlp/releases/tag/${encodeURIComponent(yt.version)}`;
  const expectedYtAsset = `${SOURCE_URLS.ytdlpReleaseBase}${encodeURIComponent(yt.version)}/yt-dlp.exe`;
  const expectedYtSums = `${SOURCE_URLS.ytdlpReleaseBase}${encodeURIComponent(yt.version)}/SHA2-256SUMS`;
  const expectedYtSignature = `${SOURCE_URLS.ytdlpReleaseBase}${encodeURIComponent(yt.version)}/SHA2-256SUMS.sig`;
  if (yt.release_url !== expectedYtRelease || yt.source_url !== expectedYtAsset || yt.metadata_sources[0] !== SOURCE_URLS.ytdlpReleaseApi || yt.metadata_sources[1] !== expectedYtSums || yt.metadata_sources[2] !== expectedYtSignature)
    throw new Error('yt-dlp source metadata does not match the pinned upstream repository paths.');
  if (yt.release_date !== yt.published_at.slice(0, 10)) throw new Error('yt-dlp release_date does not match published_at.');
  assertExactKeys(yt.security, ['status', 'verification_method', 'publisher_signature_verified', 'signing_key_fingerprint', 'signer_fingerprint', 'signed_checksum_file', 'signature_file', 'signed_checksum_sha256', 'signature_file_sha256', 'github_asset_digest_sha256', 'github_asset_digest_match', 'assurance_note'], 'yt-dlp.security');
  const yts = yt.security;
  if (yts.status !== 'verified' || yts.verification_method !== 'openpgp_detached_signature' || yts.publisher_signature_verified !== true)
    throw new Error('yt-dlp signature-verification status is not verified.');
  if (yts.signing_key_fingerprint !== YTDLP_SIGNING_KEY_FINGERPRINT || yts.signer_fingerprint !== YTDLP_SIGNING_KEY_FINGERPRINT)
    throw new Error('yt-dlp signing identity does not match the pinned upstream key.');
  if (yts.signed_checksum_file !== 'SHA2-256SUMS' || yts.signature_file !== 'SHA2-256SUMS.sig') throw new Error('yt-dlp signature evidence filenames are invalid.');
  assertHash(yts.signed_checksum_sha256, 'yt-dlp.security.signed_checksum_sha256');
  assertHash(yts.signature_file_sha256, 'yt-dlp.security.signature_file_sha256');
  if (yts.github_asset_digest_sha256 !== null) {
    assertHash(yts.github_asset_digest_sha256, 'yt-dlp.security.github_asset_digest_sha256');
    if (yts.github_asset_digest_match !== true || yts.github_asset_digest_sha256 !== yt.sha256) throw new Error('yt-dlp GitHub asset digest cross-check is inconsistent.');
  } else if (yts.github_asset_digest_match !== null) throw new Error('yt-dlp missing GitHub digest must be represented as a null cross-check.');
  requireString(yts.assurance_note, 'yt-dlp.security.assurance_note');

  const ff = snapshot.components.ffmpeg;
  validateCommonRelease(ff, 'ffmpeg', 'FFmpeg');
  if (ff.display_name !== 'FFmpeg (Gyan.dev Full build)' || !/^\d+(?:\.\d+){1,2}$/.test(ff.version) || ff.asset_name !== `ffmpeg-${ff.version}-full_build.7z` || ff.size_bytes > MAX_FFMPEG_ARCHIVE_BYTES)
    throw new Error('FFmpeg release identity or asset size is invalid.');
  const expectedFfmpegRelease = `https://github.com/GyanD/codexffmpeg/releases/tag/${encodeURIComponent(ff.version)}`;
  const expectedFfmpegAsset = `https://github.com/GyanD/codexffmpeg/releases/download/${encodeURIComponent(ff.version)}/${ff.asset_name}`;
  const expectedFfmpegApi = `${SOURCE_URLS.ffmpegGitHubReleaseApiPrefix}${encodeURIComponent(ff.version)}`;
  if (ff.release_url !== expectedFfmpegRelease || ff.source_url !== expectedFfmpegAsset || ff.metadata_sources[0] !== SOURCE_URLS.gyanReleaseVersion || ff.metadata_sources[1] !== SOURCE_URLS.gyanFullChecksum || ff.metadata_sources[2] !== expectedFfmpegApi)
    throw new Error('FFmpeg source metadata does not match the approved Gyan.dev/GitHub paths.');
  if (ff.release_date !== ff.published_at.slice(0, 10)) throw new Error('FFmpeg release_date does not match published_at.');
  assertExactKeys(ff.security, ['status', 'verification_method', 'publisher_signature_verified', 'github_asset_digest_sha256', 'gyan_sidecar_sha256', 'checksums_match', 'sidecar_source_url', 'assurance_note'], 'ffmpeg.security');
  const ffs = ff.security;
  if (ffs.status !== 'cross_checked' || ffs.verification_method !== 'github_asset_digest_vs_gyan_sidecar' || ffs.publisher_signature_verified !== false || ffs.checksums_match !== true)
    throw new Error('FFmpeg checksum cross-check status is invalid.');
  assertHash(ffs.github_asset_digest_sha256, 'ffmpeg.security.github_asset_digest_sha256');
  assertHash(ffs.gyan_sidecar_sha256, 'ffmpeg.security.gyan_sidecar_sha256');
  if (ffs.github_asset_digest_sha256 !== ff.sha256 || ffs.gyan_sidecar_sha256 !== ff.sha256) throw new Error('FFmpeg checksum evidence does not match the published asset hash.');
  if (ffs.sidecar_source_url !== SOURCE_URLS.gyanFullChecksum) throw new Error('FFmpeg checksum sidecar source is not the approved Gyan.dev endpoint.');
  requireString(ffs.assurance_note, 'ffmpeg.security.assurance_note');
  if (!/not a detached Gyan publisher signature/i.test(ffs.assurance_note)) throw new Error('FFmpeg assurance note must state that no Gyan detached signature was verified.');
  return true;
}

export async function collectUpstreamStatus({
  fetchImpl = fetch,
  now = () => new Date(),
  verifySignature = verifyYtDlpDetachedSignature,
  publicKeyPath = DEFAULT_PUBLIC_KEY,
  monitor = {},
} = {}) {
  const [ytdlp, ffmpeg] = await Promise.all([
    checkYtDlp({ fetchImpl, now, verifySignature, publicKeyPath }),
    checkFfmpeg({ fetchImpl, now }),
  ]);
  const generatedAt = now().toISOString();
  const snapshot = {
    schema_version: 1,
    status: 'success',
    generated_at: generatedAt,
    last_checked_at: generatedAt,
    monitor: {
      name: 'VidMax upstream release monitor',
      workflow: monitor.workflow ?? process.env.GITHUB_WORKFLOW ?? 'local',
      repository: monitor.repository ?? process.env.GITHUB_REPOSITORY ?? 'local/vidmax-engine-releases',
      commit_sha: monitor.commit_sha ?? process.env.GITHUB_SHA ?? 'local',
      run_id: String(monitor.run_id ?? process.env.GITHUB_RUN_ID ?? 'local'),
      run_attempt: Number(monitor.run_attempt ?? process.env.GITHUB_RUN_ATTEMPT ?? 1),
      trigger: monitor.trigger ?? (process.env.GITHUB_EVENT_NAME === 'schedule' ? 'schedule' : process.env.GITHUB_EVENT_NAME === 'workflow_dispatch' ? 'workflow_dispatch' : 'local'),
    },
    components: { ytdlp, ffmpeg },
  };
  validateUpstreamStatus(snapshot);
  return snapshot;
}

export async function writeSnapshotAtomically(path, snapshot) {
  validateUpstreamStatus(snapshot);
  const outputPath = resolve(path);
  const parent = dirname(outputPath);
  await mkdir(parent, { recursive: true });
  const tempPath = resolve(parent, `.${outputPath.split(/[\\/]/).at(-1)}.${process.pid}.${Date.now()}.tmp`);
  try {
    await writeFile(tempPath, `${JSON.stringify(snapshot, null, 2)}\n`, { encoding: 'utf8', mode: 0o644, flag: 'wx' });
    await rename(tempPath, outputPath);
  } finally {
    await rm(tempPath, { force: true }).catch(() => {});
  }
}

export function parseOutputArg(argv) {
  if (!Array.isArray(argv)) throw new Error('CLI arguments must be an array.');
  if (argv.length === 0) return 'upstream-status.json';
  if (argv.length !== 2 || argv[0] !== '--output' || !argv[1] || argv[1].startsWith('--'))
    throw new Error('Usage: node scripts/monitor-upstream.mjs [--output <path>].');
  return argv[1];
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    // Reject malformed command-line input before any upstream network request.
    const output = parseOutputArg(process.argv.slice(2));
    const snapshot = await collectUpstreamStatus();
    await writeSnapshotAtomically(output, snapshot);
    console.log(`[PASS] Verified upstream metadata and atomically wrote ${resolve(output)}.`);
    console.log(`[INFO] yt-dlp ${snapshot.components.ytdlp.version}; FFmpeg ${snapshot.components.ffmpeg.version}.`);
    console.log('[INFO] No engine binary was downloaded, and no Worker/D1 or channel state was changed.');
  } catch (error) {
    console.error(`[FAILED] Upstream monitoring failed; no new snapshot was published. ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
