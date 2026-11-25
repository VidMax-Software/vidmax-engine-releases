import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  YTDLP_SIGNING_KEY_FINGERPRINT,
  SOURCE_URLS,
  collectUpstreamStatus,
  parseGyanChecksumSidecar,
  parseOutputArg,
  parseYtDlpChecksumFile,
  validateUpstreamStatus,
  verifyYtDlpDetachedSignature,
  writeSnapshotAtomically,
} from '../scripts/monitor-upstream.mjs';

const NOW = '2026-11-25T04:00:00.000Z';
const YTDLP_VERSION = '2026.11.23';
const FFMPEG_VERSION = '9.0.2';
const YTDLP_HASH = 'a'.repeat(64);
const FFMPEG_HASH = 'b'.repeat(64);
const CHECKSUM_BYTES = Buffer.from(`${YTDLP_HASH} *yt-dlp.exe\n`, 'utf8');
const SIGNATURE_BYTES = Buffer.from('test detached signature', 'utf8');
const PINNED_KEY_PATH = fileURLToPath(new URL('../scripts/keys/yt-dlp-signing-public.asc', import.meta.url));
const SCHEMA_PATH = fileURLToPath(new URL('../schemas/upstream-status.schema.json', import.meta.url));

function jsonResponse(value, url = '') {
  const response = new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
  if (url) Object.defineProperty(response, 'url', { value: url });
  return response;
}
function textResponse(value, url = '') {
  const response = new Response(value, { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  if (url) Object.defineProperty(response, 'url', { value: url });
  return response;
}

function mockSources({ ytdlpDigest = `sha256:${YTDLP_HASH}`, gyanHash = FFMPEG_HASH } = {}) {
  const ytTag = YTDLP_VERSION;
  const ffTag = FFMPEG_VERSION;
  const ghAsset = (name, owner, repo, tag, size, digest = null) => ({
    name, state: 'uploaded', size,
    browser_download_url: `https://github.com/${owner}/${repo}/releases/download/${tag}/${name}`,
    digest,
  });
  const ytRelease = {
    tag_name: ytTag,
    draft: false,
    prerelease: false,
    published_at: '2026-11-23T23:49:48Z',
    html_url: `https://github.com/yt-dlp/yt-dlp/releases/tag/${ytTag}`,
    assets: [
      ghAsset('yt-dlp.exe', 'yt-dlp', 'yt-dlp', ytTag, 22_500_000, ytdlpDigest),
      ghAsset('SHA2-256SUMS', 'yt-dlp', 'yt-dlp', ytTag, 1_600),
      ghAsset('SHA2-256SUMS.sig', 'yt-dlp', 'yt-dlp', ytTag, 566),
    ],
  };
  const ffRelease = {
    tag_name: ffTag,
    draft: false,
    prerelease: false,
    published_at: '2026-09-20T06:40:00Z',
    html_url: `https://github.com/GyanD/codexffmpeg/releases/tag/${ffTag}`,
    author: { login: 'GyanD' },
    assets: [ghAsset(`ffmpeg-${ffTag}-full_build.7z`, 'GyanD', 'codexffmpeg', ffTag, 400_000_000, `sha256:${FFMPEG_HASH}`)],
  };

  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (url === SOURCE_URLS.ytdlpReleaseApi) return jsonResponse(ytRelease);
    if (url === SOURCE_URLS.gyanReleaseVersion) return textResponse(`${FFMPEG_VERSION}\n`);
    if (url === SOURCE_URLS.gyanFullChecksum) return textResponse(`${gyanHash}  ffmpeg-release-full.7z\n`);
    if (url === SOURCE_URLS.ffmpegGitHubReleaseApiPrefix + FFMPEG_VERSION) return jsonResponse(ffRelease);
    if (url.endsWith(`/releases/download/${ytTag}/SHA2-256SUMS`)) return new Response(CHECKSUM_BYTES, { status: 200 });
    if (url.endsWith(`/releases/download/${ytTag}/SHA2-256SUMS.sig`)) return new Response(SIGNATURE_BYTES, { status: 200 });
    throw new Error(`Unexpected test request: ${url}`);
  };
  return { fetchImpl, calls };
}

 test('parses exactly one yt-dlp.exe checksum and tolerates GNU/BSD-style filename markers', () => {
  assert.equal(parseYtDlpChecksumFile(`${'c'.repeat(64)}  folder\\yt-dlp.exe\n`, 'yt-dlp.exe'), 'c'.repeat(64));
  assert.equal(parseYtDlpChecksumFile(`${'d'.repeat(64)} *yt-dlp.exe\n`, 'yt-dlp.exe'), 'd'.repeat(64));
  assert.throws(() => parseYtDlpChecksumFile(`${'e'.repeat(64)} yt-dlp.exe\n${'f'.repeat(64)} yt-dlp.exe\n`), /exactly one/);
  assert.throws(() => parseYtDlpChecksumFile(`${'a'.repeat(64)} yt-dlp-linux\n`), /exactly one/);
});


test('accepts only the documented output CLI arguments', () => {
  assert.equal(parseOutputArg([]), 'upstream-status.json');
  assert.equal(parseOutputArg(['--output', 'C:/temp/status.json']), 'C:/temp/status.json');
  assert.throws(() => parseOutputArg(['--unknown']), /Usage:/);
  assert.throws(() => parseOutputArg(['--output']), /Usage:/);
  assert.throws(() => parseOutputArg(['--output', 'status.json', '--extra']), /Usage:/);
});

test('parses exactly one Gyan FFmpeg sidecar SHA-256', () => {
  assert.equal(parseGyanChecksumSidecar(`${FFMPEG_HASH}  ffmpeg-release-full.7z\n`), FFMPEG_HASH);
  assert.throws(() => parseGyanChecksumSidecar(`${FFMPEG_HASH}\n${'c'.repeat(64)}\n`), /exactly one/);
  assert.throws(() => parseGyanChecksumSidecar('not a checksum'), /exactly one/);
});

test('collects a complete C5-01 snapshot with pinned yt-dlp signature and honest FFmpeg cross-check semantics', async () => {
  const { fetchImpl, calls } = mockSources();
  let verifierArguments;
  const snapshot = await collectUpstreamStatus({
    fetchImpl,
    now: () => new Date(NOW),
    verifySignature: async args => {
      verifierArguments = args;
      return { fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT, signerFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT };
    },
    monitor: { trigger: 'local', repository: 'local/test', commit_sha: 'local-test' },
  });

  assert.equal(snapshot.schema_version, 1);
  assert.equal(snapshot.status, 'success');
  assert.equal(snapshot.generated_at, NOW);
  assert.equal(snapshot.last_checked_at, NOW);
  assert.equal(snapshot.components.ytdlp.version, YTDLP_VERSION);
  assert.equal(snapshot.components.ytdlp.sha256, YTDLP_HASH);
  assert.equal(snapshot.components.ytdlp.security.publisher_signature_verified, true);
  assert.equal(snapshot.components.ytdlp.security.signing_key_fingerprint, YTDLP_SIGNING_KEY_FINGERPRINT);
  assert.equal(snapshot.components.ffmpeg.version, FFMPEG_VERSION);
  assert.equal(snapshot.components.ffmpeg.sha256, FFMPEG_HASH);
  assert.equal(snapshot.components.ffmpeg.security.status, 'cross_checked');
  assert.equal(snapshot.components.ffmpeg.security.publisher_signature_verified, false);
  assert.match(snapshot.components.ffmpeg.security.assurance_note, /not a detached Gyan publisher signature/);
  assert.equal(verifierArguments.checksumBytes.toString('utf8'), CHECKSUM_BYTES.toString('utf8'));
  assert.equal(verifierArguments.signatureBytes.toString('utf8'), SIGNATURE_BYTES.toString('utf8'));
  assert.equal(verifierArguments.expectedFingerprint, YTDLP_SIGNING_KEY_FINGERPRINT);
  assert.equal(calls.some(call => call.url.endsWith('/yt-dlp.exe')), false, 'the monitor must not download the yt-dlp executable');
  assert.equal(calls.some(call => call.url.endsWith('.7z')), false, 'the monitor must not download the FFmpeg archive');
  assert.equal(calls.length, 6, 'only the two release APIs, Gyan metadata and two yt-dlp signature evidence files are fetched');
  assert.equal(validateUpstreamStatus(snapshot), true);
});

test('published schema is strict Draft 2020-12 with the expected v1 components', async () => {
  const schema = JSON.parse(await readFile(SCHEMA_PATH, 'utf8'));
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.properties.schema_version.const, 1);
  assert.equal(schema.properties.status.const, 'success');
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(Object.keys(schema.properties.components.properties).sort(), ['ffmpeg', 'ytdlp']);
  assert.equal(schema.$defs.ytdlp.allOf[1].properties.security.properties.publisher_signature_verified.const, true);
  assert.equal(schema.$defs.ffmpeg.allOf[1].properties.security.properties.publisher_signature_verified.const, false);
});

test('snapshot replacement validates before atomically replacing an existing file', async () => {
  const { fetchImpl } = mockSources();
  const snapshot = await collectUpstreamStatus({
    fetchImpl,
    now: () => new Date(NOW),
    verifySignature: async () => ({ fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT, signerFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT }),
  });
  const directory = await mkdtemp(resolve(tmpdir(), 'vidmax-c5-atomic-'));
  const outputPath = resolve(directory, 'upstream-status.json');
  try {
    await writeFile(outputPath, '{"old":true}\n');
    await writeSnapshotAtomically(outputPath, snapshot);
    assert.deepEqual(JSON.parse(await readFile(outputPath, 'utf8')), snapshot);
    await assert.rejects(writeSnapshotAtomically(outputPath, { ...snapshot, status: 'failed' }), /schema_version\/status is unsupported/);
    assert.deepEqual(JSON.parse(await readFile(outputPath, 'utf8')), snapshot, 'invalid candidate must not replace the last valid snapshot');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('follows only the approved GitHub release-asset CDN redirect', async () => {
  const { fetchImpl: baseFetch } = mockSources();
  const sumsUrl = `${SOURCE_URLS.ytdlpReleaseBase}${YTDLP_VERSION}/SHA2-256SUMS`;
  const sigUrl = `${SOURCE_URLS.ytdlpReleaseBase}${YTDLP_VERSION}/SHA2-256SUMS.sig`;
  const fetchImpl = async (url, options) => {
    if (url === sumsUrl) return new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/assets/sums' } });
    if (url === sigUrl) return new Response(null, { status: 302, headers: { location: 'https://release-assets.githubusercontent.com/assets/signature' } });
    if (url === 'https://release-assets.githubusercontent.com/assets/sums') return new Response(CHECKSUM_BYTES, { status: 200 });
    if (url === 'https://release-assets.githubusercontent.com/assets/signature') return new Response(SIGNATURE_BYTES, { status: 200 });
    return baseFetch(url, options);
  };
  const snapshot = await collectUpstreamStatus({
    fetchImpl,
    now: () => new Date(NOW),
    verifySignature: async () => ({ fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT, signerFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT }),
  });
  assert.equal(snapshot.components.ytdlp.sha256, YTDLP_HASH);
});

test('follows Gyan.dev release-checksum sidecar version-path redirect on the same host', async () => {
  const { fetchImpl: baseFetch } = mockSources();
  const sidecarUrl = SOURCE_URLS.gyanFullChecksum;
  const finalSidecarUrl = 'https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-9.0.2-full_build.7z.sha256';
  const fetchImpl = async (url, options) => {
    if (url === sidecarUrl) return new Response(null, { status: 302, headers: { location: '/ffmpeg/builds/packages/ffmpeg-9.0.2-full_build.7z.sha256' } });
    if (url === finalSidecarUrl) return new Response(`${FFMPEG_HASH}  ffmpeg-release-full.7z\n`, { status: 200 });
    return baseFetch(url, options);
  };
  const snapshot = await collectUpstreamStatus({
    fetchImpl,
    now: () => new Date(NOW),
    verifySignature: async () => ({ fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT, signerFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT }),
  });
  assert.equal(snapshot.components.ffmpeg.sha256, FFMPEG_HASH);
});

test('rejects a GitHub release-asset redirect to an unapproved host', async () => {
  const { fetchImpl: baseFetch } = mockSources();
  const sumsUrl = `${SOURCE_URLS.ytdlpReleaseBase}${YTDLP_VERSION}/SHA2-256SUMS`;
  const fetchImpl = async (url, options) => {
    if (url === sumsUrl) return new Response(null, { status: 302, headers: { location: 'https://attacker.invalid/steal' } });
    return baseFetch(url, options);
  };
  await assert.rejects(
    collectUpstreamStatus({ fetchImpl, now: () => new Date(NOW), verifySignature: async () => ({ fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT, signerFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT }) }),
    /outside the HTTPS upstream allowlist|unapproved host/,
  );
});

test('fails closed when GitHub and Gyan FFmpeg checksum evidence disagree', async () => {
  const { fetchImpl } = mockSources({ gyanHash: 'c'.repeat(64) });
  await assert.rejects(
    collectUpstreamStatus({ fetchImpl, now: () => new Date(NOW), verifySignature: async () => ({ fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT, signerFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT }) }),
    /does not match the GitHub Release asset digest/,
  );
});

test('fails closed when yt-dlp GitHub digest disagrees with the signed checksum entry', async () => {
  const { fetchImpl } = mockSources({ ytdlpDigest: `sha256:${'c'.repeat(64)}` });
  await assert.rejects(
    collectUpstreamStatus({ fetchImpl, now: () => new Date(NOW), verifySignature: async () => ({ fingerprint: YTDLP_SIGNING_KEY_FINGERPRINT, signerFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT }) }),
    /disagrees with its upstream-signed/,
  );
});

test('fails closed when yt-dlp detached signature verification fails', async () => {
  const { fetchImpl } = mockSources();
  await assert.rejects(
    collectUpstreamStatus({ fetchImpl, now: () => new Date(NOW), verifySignature: async () => { throw new Error('bad signature'); } }),
    /bad signature/,
  );
});

test('bundled yt-dlp public key fingerprint matches the audited Desktop pin', async t => {
  const gpgCheck = spawnSync('gpg', ['--version'], { encoding: 'utf8' });
  if (gpgCheck.error || gpgCheck.status !== 0) {
    t.skip('GnuPG is not installed in this environment.');
    return;
  }
  const home = await mkdtemp(resolve(tmpdir(), 'vidmax-c5-pinned-key-'));
  try {
    execFileSync('gpg', ['--batch', '--no-tty', '--homedir', home, '--import', PINNED_KEY_PATH], { stdio: 'pipe' });
    const listing = execFileSync('gpg', ['--batch', '--no-tty', '--homedir', home, '--with-colons', '--fingerprint', '--list-keys'], { encoding: 'utf8' });
    const primaryFingerprint = listing.split(/\r?\n/).find(line => line.startsWith('fpr:'))?.split(':')[9]?.toUpperCase();
    assert.equal(primaryFingerprint, YTDLP_SIGNING_KEY_FINGERPRINT);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('verifies a detached OpenPGP signature and rejects tampered checksum bytes', async t => {
  const gpgCheck = spawnSync('gpg', ['--version'], { encoding: 'utf8' });
  if (gpgCheck.error || gpgCheck.status !== 0) {
    t.skip('GnuPG is not installed in this environment.');
    return;
  }
  const home = await mkdtemp(resolve(tmpdir(), 'vidmax-c5-test-gpg-'));
  try {
    const run = args => execFileSync('gpg', ['--batch', '--yes', '--no-tty', '--homedir', home, ...args], { stdio: 'pipe' });
    run(['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', 'VidMax C5 test <vidmax-c5@example.invalid>', 'ed25519', 'sign', '0']);
    const listing = execFileSync('gpg', ['--batch', '--no-tty', '--homedir', home, '--with-colons', '--fingerprint', '--list-keys'], { encoding: 'utf8' });
    const fingerprint = listing.split(/\r?\n/).find(line => line.startsWith('fpr:'))?.split(':')[9];
    assert.match(fingerprint || '', /^[A-F0-9]{40}$/i);

    const messagePath = resolve(home, 'signed-checksums.txt');
    const signaturePath = resolve(home, 'signed-checksums.txt.sig');
    const publicKeyPath = resolve(home, 'test-public-key.asc');
    const message = Buffer.from(`${'9'.repeat(64)} *yt-dlp.exe\n`, 'utf8');
    await writeFile(messagePath, message);
    run(['--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', fingerprint, '--output', signaturePath, '--detach-sign', messagePath]);
    const publicKey = execFileSync('gpg', ['--batch', '--no-tty', '--homedir', home, '--armor', '--export', fingerprint]);
    await writeFile(publicKeyPath, publicKey);
    const signature = await readFile(signaturePath);

    const verification = await verifyYtDlpDetachedSignature({ checksumBytes: message, signatureBytes: signature, publicKeyPath, expectedFingerprint: fingerprint });
    assert.equal(verification.fingerprint, fingerprint);
    await assert.rejects(
      verifyYtDlpDetachedSignature({ checksumBytes: Buffer.from(`${'8'.repeat(64)} *yt-dlp.exe\n`), signatureBytes: signature, publicKeyPath, expectedFingerprint: fingerprint }),
      /GnuPG rejected|did not report exactly one valid detached signature/,
    );
    await assert.rejects(
      verifyYtDlpDetachedSignature({ checksumBytes: message, signatureBytes: signature, publicKeyPath, expectedFingerprint: YTDLP_SIGNING_KEY_FINGERPRINT }),
      /does not match the pinned fingerprint/,
    );
    const weakSignaturePath = resolve(home, 'signed-checksums-sha1.sig');
    run(['--digest-algo', 'SHA1', '--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', fingerprint, '--output', weakSignaturePath, '--detach-sign', messagePath]);
    const weakSignature = await readFile(weakSignaturePath);
    await assert.rejects(
      verifyYtDlpDetachedSignature({ checksumBytes: message, signatureBytes: weakSignature, publicKeyPath, expectedFingerprint: fingerprint }),
      /must use SHA-256 or SHA-512/,
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
