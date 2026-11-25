#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { validateUpstreamStatus } from './monitor-upstream.mjs';

const path = resolve(process.argv[2] || 'upstream-status.json');
try {
  const snapshot = JSON.parse(await readFile(path, 'utf8'));
  validateUpstreamStatus(snapshot);
  console.log(`[PASS] ${path} conforms to the VidMax upstream-status v1 contract.`);
} catch (error) {
  console.error(`[FAILED] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
