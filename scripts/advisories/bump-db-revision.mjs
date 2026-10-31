#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * DBのみ更新リリース用のバージョン採番 (scripts/advisories/bump-db-revision.mjs)
 *
 * Chrome Web Store はアップロードのたびに manifest.version の増加を要求する。
 * コード変更を伴わない脆弱性DB更新リリースでは、manifest.version の第4要素 (DBリビジョン) のみを増やす:
 *   1.6.5      -> 1.6.5.1
 *   1.6.5.1    -> 1.6.5.2
 * package.json (semver) と RULES_VERSION は変更しない。コードリリース時は開発者が 3 要素へ戻す (例: 1.7.0)。
 * Chrome の manifest version は各要素 0〜65535 の整数で最大4要素 (https://developer.chrome.com/docs/extensions/reference/manifest/version)。
 *
 * 使い方: node scripts/advisories/bump-db-revision.mjs [--dry-run]
 */

import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { PATHS, readJson } from './lib/util.mjs';

export function nextDbRevision(version) {
  const parts = String(version).split('.');
  if (parts.length < 3 || parts.length > 4 || parts.some((p) => !/^\d+$/.test(p) || Number(p) > 65535)) {
    throw new Error(`manifest.version が想定外の形式です: ${version}`);
  }
  const rev = parts.length === 4 ? Number(parts[3]) + 1 : 1;
  if (rev > 65535) throw new Error('DBリビジョンが上限 (65535) に達しました。');
  return `${parts.slice(0, 3).join('.')}.${rev}`;
}

function main() {
  const dryRun = process.argv.includes('--dry-run');
  const raw = fs.readFileSync(PATHS.manifest, 'utf-8');
  const manifest = readJson(PATHS.manifest);
  const next = nextDbRevision(manifest.version);
  // 書式 (インデント等) を保つため文字列置換で更新する
  const updated = raw.replace(/("version"\s*:\s*")[^"]+(")/, `$1${next}$2`);
  if (!dryRun) fs.writeFileSync(PATHS.manifest, updated, 'utf-8');
  console.log(next);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `version=${next}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
