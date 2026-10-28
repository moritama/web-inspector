/**
 * Web Technology & Security Inspector
 * 脆弱性DBパイプライン共通ユーティリティ (scripts/advisories/lib/util.mjs)
 *
 * - パス解決、安定したJSON書き出し、semver系バージョン比較、ハッシュ計算
 * - 外部依存なし (Node.js 20+ 標準モジュールのみ)
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

/** リポジトリルート (scripts/advisories/lib から3階層上) */
export const ROOT_DIR = path.resolve(path.dirname(__filename), '..', '..', '..');

export const PATHS = {
  catalog: path.join(ROOT_DIR, 'data', 'advisories', 'catalog.json'),
  curated: path.join(ROOT_DIR, 'data', 'advisories', 'curated.json'),
  upstreamDir: path.join(ROOT_DIR, 'data', 'advisories', 'upstream'),
  buildReport: path.join(ROOT_DIR, 'data', 'advisories', 'build-report.json'),
  outputDb: path.join(ROOT_DIR, 'src', 'detection', 'advisory-db.json'),
  manifest: path.join(ROOT_DIR, 'public', 'manifest.json'),
  packageJson: path.join(ROOT_DIR, 'package.json'),
};

export function readJson(filePath, fallback = undefined) {
  if (!fs.existsSync(filePath)) {
    if (fallback !== undefined) return fallback;
    throw new Error(`ファイルが存在しません: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

/** 改行コード・末尾改行を固定した決定的なJSON書き出し (差分レビューを安定させる) */
export function stableStringify(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, stableStringify(value), 'utf-8');
}

export function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** ファイル名に使える安全なキーへ変換 (例: "@angular/core" -> "_angular__core") */
export function safeFileKey(text) {
  return String(text).replace(/[^A-Za-z0-9._-]/g, '_');
}

/**
 * バージョン文字列を比較可能な構造に分解する
 * - "v" 接頭辞を除去
 * - 数値部 (最大4要素) とプレリリース部を分離
 * - パース不能な場合は null
 */
export function parseVersion(version) {
  if (version === null || version === undefined) return null;
  const clean = String(version).trim().replace(/^v\.?/i, '');
  const m = clean.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?((?:alpha|beta|rc|pre|dev|preview|a|b)[0-9A-Za-z.-]*))?/i);
  if (!m) return null;
  return {
    parts: [m[1], m[2], m[3], m[4]].map((p) => (p === undefined ? 0 : parseInt(p, 10))),
    pre: m[5] ? m[5].toLowerCase() : null,
  };
}

/** 1: a>b, -1: a<b, 0: 等価。パース不能な値は比較対象外として0を返さず例外とする */
export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) {
    throw new Error(`比較できないバージョンです: "${a}" / "${b}"`);
  }
  for (let i = 0; i < 4; i++) {
    if (pa.parts[i] > pb.parts[i]) return 1;
    if (pa.parts[i] < pb.parts[i]) return -1;
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === null) return 1; // 正式版 > プレリリース
  if (pb.pre === null) return -1;
  return pa.pre > pb.pre ? 1 : pa.pre < pb.pre ? -1 : 0;
}

export function isComparableVersion(v) {
  return parseVersion(v) !== null;
}

/** YYYY-MM-DD 形式の日付文字列に正規化 (不正値は null) */
export function toIsoDate(value) {
  if (!value || typeof value !== 'string') return null;
  const m = value.match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : null;
}

export function uniq(arr) {
  return Array.from(new Set(arr));
}
