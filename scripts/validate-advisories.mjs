/**
 * Web Technology & Security Inspector
 * オフライン脆弱性DB 品質・整合性検証スクリプト (scripts/validate-advisories.mjs)
 *
 * ビルド前・パッケージング前・DB自動更新PRで実行され、advisory-db.json のスキーマ、
 * ファイルサイズ上限、収録件数、各エントリの一次情報整合性、および「UIへ埋め込まれても安全なデータか」
 * (HTML特殊文字・URLスキーム・ホスト) を検証する。(Rev.2.1 IMP-06 / DB-01 / v1.6.5レビュー DB-SEC-1)
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DB_FILE = path.join(ROOT_DIR, 'src', 'detection', 'advisory-db.json');

// 検証しきい値
export const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB上限
const MIN_PRODUCT_COUNT = 5; // 最低5製品
const MIN_ADVISORY_COUNT = 10; // 最低10件のアドバイザリ
const SUPPORTED_SCHEMA_VERSIONS = new Set(['2.1', '2.2']);

const ID_PATTERN = /^(?:CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|[A-Z]+-\d{4}-[0-9A-Za-z-]+)$/;
const URL_PREFIXES = ['https://nvd.nist.gov/vuln/detail/', 'https://github.com/advisories/', 'https://osv.dev/vulnerability/'];
const CLAUSE_RE = /^(<=|>=|<|>|=)\s*v?(\d+(?:\.\d+){0,3}(?:[-.][0-9A-Za-z.-]+)?)$/;
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const EOL_STATUSES = new Set(['Supported', 'Maintenance', 'EOL', 'Unknown']);
const FIX_STATUSES = new Set(['fixed', 'partial', 'none', 'unknown']);
const ORIGINS = new Set(['curated', 'auto']);
// eslint-disable-next-line no-control-regex
const UNSAFE_TEXT = /[<>"'`\u0000-\u001f\u007f]/;

/** CVSSスコアから期待される重大度を導出する */
function getExpectedSeverity(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

function isValidRange(spec) {
  if (typeof spec !== 'string' || !spec.trim()) return false;
  if (spec.trim() === '*') return true;
  return spec.split('||').every((b) => {
    const clauses = b.split(',').map((c) => c.trim()).filter(Boolean);
    return clauses.length > 0 && clauses.every((c) => CLAUSE_RE.test(c));
  });
}

/**
 * DB オブジェクトを検証する (テストから直接呼び出し可能)
 * @returns {{ productCount: number, advisoryCount: number }}
 */
export function validateDb(db, { sizeBytes = 0 } = {}) {
  if (sizeBytes > MAX_FILE_SIZE_BYTES) {
    throw new Error(`脆弱性DBのファイルサイズが上限(2MB)を超過しています: ${sizeBytes} bytes`);
  }
  if (!SUPPORTED_SCHEMA_VERSIONS.has(db.schemaVersion)) {
    throw new Error(`schemaVersion が不正です: 対応="${[...SUPPORTED_SCHEMA_VERSIONS].join(', ')}", 実際="${db.schemaVersion}"`);
  }
  if (!db.dataVersion || typeof db.dataVersion !== 'string' || !/^\d{8}$/.test(db.dataVersion)) {
    throw new Error('dataVersion が存在しないか無効です (YYYYMMDD)。');
  }
  if (!db.generatedAt || isNaN(new Date(db.generatedAt).getTime())) {
    throw new Error('generatedAt が有効なISO日時形式ではありません。');
  }
  if (new Date(db.generatedAt).getTime() > Date.now() + 86400_000) {
    throw new Error('generatedAt が未来日時です。');
  }
  if (!Array.isArray(db.sources) || db.sources.length === 0) {
    throw new Error('sources 配列が空または存在しません。');
  }
  if (!db.coverage || !Array.isArray(db.coverage.technologies)) {
    throw new Error('coverage.technologies 配列が存在しません。');
  }
  if (!db.libraries || typeof db.libraries !== 'object') {
    throw new Error('libraries オブジェクトが存在しません。');
  }

  const productKeys = Object.keys(db.libraries);
  if (productKeys.length < MIN_PRODUCT_COUNT) {
    throw new Error(`登録製品数が少なすぎます (${productKeys.length} < ${MIN_PRODUCT_COUNT})。同期データの破損が疑われます。`);
  }

  // 改ざん検知用ダイジェスト (schema 2.2 以降)
  if (db.integrity) {
    const digest = crypto.createHash('sha256').update(JSON.stringify(db.libraries)).digest('hex');
    if (db.integrity.digest !== digest) {
      throw new Error('integrity.digest が libraries の内容と一致しません (手編集または破損の可能性)。');
    }
  }

  let advisoryCount = 0;
  const aliasOwners = new Map();
  const warnings = [];
  // schema 2.1 (v1.6.5 以前の手書き生成DB) は互換のため安全性チェックを警告に留める
  const strict = db.schemaVersion !== '2.1';

  for (const [key, lib] of Object.entries(db.libraries)) {
    if (!Array.isArray(lib.aliases)) throw new Error(`ライブラリ "${key}" の aliases が配列ではありません。`);
    if (!Array.isArray(lib.versions)) throw new Error(`ライブラリ "${key}" の versions が配列ではありません。`);
    if (!Array.isArray(lib.eol)) throw new Error(`ライブラリ "${key}" の eol が配列ではありません。`);

    for (const alias of lib.aliases) {
      const a = String(alias).toLowerCase();
      if (aliasOwners.has(a) && aliasOwners.get(a) !== key) {
        throw new Error(`alias "${a}" が複数製品 (${aliasOwners.get(a)}, ${key}) に重複登録されています。`);
      }
      aliasOwners.set(a, key);
    }

    const seenIds = new Set();
    for (const v of lib.versions) {
      advisoryCount++;
      const id = v.cve || v.title || 'Unknown';

      if (!v.cve || !ID_PATTERN.test(v.cve)) throw new Error(`[${key}] アドバイザリIDの形式が不正です: "${v.cve}"`);
      if (seenIds.has(v.cve)) throw new Error(`[${key}] アドバイザリIDが重複しています: "${v.cve}"`);
      seenIds.add(v.cve);

      if (!isValidRange(v.range)) throw new Error(`[${key} / ${id}] range が version-matcher で解釈できない書式です: "${v.range}"`);

      if (typeof v.cvssScore !== 'number' || v.cvssScore < 0 || v.cvssScore > 10) {
        throw new Error(`[${key} / ${id}] 有効な cvssScore (0.0〜10.0) が必須です (実際: ${v.cvssScore})`);
      }
      if (!SEVERITIES.has(v.severity)) throw new Error(`[${key} / ${id}] 不正な重大度です: "${v.severity}"`);
      const expectedSeverity = getExpectedSeverity(v.cvssScore);
      if (v.severity !== expectedSeverity) {
        throw new Error(`[${key} / ${id}] 重大度がスコアと不一致です: スコア=${v.cvssScore} -> 期待="${expectedSeverity}", 実際="${v.severity}"`);
      }

      if (!v.advisoryUrl || typeof v.advisoryUrl !== 'string' || !URL_PREFIXES.some((p) => v.advisoryUrl.startsWith(p)) || /["'<>\s`]/.test(v.advisoryUrl)) {
        throw new Error(`[${key} / ${id}] 有効な一次情報 advisoryUrl (${URL_PREFIXES.join(' / ')}) が必須です: "${v.advisoryUrl}"`);
      }
      if (!v.verifiedAt || !/^\d{4}-\d{2}-\d{2}$/.test(v.verifiedAt)) {
        throw new Error(`[${key} / ${id}] 有効な検証日 verifiedAt (YYYY-MM-DD) が必須です: "${v.verifiedAt}"`);
      }
      if (!v.scoreSource || typeof v.scoreSource !== 'string') {
        throw new Error(`[${key} / ${id}] scoreSource が必須です: "${v.scoreSource}"`);
      }

      // UI 埋め込み安全性 (DB-SEC-1): v1.6.5 では title / referenceUrls が未エスケープで innerHTML に出力される
      for (const field of ['title', 'summary', 'notes', 'fixedVersion', 'scoreSource']) {
        if (v[field] !== undefined && v[field] !== null && (typeof v[field] !== 'string' || UNSAFE_TEXT.test(v[field]))) {
          const msg = `[${key} / ${id}] ${field} に HTML特殊文字・制御文字が含まれています: "${String(v[field]).slice(0, 80)}"`;
          if (strict) throw new Error(msg);
          warnings.push(msg);
        }
      }
      if (v.title && v.title.length > 200) throw new Error(`[${key} / ${id}] title が長すぎます (${v.title.length} > 200)`);
      if (v.summary && v.summary.length > 500) throw new Error(`[${key} / ${id}] summary が長すぎます (${v.summary.length} > 500)`);

      if (db.schemaVersion === '2.2') {
        if (!ORIGINS.has(v.origin)) throw new Error(`[${key} / ${id}] origin が不正です: "${v.origin}"`);
        if (v.fixStatus !== undefined && !FIX_STATUSES.has(v.fixStatus)) throw new Error(`[${key} / ${id}] fixStatus が不正です: "${v.fixStatus}"`);
      }
    }

    for (const e of lib.eol) {
      if (!e || typeof e.cycle !== 'string' || !e.cycle) throw new Error(`[${key}] eol.cycle が不正です: ${JSON.stringify(e)}`);
      if (!EOL_STATUSES.has(e.status)) throw new Error(`[${key}] eol.status が不正です: ${JSON.stringify(e)}`);
      if (db.schemaVersion === '2.2' && e.eolDate !== null && !/^\d{4}-\d{2}-\d{2}$/.test(e.eolDate)) {
        throw new Error(`[${key}] eol.eolDate は YYYY-MM-DD または null である必要があります: ${JSON.stringify(e)}`);
      }
    }
  }

  if (advisoryCount < MIN_ADVISORY_COUNT) {
    throw new Error(`登録アドバイザリ総数が少なすぎます (${advisoryCount} < ${MIN_ADVISORY_COUNT})。データ異常の可能性があります。`);
  }
  return { productCount: productKeys.length, advisoryCount, warnings };
}

function main() {
  console.log('[validate-advisories] オフライン脆弱性DBの整合性を検証中...');
  if (!fs.existsSync(DB_FILE)) throw new Error(`脆弱性DBファイルが存在しません: ${DB_FILE}`);
  const stat = fs.statSync(DB_FILE);
  console.log(`  - ファイルサイズ: ${(stat.size / 1024).toFixed(2)} KB (上限: 2048 KB)`);
  if (stat.size === 0) throw new Error('脆弱性DBファイルが空です。');

  let db;
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
  } catch (err) {
    throw new Error(`JSONパースに失敗しました: ${err.message}`);
  }

  const { productCount, advisoryCount, warnings } = validateDb(db, { sizeBytes: stat.size });
  for (const w of warnings) console.warn(`  [warn] ${w}`);
  console.log('[validate-advisories] 検証成功:');
  console.log(`  - schemaVersion: ${db.schemaVersion}`);
  console.log(`  - dataVersion: ${db.dataVersion}`);
  console.log(`  - 登録製品数: ${productCount} 件`);
  console.log(`  - 登録アドバイザリ数: ${advisoryCount} 件`);
  console.log('  - 一次情報・スコア導出整合性・UI埋め込み安全性: 全件合格');
  console.log(`  - 同期ステータス: ${db.syncStatus ?? 'N/A'}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
    process.exit(0);
  } catch (err) {
    console.error('[validate-advisories] エラー: 検証に失敗しました:');
    console.error(`  ${err.message}`);
    process.exit(1);
  }
}
