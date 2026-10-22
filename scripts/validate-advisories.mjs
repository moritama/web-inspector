/**
 * Web Technology & Security Inspector
 * オフライン脆弱性DB 品質・整合性検証スクリプト (scripts/validate-advisories.mjs)
 * 
 * ビルド前およびパッケージング前に実行され、advisory-db.jsonのスキーマ、
 * ファイルサイズ上限、収録件数の異常減少を検証します。(Rev.2.1 IMP-06 / 5.7)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DB_FILE = path.join(ROOT_DIR, 'src', 'detection', 'advisory-db.json');

// 検証しきい値
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB上限
const MIN_PRODUCT_COUNT = 5;                 // 最低5製品
const MIN_ADVISORY_COUNT = 10;               // 最低10件のアドバイザリ
const EXPECTED_SCHEMA_VERSION = '2.1';

function validateAdvisories() {
  console.log('[validate-advisories] オフライン脆弱性DBの整合性を検証中...');

  // 1. ファイル存在チェック
  if (!fs.existsSync(DB_FILE)) {
    throw new Error(`脆弱性DBファイルが存在しません: ${DB_FILE}`);
  }

  // 2. ファイルサイズチェック (上限2MB)
  const stat = fs.statSync(DB_FILE);
  console.log(`  - ファイルサイズ: ${(stat.size / 1024).toFixed(2)} KB (上限: 2048 KB)`);
  if (stat.size > MAX_FILE_SIZE_BYTES) {
    throw new Error(`脆弱性DBのファイルサイズが上限(2MB)を超過しています: ${stat.size} bytes`);
  }
  if (stat.size === 0) {
    throw new Error('脆弱性DBファイルが空です。');
  }

  // 3. JSONパースチェック
  let db;
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    db = JSON.parse(raw);
  } catch (err) {
    throw new Error(`JSONパースに失敗しました: ${err.message}`);
  }

  // 4. スキーマ検証 (Rev.2.1 メタデータ)
  if (db.schemaVersion !== EXPECTED_SCHEMA_VERSION) {
    throw new Error(`schemaVersion が不正です: 期待値="${EXPECTED_SCHEMA_VERSION}", 実際="${db.schemaVersion}"`);
  }
  if (!db.dataVersion || typeof db.dataVersion !== 'string') {
    throw new Error('dataVersion が存在しないか無効です。');
  }
  if (!db.generatedAt || isNaN(new Date(db.generatedAt).getTime())) {
    throw new Error('generatedAt が有効なISO日時形式ではありません。');
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

  // 5. 収録件数の異常減少検知
  const productKeys = Object.keys(db.libraries);
  if (productKeys.length < MIN_PRODUCT_COUNT) {
    throw new Error(`登録製品数が少なすぎます (${productKeys.length} < ${MIN_PRODUCT_COUNT})。同期データの破損が疑われます。`);
  }

  let calculatedAdvisoryCount = 0;
  for (const [key, lib] of Object.entries(db.libraries)) {
    if (!Array.isArray(lib.aliases)) {
      throw new Error(`ライブラリ "${key}" の aliases が配列ではありません。`);
    }
    if (!Array.isArray(lib.versions)) {
      throw new Error(`ライブラリ "${key}" の versions が配列ではありません。`);
    }
    if (!Array.isArray(lib.eol)) {
      throw new Error(`ライブラリ "${key}" の eol が配列ではありません。`);
    }
    calculatedAdvisoryCount += lib.versions.length;
  }

  if (calculatedAdvisoryCount < MIN_ADVISORY_COUNT) {
    throw new Error(`登録アドバイザリ総数が少なすぎます (${calculatedAdvisoryCount} < ${MIN_ADVISORY_COUNT})。データ異常の可能性があります。`);
  }

  console.log(`[validate-advisories] 検証成功:`);
  console.log(`  - schemaVersion: ${db.schemaVersion}`);
  console.log(`  - dataVersion: ${db.dataVersion}`);
  console.log(`  - 登録製品数: ${productKeys.length} 件`);
  console.log(`  - 登録アドバイザリ数: ${calculatedAdvisoryCount} 件`);
  console.log(`  - 同期ステータス: ${db.syncStatus ?? 'N/A'}`);
}

try {
  validateAdvisories();
  process.exit(0);
} catch (err) {
  console.error('[validate-advisories] エラー: 検証に失敗しました:');
  console.error(`  ${err.message}`);
  process.exit(1);
}
