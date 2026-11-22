#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * 同梱データの出典とライセンスの検証 (scripts/ci/check-data-sources.mjs)
 *
 * - advisory-db.json の sources と distro._source の全要素に license または licenseNote があるか検証する (H9・§5.2)
 * - THIRD_PARTY_NOTICES.md が存在する場合、DB の出典がすべて記載されているか検証する (§5.3)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename), '..', '..');

/**
 * @param {{ db: any, noticesText: string | null | undefined }} input
 * @returns {{ ok: boolean, issues: string[], warnings: string[] }}
 */
export function checkDataSources({ db, noticesText }) {
  const issues = [];
  const warnings = [];

  if (!db || !Array.isArray(db.sources) || db.sources.length === 0) {
    issues.push('db.sources が空でない配列ではありません');
    return { ok: false, issues, warnings };
  }

  for (const s of db.sources) {
    if (typeof s !== 'object' || s === null || Array.isArray(s)) {
      issues.push(`sources にオブジェクトでない要素が含まれています: ${JSON.stringify(s)}`);
      continue;
    }
    const hasLicense = typeof s.license === 'string' && s.license.trim().length > 0;
    const hasLicenseNote = typeof s.licenseNote === 'string' && s.licenseNote.trim().length > 0;
    if (!hasLicense && !hasLicenseNote) {
      issues.push(`出典 "${s.name}" に license も licenseNote もありません`);
    }
  }

  if (db.distro && Array.isArray(db.distro._source)) {
    for (const s of db.distro._source) {
      if (typeof s !== 'object' || s === null || Array.isArray(s)) {
        issues.push(`distro._source にオブジェクトでない要素が含まれています: ${JSON.stringify(s)}`);
        continue;
      }
      const hasLicense = typeof s.license === 'string' && s.license.trim().length > 0;
      const hasLicenseNote = typeof s.licenseNote === 'string' && s.licenseNote.trim().length > 0;
      if (!hasLicense && !hasLicenseNote) {
        issues.push(`distro._source の出典 "${s.name}" に license も licenseNote もありません`);
      }
    }
  }

  if (noticesText === null || noticesText === undefined) {
    warnings.push('THIRD_PARTY_NOTICES.md が無いため、出典の照合をスキップしました');
  } else if (typeof noticesText === 'string') {
    for (const s of db.sources) {
      if (!s || typeof s !== 'object') continue;
      const nameFound = typeof s.name === 'string' && noticesText.includes(s.name);
      const urlFound = typeof s.url === 'string' && noticesText.includes(s.url);
      if (!nameFound && !urlFound) {
        issues.push(`THIRD_PARTY_NOTICES.md に出典 "${s.name}" (${s.url}) が記載されていません`);
      }
    }
  }

  return { ok: issues.length === 0, issues, warnings };
}

function parseArgs(argv) {
  let dbPath = path.join(REPO_ROOT, 'src', 'detection', 'advisory-db.json');
  let noticesPath = path.join(REPO_ROOT, 'THIRD_PARTY_NOTICES.md');

  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--db' && argv[i + 1]) {
      dbPath = path.resolve(argv[++i]);
    } else if (argv[i] === '--notices' && argv[i + 1]) {
      noticesPath = path.resolve(argv[++i]);
    }
  }
  return { dbPath, noticesPath };
}

function main() {
  const { dbPath, noticesPath } = parseArgs(process.argv);
  if (!fs.existsSync(dbPath)) {
    console.error(`[check-data-sources] エラー: DB ファイルが存在しません: ${dbPath}`);
    process.exit(1);
  }

  const db = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
  let noticesText = null;
  if (fs.existsSync(noticesPath)) {
    noticesText = fs.readFileSync(noticesPath, 'utf-8');
  }

  const result = checkDataSources({ db, noticesText });

  for (const w of result.warnings) {
    console.warn(`[check-data-sources] [warn] ${w}`);
  }
  if (!result.ok) {
    console.error('[check-data-sources] エラー: 検証に失敗しました:');
    for (const issue of result.issues) {
      console.error(`  - ${issue}`);
    }
    process.exit(1);
  }
  console.log('[check-data-sources] 出典とライセンスの検証に合格しました');
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(__filename)) {
  main();
}
