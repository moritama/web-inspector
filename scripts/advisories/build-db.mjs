#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * オフライン脆弱性DB 生成スクリプト (scripts/advisories/build-db.mjs)
 *
 * 【役割】ネットワークにアクセスせず、以下の入力のみから決定的に src/detection/advisory-db.json を生成する。
 *   - data/advisories/catalog.json   : 対象製品・取得元の定義 (人間管理)
 *   - data/advisories/curated.json   : レビュー済みアドバイザリ・除外リスト・静的EOL (人間管理, 自動取得より優先)
 *   - data/advisories/upstream/**    : fetch-upstream.mjs が保存した上流スナップショット
 *
 * 出力スキーマ 2.2 は 2.1 (v1.6.5 の advisory.ts が読む形式) の上位互換:
 *   libraries[key].versions[] に origin / fixStatus / kev / ghsa / published 等の任意フィールドを追加。
 *
 * 使い方:
 *   node scripts/advisories/build-db.mjs            # 生成して書き出し
 *   node scripts/advisories/build-db.mjs --check    # 生成結果がコミット済みファイルと一致するか検査 (CI用)
 *   node scripts/advisories/build-db.mjs --as-of 2026-10-26  # upstream が無い場合の基準日
 */

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { deriveSeverity } from './lib/cvss.mjs';
import { normalizeEol } from './lib/eol.mjs';
import { kevMap } from './lib/kev.mjs';
import { nvdToAdvisories } from './lib/nvd.mjs';
import { osvToAdvisories } from './lib/osv.mjs';
import { isValidRangeSpec } from './lib/range.mjs';
import { cleanText, safeUrl } from './lib/sanitize.mjs';
import { PATHS, readJson, sha256, stableStringify, toIsoDate, writeJson } from './lib/util.mjs';

export const OUTPUT_SCHEMA_VERSION = '2.2';
/** この DB を正しく解釈できる拡張機能の最低バージョン (fixStatus 等を使う NVD 自動取込を有効化する際に引き上げる) */
export const MIN_EXTENSION_VERSION = '1.6.5';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function loadOptional(file) {
  return fs.existsSync(file) ? readJson(file) : null;
}

/** curated エントリを出力形式へ正規化 (テキストは curated であってもサニタイズする) */
function normalizeCurated(entry, ctx) {
  const id = entry.cve;
  const kevDate = ctx.kev.get(id);
  let notes = entry.notes ? cleanText(entry.notes, 300) : undefined;
  if (kevDate && !(notes || '').includes('CISA KEV')) {
    notes = cleanText(`${notes ? `${notes} / ` : ''}CISA KEV 登録 (${kevDate})`, 300);
  }
  return {
    range: entry.range,
    cve: id,
    cvssScore: entry.cvssScore,
    severity: deriveSeverity(entry.cvssScore),
    title: cleanText(entry.title, 160),
    ...(entry.summary ? { summary: cleanText(entry.summary, 400) } : {}),
    fixedVersion: entry.fixedVersion ?? null,
    fixStatus: entry.fixStatus || (entry.fixedVersion ? 'fixed' : 'none'),
    advisoryUrl: safeUrl(entry.advisoryUrl) || `https://nvd.nist.gov/vuln/detail/${id}`,
    verifiedAt: entry.verifiedAt,
    scoreSource: entry.scoreSource,
    ...(notes ? { notes } : {}),
    ...(kevDate ? { kev: true, kevDateAdded: kevDate } : {}),
    origin: 'curated',
  };
}

function normalizeAuto(adv, ctx) {
  const kevDate = adv.cve ? ctx.kev.get(adv.cve) : undefined;
  let notes = adv.notes;
  if (kevDate) notes = cleanText(`${notes ? `${notes} / ` : ''}CISA KEV 登録 (${kevDate})`, 300);
  return {
    range: adv.range,
    cve: adv.id,
    ...(adv.ghsa && adv.ghsa !== adv.id ? { ghsa: adv.ghsa } : {}),
    cvssScore: adv.cvssScore,
    severity: deriveSeverity(adv.cvssScore),
    title: adv.title,
    ...(adv.summary ? { summary: adv.summary } : {}),
    fixedVersion: adv.fixedVersion,
    fixStatus: adv.fixStatus,
    advisoryUrl: adv.advisoryUrl,
    verifiedAt: ctx.asOf,
    scoreSource: adv.scoreSource,
    ...(adv.cvssVector ? { cvssVector: adv.cvssVector } : {}),
    ...(adv.published ? { published: adv.published } : {}),
    ...(notes ? { notes } : {}),
    ...(kevDate ? { kev: true, kevDateAdded: kevDate } : {}),
    ...(adv.rangeApproximated ? { rangeApproximated: true } : {}),
    origin: 'auto',
    sources: adv.sources,
  };
}

/**
 * DB を生成する (純粋関数: ファイル読込は呼び出し側で行う)
 */
export function buildDatabase({ catalog, curated, upstream, previousDb, asOf, generatedAt }) {
  const kev = kevMap(upstream.kev);
  const nvdScores = new Map(
    Object.entries(upstream.nvdScores || {})
      .filter(([, v]) => v && v.cvss)
      .map(([k, v]) => [k, v.cvss])
  );
  const excludes = new Map((curated.excludes || []).map((e) => [`${e.product}:${e.id}`, e.reason]));
  const ctx = { kev, asOf };

  const report = { asOf, products: {}, drift: [], excluded: [], skippedSummary: {}, staleSources: [] };
  for (const [k, v] of Object.entries(upstream.manifest?.sources || {})) {
    if (v.status !== 'ok') report.staleSources.push({ source: k, status: v.status, error: v.error });
  }

  const libraries = {};
  let total = 0;

  for (const [key, product] of Object.entries(catalog.products)) {
    const cur = curated.products?.[key] || { advisories: [] };
    const autoCandidates = [];
    const skipped = [];

    // --- OSV ---
    const osvCompacts = [];
    for (const pkg of product.osv || []) {
      const snap = upstream.osv?.[`${pkg.ecosystem}:${pkg.name}`];
      if (snap) osvCompacts.push(...snap.vulns);
    }
    if (osvCompacts.length > 0) {
      const r = osvToAdvisories(osvCompacts, { nvdScores });
      autoCandidates.push(...r.advisories);
      skipped.push(...r.skipped);
    }

    // --- NVD ---
    const nvdIndex = new Map();
    if (product.nvd) {
      const nvdCompacts = [];
      for (const target of product.nvd.targets) {
        const snap = upstream.nvd?.[target];
        if (snap) nvdCompacts.push(...snap.cves);
      }
      const filters = { ...(catalog.defaults?.nvd || {}), ...(product.nvd.filters || {}), kev };
      const r = nvdToAdvisories(nvdCompacts, filters);
      for (const a of r.advisories) nvdIndex.set(a.id, a);
      if (product.nvd.autoIngest) {
        autoCandidates.push(...r.advisories);
        skipped.push(...r.skipped);
      }
    }

    // --- マージ (curated 優先) ---
    const merged = new Map();
    for (const e of cur.advisories || []) {
      merged.set(e.cve, normalizeCurated(e, ctx));
    }
    for (const a of autoCandidates) {
      const exKey = `${key}:${a.id}`;
      if (excludes.has(exKey)) {
        report.excluded.push({ product: key, id: a.id, reason: excludes.get(exKey) });
        continue;
      }
      const existing = merged.get(a.id) || (a.ghsa ? merged.get(a.ghsa) : null);
      if (existing) {
        if (existing.origin === 'curated' && (existing.range !== a.range || existing.cvssScore !== a.cvssScore)) {
          report.drift.push({ product: key, id: a.id, curated: { range: existing.range, cvssScore: existing.cvssScore }, upstream: { range: a.range, cvssScore: a.cvssScore, source: a.sources?.[0] } });
        }
        continue;
      }
      merged.set(a.id, normalizeAuto(a, ctx));
    }
    // curated と NVD スナップショットの乖離検出 (NVD 自動取込が無効な製品でも検証のみ行う)
    for (const e of cur.advisories || []) {
      const n = nvdIndex.get(e.cve);
      if (n && (n.range !== e.range || n.cvssScore !== e.cvssScore) && !report.drift.some((d) => d.id === e.cve)) {
        report.drift.push({ product: key, id: e.cve, curated: { range: e.range, cvssScore: e.cvssScore }, upstream: { range: n.range, cvssScore: n.cvssScore, source: 'nvd' } });
      }
    }

    const versions = [...merged.values()].filter((v) => isValidRangeSpec(v.range));
    const invalid = [...merged.values()].filter((v) => !isValidRangeSpec(v.range));
    for (const v of invalid) skipped.push({ id: v.cve, reason: `invalid-range:${v.range}` });
    versions.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.cvssScore - a.cvssScore || b.cve.localeCompare(a.cve));

    // --- EOL ---
    let eol = [];
    let eolSource = 'none';
    const eolSnap = product.eol?.slug ? upstream.eol?.[product.eol.slug] : null;
    if (eolSnap && eolSnap.cycles.length > 0) {
      eol = normalizeEol(eolSnap.cycles, { asOf, supportedLatestCycles: product.eol.supportedLatestCycles });
      eolSource = 'endoflife.date';
    } else if (cur.staticEol) {
      eol = cur.staticEol.map((e) => ({ cycle: e.cycle, eolDate: e.eolDate ?? null, status: e.status }));
      eolSource = 'curated';
    } else if (previousDb?.libraries?.[key]?.eol) {
      eol = previousDb.libraries[key].eol.map((e) => ({ ...e, eolDate: toIsoDate(e.eolDate) }));
      eolSource = 'previous-db';
    }

    libraries[key] = { aliases: product.aliases, versions, eol };
    total += versions.length;

    const reasons = {};
    for (const s of skipped) {
      const r = s.reason.split(':')[0];
      reasons[r] = (reasons[r] || 0) + 1;
    }
    report.products[key] = {
      curated: versions.filter((v) => v.origin === 'curated').length,
      auto: versions.filter((v) => v.origin === 'auto').length,
      nvdCandidates: nvdIndex.size,
      nvdAutoIngest: Boolean(product.nvd?.autoIngest),
      eolSource,
      skipped: reasons,
    };
    for (const [r, n] of Object.entries(reasons)) report.skippedSummary[r] = (report.skippedSummary[r] || 0) + n;
  }

  const librariesJson = JSON.stringify(libraries);
  const db = {
    schemaVersion: OUTPUT_SCHEMA_VERSION,
    version: asOf.slice(0, 7).replace('-', '.'),
    dataVersion: asOf.replace(/-/g, ''),
    generatedAt,
    minExtensionVersion: MIN_EXTENSION_VERSION,
    sources: [
      'NIST NVD 2.0 API (Primary: nvd@nist.gov)',
      'OSV.dev (GitHub Advisory Database / npm / Packagist)',
      'endoflife.date API',
      'CISA KEV Catalog',
      'Curated (data/advisories/curated.json)',
    ],
    coverage: { totalAdvisories: total, technologies: Object.keys(libraries) },
    syncStatus: report.staleSources.length === 0 ? 'success' : 'partial',
    integrity: { algorithm: 'sha256', target: 'libraries', digest: sha256(librariesJson) },
    libraries,
  };
  return { db, report };
}

/** upstream ディレクトリを読み込む */
export function loadUpstream(dir) {
  const upstream = { manifest: loadOptional(path.join(dir, 'manifest.json')), osv: {}, nvd: {}, eol: {}, kev: null, nvdScores: {} };
  const read = (sub, keyOf) => {
    const d = path.join(dir, sub);
    if (!fs.existsSync(d)) return;
    for (const f of fs.readdirSync(d).filter((x) => x.endsWith('.json')).sort()) {
      const json = readJson(path.join(d, f));
      upstream[sub][keyOf(json)] = json;
    }
  };
  read('osv', (j) => `${j.package.ecosystem}:${j.package.name}`);
  read('nvd', (j) => j.target);
  read('eol', (j) => j.slug);
  upstream.kev = loadOptional(path.join(dir, 'kev.json'));
  upstream.nvdScores = loadOptional(path.join(dir, 'nvd-scores.json')) || {};
  return upstream;
}

function parseArgs(argv) {
  const args = { check: false, asOf: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--check') args.check = true;
    else if (argv[i] === '--as-of') args.asOf = argv[++i];
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);
  const catalog = readJson(PATHS.catalog);
  const curated = readJson(PATHS.curated);
  const upstream = loadUpstream(PATHS.upstreamDir);
  const previousDb = loadOptional(PATHS.outputDb);

  const fetchedAt = upstream.manifest?.fetchedAt;
  const asOf = args.asOf || toIsoDate(fetchedAt);
  if (!asOf) {
    console.error('[build-db] upstream スナップショット (data/advisories/upstream/manifest.json) がありません。先に fetch-upstream.mjs を実行するか --as-of を指定してください。');
    process.exit(1);
  }
  const generatedAt = fetchedAt || `${asOf}T00:00:00.000Z`;

  const { db, report } = buildDatabase({ catalog, curated, upstream, previousDb, asOf, generatedAt });
  const output = stableStringify(db);

  if (args.check) {
    const current = fs.existsSync(PATHS.outputDb) ? fs.readFileSync(PATHS.outputDb, 'utf-8') : '';
    if (current !== output) {
      console.error('[build-db] --check 失敗: コミット済みの advisory-db.json が upstream スナップショットからの生成結果と一致しません。');
      console.error('  手編集された可能性があります。`npm run advisories:build` を実行して再生成してください。');
      process.exit(1);
    }
    console.log('[build-db] --check OK: advisory-db.json はスナップショットと一致しています。');
    return;
  }

  fs.writeFileSync(PATHS.outputDb, output, 'utf-8');
  writeJson(PATHS.buildReport, report);
  console.log(`[build-db] 生成完了: ${path.relative(process.cwd(), PATHS.outputDb)} (schema ${db.schemaVersion}, dataVersion ${db.dataVersion}, ${db.coverage.totalAdvisories} 件)`);
  for (const [k, v] of Object.entries(report.products)) {
    console.log(`  - ${k}: curated ${v.curated} / auto ${v.auto} / EOL ${v.eolSource}${v.nvdCandidates ? ` / NVD候補 ${v.nvdCandidates}${v.nvdAutoIngest ? '' : ' (未取込)'}` : ''}`);
  }
  if (report.drift.length) console.log(`  ! curated と上流の乖離: ${report.drift.length} 件 (build-report.json を確認)`);
  if (report.staleSources.length) console.log(`  ! 取得失敗/古いソース: ${report.staleSources.map((s) => s.source).join(', ')}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('[build-db] エラー:', err);
    process.exit(1);
  });
}

