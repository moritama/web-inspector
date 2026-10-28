#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * 上流脆弱性データ取得スクリプト (scripts/advisories/fetch-upstream.mjs)
 *
 * 【役割】ネットワークアクセスを行う唯一のステップ。CI (GitHub Actions) の定期ジョブで実行する。
 *   catalog.json に定義された製品について OSV / NVD / endoflife.date / CISA KEV から取得し、
 *   DB 生成に必要な最小フィールドへ圧縮したスナップショットを data/advisories/upstream/ に保存する。
 *   スナップショットは PR にコミットされ、build-db.mjs はこのスナップショットのみから
 *   決定的 (deterministic) に advisory-db.json を生成する (再現性・レビュー容易性の確保)。
 *
 * 【障害時の挙動】
 *   個別ソースの取得失敗時は、既存スナップショットを保持したまま manifest に status: "stale" を記録し継続する。
 *   全ソースが失敗した場合のみ終了コード 1。
 *
 * 使い方:
 *   node scripts/advisories/fetch-upstream.mjs [--only jquery,php] [--skip-nvd] [--nvd-refresh-days 14]
 *   環境変数 NVD_API_KEY (任意。設定するとレート制限が 5→50 req/30s に緩和される)
 */

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createFetchJson } from './lib/http.mjs';
import { compactEolCycles, eolApiUrl } from './lib/eol.mjs';
import { compactKev, KEV_URL } from './lib/kev.mjs';
import { compactNvdCve, fetchNvdByCpe, fetchNvdCve, pickNvdCvss } from './lib/nvd.mjs';
import { compactOsvVuln, fetchOsvPackage, pickIds } from './lib/osv.mjs';
import { PATHS, readJson, safeFileKey, writeJson } from './lib/util.mjs';

function parseArgs(argv) {
  const args = { only: null, skipNvd: false, nvdRefreshDays: 14 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--only') args.only = new Set(argv[++i].split(',').map((s) => s.trim()));
    else if (a === '--skip-nvd') args.skipNvd = true;
    else if (a === '--nvd-refresh-days') args.nvdRefreshDays = Number(argv[++i]);
  }
  return args;
}

export async function fetchUpstream({ catalog, curated, upstreamDir, fetchJson, now = new Date(), args = {}, log = console.log }) {
  const fetchedAt = now.toISOString();
  const manifestPath = path.join(upstreamDir, 'manifest.json');
  const prevManifest = readJson(manifestPath, { sources: {} });
  const manifest = { schemaVersion: 1, fetchedAt, sources: {} };
  const nvdHeaders = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};

  let okCount = 0;
  let failCount = 0;

  const record = async (key, filePath, task) => {
    try {
      const { payload, count } = await task();
      writeJson(filePath, payload);
      manifest.sources[key] = { status: 'ok', count, fetchedAt };
      okCount++;
      log(`  [ok] ${key} (${count})`);
    } catch (err) {
      failCount++;
      const prev = prevManifest.sources?.[key];
      manifest.sources[key] = {
        status: fs.existsSync(filePath) ? 'stale' : 'failed',
        count: prev?.count ?? 0,
        fetchedAt: prev?.fetchedAt ?? null,
        error: String(err.message || err).slice(0, 300),
      };
      log(`  [NG] ${key}: ${err.message}`);
    }
  };

  const cveIdsNeedingScore = new Set();
  for (const p of Object.values(curated.products || {})) {
    for (const a of p.advisories || []) if (a.cve) cveIdsNeedingScore.add(a.cve);
  }

  for (const [key, product] of Object.entries(catalog.products)) {
    if (args.only && !args.only.has(key)) continue;
    log(`[fetch] ${key}`);

    for (const pkg of product.osv || []) {
      const file = path.join(upstreamDir, 'osv', `${safeFileKey(pkg.ecosystem)}__${safeFileKey(pkg.name)}.json`);
      await record(`osv:${pkg.ecosystem}:${pkg.name}`, file, async () => {
        const vulns = (await fetchOsvPackage(pkg, fetchJson)).map((v) => compactOsvVuln(v, pkg));
        vulns.sort((a, b) => a.id.localeCompare(b.id));
        for (const v of vulns) {
          const { cve } = pickIds(v);
          if (cve) cveIdsNeedingScore.add(cve);
        }
        return { payload: { package: pkg, fetchedAt, vulns }, count: vulns.length };
      });
    }

    if (product.nvd && !args.skipNvd) {
      for (const target of product.nvd.targets) {
        const file = path.join(upstreamDir, 'nvd', `${safeFileKey(target.replace(':', '__'))}.json`);
        await record(`nvd:${target}`, file, async () => {
          const cves = (await fetchNvdByCpe(target, fetchJson, nvdHeaders)).map((c) => compactNvdCve(c, product.nvd.targets));
          cves.sort((a, b) => a.id.localeCompare(b.id));
          return { payload: { target, fetchedAt, cves }, count: cves.length };
        });
      }
    }

    if (product.eol?.slug) {
      const file = path.join(upstreamDir, 'eol', `${safeFileKey(product.eol.slug)}.json`);
      await record(`eol:${product.eol.slug}`, file, async () => {
        const cycles = compactEolCycles(await fetchJson(eolApiUrl(product.eol.slug)));
        return { payload: { slug: product.eol.slug, fetchedAt, cycles }, count: cycles.length };
      });
    }
  }

  await record('kev', path.join(upstreamDir, 'kev.json'), async () => {
    const compact = compactKev(await fetchJson(KEV_URL));
    return { payload: compact, count: compact.count };
  });

  // OSV / curated 由来 CVE の NVD スコア補完 (NVD Primary スコア優先ポリシーのため)
  if (!args.skipNvd) {
    const scoresPath = path.join(upstreamDir, 'nvd-scores.json');
    const scores = readJson(scoresPath, {});
    const refreshBefore = new Date(now.getTime() - (args.nvdRefreshDays ?? 14) * 86400_000).toISOString();
    const targets = [...cveIdsNeedingScore].sort().filter((id) => !scores[id] || (scores[id].fetchedAt || '') < refreshBefore);
    log(`[fetch] NVD スコア補完: ${targets.length} 件 (キャッシュ済み ${Object.keys(scores).length} 件)`);
    let errors = 0;
    for (const id of targets) {
      try {
        const cve = await fetchNvdCve(id, fetchJson, nvdHeaders);
        scores[id] = { fetchedAt, cvss: cve ? pickNvdCvss(cve.metrics) : null, vulnStatus: cve?.vulnStatus ?? null };
      } catch (err) {
        errors++;
        log(`  [NG] nvd-score ${id}: ${err.message}`);
      }
    }
    const sorted = Object.fromEntries(Object.entries(scores).sort(([a], [b]) => a.localeCompare(b)));
    writeJson(scoresPath, sorted);
    manifest.sources['nvd-scores'] = { status: errors === 0 ? 'ok' : 'partial', count: Object.keys(sorted).length, fetchedAt, errors };
  }

  // 今回取得対象外 (--only 指定時) のソースは前回の状態を引き継ぐ
  for (const [k, v] of Object.entries(prevManifest.sources || {})) {
    if (!manifest.sources[k]) manifest.sources[k] = v;
  }
  manifest.sources = Object.fromEntries(Object.entries(manifest.sources).sort(([a], [b]) => a.localeCompare(b)));
  writeJson(manifestPath, manifest);

  return { okCount, failCount, manifest };
}

async function main() {
  const args = parseArgs(process.argv);
  const catalog = readJson(PATHS.catalog);
  const curated = readJson(PATHS.curated);
  const fetchJson = createFetchJson({
    minIntervalMs: {
      'services.nvd.nist.gov': process.env.NVD_API_KEY ? 700 : 6500,
      'api.osv.dev': 100,
      'endoflife.date': 200,
    },
    log: console.log,
  });
  const { okCount, failCount } = await fetchUpstream({ catalog, curated, upstreamDir: PATHS.upstreamDir, fetchJson, args });
  console.log(`[fetch] 完了: 成功 ${okCount} / 失敗 ${failCount}`);
  if (okCount === 0) process.exit(1);
  if (failCount > 0) process.exitCode = 2; // 部分失敗 (ワークフロー側で警告扱い)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('[fetch] 致命的エラー:', err);
    process.exit(1);
  });
}
