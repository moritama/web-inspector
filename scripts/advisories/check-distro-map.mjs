#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * 対応表 (distro-map.json) の週次突き合わせ (scripts/advisories/check-distro-map.mjs)
 *
 * Ubuntu (Launchpad API) と Debian (sources.debian.org API) の各リリースで
 * 現在公開されているパッケージの版を取得し、対応表に無い上流版を「ずれ」として検出する。
 * 対応表のファイルは一切書き換えない。結果は build-report.json の distroMapDrift に記録する。
 */

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { PATHS, stableStringify } from './lib/util.mjs';
import { createFetchJson } from './lib/http.mjs';

const LAUNCHPAD_BASE = 'https://api.launchpad.net/1.0/ubuntu';
const UBUNTU_POCKETS = new Set(['Release', 'Updates', 'Security']);
const UBUNTU_STATUS = 'Published';

const PACKAGE_VERSION_RE = /^[0-9A-Za-z.+~:-]+$/;
const UPSTREAM_VERSION_RE = /^\d+(?:\.\d+)+[a-z]?/;

/**
 * パッケージバージョン文字列から上流バージョンを抽出する
 * dpkg の形式 [epoch:]upstream[-revision] から epoch と revision を外し、
 * 先頭の /^\d+(?:\.\d+)+[a-z]?/ を取得する
 *
 * @param {string} version - パッケージバージョン文字列
 * @returns {string | null} 上流バージョン文字列、抽出不可時は null
 */
export function extractUpstreamVersion(version) {
  if (typeof version !== 'string') return null;
  const clean = version.trim();
  if (clean.length === 0 || clean.length > 100) return null;
  if (!PACKAGE_VERSION_RE.test(clean)) return null;

  // epoch を除去 (最初の : まで)
  let v = clean.replace(/^[^:]*:/, '');
  // revision を除去 (最後の - から後ろ)
  const lastDash = v.lastIndexOf('-');
  if (lastDash >= 0) {
    v = v.slice(0, lastDash);
  }

  const m = v.match(UPSTREAM_VERSION_RE);
  return m ? m[0] : null;
}

/**
 * Launchpad API から Ubuntu リリースの公開パッケージ版一覧を取得・検証する
 *
 * @param {object} entry - 対応表エントリ
 * @param {Function} fetchJson - HTTP 取得関数
 * @returns {Promise<{ status: string, publishedVersions: string[], unlistedUpstreamVersions: string[], sourceUrl: string, error?: string }>}
 */
async function checkUbuntuEntry(entry, fetchJson) {
  if (!entry.codename) {
    return {
      status: 'unchecked',
      error: 'codename が設定されていません',
      publishedVersions: [],
      unlistedUpstreamVersions: [],
      sourceUrl: '',
    };
  }

  const url = new URL(`${LAUNCHPAD_BASE}/+archive/primary`);
  url.searchParams.set('ws.op', 'getPublishedSources');
  url.searchParams.set('source_name', entry.sourcePackage);
  url.searchParams.set('exact_match', 'true');
  url.searchParams.set('distro_series', `${LAUNCHPAD_BASE}/${entry.codename}`);
  url.searchParams.set('status', UBUNTU_STATUS);

  const sourceUrl = url.href;
  let currentUrl = sourceUrl;
  const rawVersions = [];
  let pageCount = 0;

  while (currentUrl && pageCount < 20) {
    pageCount++;
    const res = await fetchJson(currentUrl);
    if (!res || typeof res !== 'object' || !Array.isArray(res.entries)) {
      throw new Error('Launchpad の応答形式が不正です (entries が配列ではありません)');
    }

    for (const e of res.entries) {
      if (
        e &&
        e.status === UBUNTU_STATUS &&
        UBUNTU_POCKETS.has(e.pocket) &&
        e.source_package_name === entry.sourcePackage &&
        typeof e.source_package_version === 'string'
      ) {
        rawVersions.push(e.source_package_version);
      }
    }

    if (res.next_collection_link && typeof res.next_collection_link === 'string') {
      try {
        const next = new URL(res.next_collection_link);
        if (next.hostname === 'api.launchpad.net') {
          currentUrl = res.next_collection_link;
        } else {
          break;
        }
      } catch {
        break;
      }
    } else {
      break;
    }
  }

  // 有効な版のみ抽出 (不正文字・100文字超の除外)
  const validVersions = rawVersions.filter(
    (v) => typeof v === 'string' && v.length <= 100 && PACKAGE_VERSION_RE.test(v)
  );

  if (validVersions.length === 0) {
    return {
      status: 'unchecked',
      error: '公開中の版が 1 件もありません',
      publishedVersions: [],
      unlistedUpstreamVersions: [],
      sourceUrl,
    };
  }

  const publishedVersions = Array.from(new Set(validVersions));
  const mapUpstreamSet = new Set(Array.isArray(entry.upstreamVersions) ? entry.upstreamVersions : []);
  const unlistedSet = new Set();

  for (const pv of publishedVersions) {
    const upstream = extractUpstreamVersion(pv);
    if (upstream && !mapUpstreamSet.has(upstream)) {
      unlistedSet.add(upstream);
    }
  }

  const unlistedUpstreamVersions = Array.from(unlistedSet);
  const status = unlistedUpstreamVersions.length > 0 ? 'drift' : 'none';

  return {
    status,
    publishedVersions,
    unlistedUpstreamVersions,
    sourceUrl,
  };
}

/**
 * sources.debian.org API の応答から Debian リリースのパッケージ版を検証する
 *
 * @param {object} entry - 対応表エントリ
 * @param {object} res - sources.debian.org API 応答
 * @param {string} sourceUrl - 問い合わせ URL
 * @returns {{ status: string, publishedVersions: string[], unlistedUpstreamVersions: string[], sourceUrl: string, error?: string }}
 */
function processDebianData(entry, res, sourceUrl) {
  if (!entry.codename) {
    return {
      status: 'unchecked',
      error: 'codename が設定されていません',
      publishedVersions: [],
      unlistedUpstreamVersions: [],
      sourceUrl,
    };
  }

  if (!res || typeof res !== 'object') {
    throw new Error('sources.debian.org の応答形式が不正です');
  }
  if (res.error) {
    throw new Error(`sources.debian.org API エラー: ${res.error}`);
  }
  if (!Array.isArray(res.versions)) {
    throw new Error('sources.debian.org の応答形式が不正です (versions が配列ではありません)');
  }

  const targetSuites = new Set([
    entry.codename,
    `${entry.codename}-updates`,
    `${entry.codename}-security`,
  ]);

  const rawVersions = [];
  for (const v of res.versions) {
    if (v && Array.isArray(v.suites) && v.suites.some((s) => targetSuites.has(s))) {
      if (typeof v.version === 'string') {
        rawVersions.push(v.version);
      }
    }
  }

  // 有効な版のみ抽出 (不正文字・100文字超の除外)
  const validVersions = rawVersions.filter(
    (v) => typeof v === 'string' && v.length <= 100 && PACKAGE_VERSION_RE.test(v)
  );

  if (validVersions.length === 0) {
    return {
      status: 'unchecked',
      error: '該当リリースの版が 1 件もありません',
      publishedVersions: [],
      unlistedUpstreamVersions: [],
      sourceUrl,
    };
  }

  const publishedVersions = Array.from(new Set(validVersions));
  const mapUpstreamSet = new Set(Array.isArray(entry.upstreamVersions) ? entry.upstreamVersions : []);
  const unlistedSet = new Set();

  for (const pv of publishedVersions) {
    const upstream = extractUpstreamVersion(pv);
    if (upstream && !mapUpstreamSet.has(upstream)) {
      unlistedSet.add(upstream);
    }
  }

  const unlistedUpstreamVersions = Array.from(unlistedSet);
  const status = unlistedUpstreamVersions.length > 0 ? 'drift' : 'none';

  return {
    status,
    publishedVersions,
    unlistedUpstreamVersions,
    sourceUrl,
  };
}

/**
 * 対応表と API の突き合わせを行う
 *
 * @param {object} params
 * @param {{ entries: object[] }} params.distroMap - 対応表オブジェクト
 * @param {Function} params.fetchJson - HTTP 取得関数
 * @param {Date} [params.now=new Date()] - 実行日時
 * @returns {Promise<object>} DistroMapDrift 結果オブジェクト（counts.outOfScope と outOfScopeByFamily は、照合手段が無い family の件数）
 */
export async function checkDistroMap({ distroMap, fetchJson, now = new Date() }) {
  const entries = distroMap && Array.isArray(distroMap.entries) ? distroMap.entries : [];
  const targetEntries = entries.filter((e) => e && (e.family === 'ubuntu' || e.family === 'debian'));
  // Launchpad と sources.debian.org では引けない family（RHEL 系）は照合できない。
  // 黙って落とすと「全件確認済み」に見えるので、対象外として件数と内訳を残す
  const outOfScopeEntries = entries.filter((e) => e && e.family !== 'ubuntu' && e.family !== 'debian');
  const outOfScopeByFamily = {};
  for (const e of outOfScopeEntries) {
    const family = String(e.family || 'その他');
    outOfScopeByFamily[family] = (outOfScopeByFamily[family] || 0) + 1;
  }

  const items = [];
  const debianCache = new Map();

  for (const entry of targetEntries) {
    const itemBase = {
      family: entry.family,
      release: entry.release,
      codename: entry.codename,
      product: entry.product,
      sourcePackage: entry.sourcePackage,
      mapUpstreamVersions: Array.isArray(entry.upstreamVersions) ? [...entry.upstreamVersions] : [],
    };

    try {
      let res;
      if (entry.family === 'ubuntu') {
        res = await checkUbuntuEntry(entry, fetchJson);
      } else if (entry.family === 'debian') {
        const sourceUrl = `https://sources.debian.org/api/src/${encodeURIComponent(entry.sourcePackage)}/`;
        let debDataPromise = debianCache.get(sourceUrl);
        if (!debDataPromise) {
          debDataPromise = fetchJson(sourceUrl).catch((err) => {
            debianCache.delete(sourceUrl);
            throw err;
          });
          debianCache.set(sourceUrl, debDataPromise);
        }
        const debData = await debDataPromise;
        res = processDebianData(entry, debData, sourceUrl);
      }

      if (res.status === 'unchecked') {
        items.push({
          ...itemBase,
          status: 'unchecked',
          publishedVersions: [],
          unlistedUpstreamVersions: [],
          sourceUrl: res.sourceUrl || '',
          error: String(res.error || '未確認').slice(0, 200),
        });
      } else if (res.status === 'drift') {
        items.push({
          ...itemBase,
          status: 'drift',
          publishedVersions: res.publishedVersions,
          unlistedUpstreamVersions: res.unlistedUpstreamVersions,
          sourceUrl: res.sourceUrl,
        });
      } else {
        items.push({
          ...itemBase,
          status: 'none',
          publishedVersions: res.publishedVersions,
          unlistedUpstreamVersions: [],
          sourceUrl: res.sourceUrl,
        });
      }
    } catch (err) {
      const sourceUrl =
        entry.family === 'ubuntu'
          ? `${LAUNCHPAD_BASE}/+archive/primary?ws.op=getPublishedSources&source_name=${encodeURIComponent(entry.sourcePackage)}&exact_match=true&distro_series=${LAUNCHPAD_BASE}/${encodeURIComponent(entry.codename || '')}&status=${UBUNTU_STATUS}`
          : `https://sources.debian.org/api/src/${encodeURIComponent(entry.sourcePackage)}/`;
      items.push({
        ...itemBase,
        status: 'unchecked',
        publishedVersions: [],
        unlistedUpstreamVersions: [],
        sourceUrl,
        error: String(err?.message || err || '取得エラー').slice(0, 200),
      });
    }
  }

  const counts = { drift: 0, none: 0, unchecked: 0, outOfScope: outOfScopeEntries.length };
  for (const item of items) {
    if (item.status === 'drift') counts.drift++;
    else if (item.status === 'none') counts.none++;
    else counts.unchecked++;
  }

  let overallStatus = 'unchecked';
  if (items.length > 0) {
    if (counts.drift > 0) {
      overallStatus = 'drift';
    } else if (counts.unchecked > 0) {
      overallStatus = 'unchecked';
    } else {
      overallStatus = 'none';
    }
  }

  return {
    checkedAt: (now instanceof Date ? now : new Date()).toISOString(),
    status: overallStatus,
    counts,
    outOfScopeByFamily,
    items,
  };
}

/**
 * build-report.json の distroMapDrift を安全に更新する
 *
 * @param {string | undefined} reportPath - build-report.json パス
 * @param {object} driftResult - distroMapDrift オブジェクト
 */
function writeDistroMapDriftToReport(reportPath, driftResult) {
  if (!reportPath) return;
  let report = {};
  if (fs.existsSync(reportPath)) {
    try {
      report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
      if (!report || typeof report !== 'object' || Array.isArray(report)) {
        report = {};
      }
    } catch {
      report = {};
    }
  }
  report.distroMapDrift = driftResult;
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, stableStringify(report), 'utf-8');
}

/**
 * 対応表ファイルを読み込み、APIと突き合わせ、build-report.json に記録する
 * 対応表ファイルには書き込まない。例外を投げず常に結果を返す。
 *
 * @param {object} params
 * @param {string} [params.mapPath] - 対応表ファイルパス
 * @param {string} [params.reportPath] - build-report.json パス
 * @param {Function} params.fetchJson - HTTP 取得関数
 * @param {Date} [params.now=new Date()] - 実行日時
 * @param {Function} [params.log] - ログ出力関数
 * @returns {Promise<object>} DistroMapDrift 結果オブジェクト
 */
export async function runDistroMapCheck({
  mapPath = PATHS.distroMap,
  reportPath = PATHS.buildReport,
  fetchJson,
  now = new Date(),
  log = () => {},
} = {}) {
  let distroMap;
  try {
    if (!fs.existsSync(mapPath)) {
      throw new Error(`対応表ファイルが存在しません: ${mapPath}`);
    }
    distroMap = JSON.parse(fs.readFileSync(mapPath, 'utf-8'));
  } catch (err) {
    const fallbackResult = {
      checkedAt: (now instanceof Date ? now : new Date()).toISOString(),
      status: 'unchecked',
      counts: { drift: 0, none: 0, unchecked: 0 },
      items: [],
      error: `対応表の読み込みに失敗しました: ${err?.message || err}`,
    };
    try {
      writeDistroMapDriftToReport(reportPath, fallbackResult);
    } catch {
      // レポート書き込み例外も無視
    }
    return fallbackResult;
  }

  let result;
  try {
    result = await checkDistroMap({ distroMap, fetchJson, now });
  } catch (err) {
    result = {
      checkedAt: (now instanceof Date ? now : new Date()).toISOString(),
      status: 'unchecked',
      counts: { drift: 0, none: 0, unchecked: 0 },
      items: [],
      error: `突き合わせ処理で予期しない例外が発生しました: ${err?.message || err}`,
    };
  }

  try {
    writeDistroMapDriftToReport(reportPath, result);
  } catch (err) {
    log(`[runDistroMapCheck] build-report.json の更新に失敗しました: ${err?.message || err}`);
  }

  return result;
}

/**
 * CLI メイン実行処理
 */
async function main() {
  try {
    const fetchJson = createFetchJson({ retries: 2, log: console.log });
    const result = await runDistroMapCheck({
      mapPath: PATHS.distroMap,
      reportPath: PATHS.buildReport,
      fetchJson,
      now: new Date(),
      log: console.log,
    });
    console.log(
      `[check-distro-map] status=${result.status} drift=${result.counts.drift} none=${result.counts.none} unchecked=${result.counts.unchecked} outOfScope=${result.counts.outOfScope}`
    );
    if (result.status === 'drift') {
      console.log('::warning::対応表 (distro-map.json) にずれがあります');
    } else if (result.status === 'unchecked') {
      console.log('::warning::対応表の突き合わせで一部または全部が未確認です');
    }
  } catch (err) {
    console.error(`[check-distro-map] エラー: ${err?.message || err}`);
  } finally {
    process.exit(0);
  }
}

try {
  if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
    main();
  }
} catch {
  if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    main();
  }
}
