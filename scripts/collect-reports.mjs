/**
 * Web Technology & Security Inspector
 * 実サイトの診断レポート一括取得 (scripts/collect-reports.mjs)
 *
 * dist/ の拡張を読み込んだ Chromium で、サイト一覧の URL を順に開き、
 * Service Worker の runInspection を呼んでレポートを作成し、
 * ポップアップの「Markdown 出力」と同じ形式のファイルと、元データの JSON を保存する。
 * 取得後に整合性チェッカー (scripts/report-lint.mjs) を実行し、結果を _summary.md に記録する。
 *
 * 使い方:
 *   npm run build
 *   node scripts/collect-reports.mjs                       # 既定のサイト一覧を使う
 *   node scripts/collect-reports.mjs --sites my-sites.txt  # サイト一覧を指定
 *   node scripts/collect-reports.mjs --snapshot            # スナップショット (HTML・ヘッダー・Resource Timing) も保存
 *   node scripts/collect-reports.mjs https://example.com/  # URL を直接指定
 *
 * オプション:
 *   --sites <file>       サイト一覧（1 行 1 URL、# 以降はコメント）
 *                        既定: report-sites.local.txt があればそれ、なければ scripts/report-sites.example.txt
 *   --out <dir>          出力先。既定: reports/<YYYY-MM-DD_HHmm>
 *   --snapshot           各サイトの HTML (page.content())、メイン文書のレスポンスヘッダー、
 *                        Resource Timing の一覧を <out>/snapshots/ に保存する（Cookie の値は含めない）
 *   --headless           ヘッドレスで実行（channel: 'chromium'。環境によっては拡張が読み込まれない）
 *   --executable <path>  Chromium / Chrome の実行ファイルを指定
 *   --wait <ms>          読み込み完了後、診断までに待つ時間。既定: 2000
 *   --timeout <ms>       1 サイトの読み込みを待つ上限。既定: 30000
 *   --strict-tls         証明書エラーのサイトを取得しない（既定では警告を記録したうえで取得する）
 *
 * 注意:
 *   - 調査は受動的解析（通常の閲覧と同じ）。1 サイトずつ順番に、トップページなど一覧の URL だけを開く。
 *   - 毎回新しいプロファイルで起動するため、Cookie は前回の閲覧の影響を受けない。
 *   - 実サイトのレポートには第三者サイトの設定不備が含まれる。公開リポジトリにはコミットしないこと
 *     （reports/ と report-sites.local.txt は .gitignore 済み）。
 */

import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { createServer } from 'vite';
import { getPendingChecks, lintReportPair } from './report-lint.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_PATH = path.join(ROOT_DIR, 'dist');
const LOCAL_SITES = path.join(ROOT_DIR, 'report-sites.local.txt');
const EXAMPLE_SITES = path.join(ROOT_DIR, 'scripts', 'report-sites.example.txt');

/** コマンドライン引数を解釈する */
export function parseArgs(argv) {
  const opts = {
    sites: null,
    out: null,
    headless: false,
    executable: null,
    waitMs: 2000,
    timeoutMs: 30000,
    inspectTimeoutMs: 60000,
    strictTls: false,
    snapshot: false,
    urls: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--sites') opts.sites = argv[++i];
    else if (a === '--out') opts.out = argv[++i];
    else if (a === '--headless') opts.headless = true;
    else if (a === '--executable') opts.executable = argv[++i];
    else if (a === '--wait') opts.waitMs = Number(argv[++i]);
    else if (a === '--timeout') opts.timeoutMs = Number(argv[++i]);
    else if (a === '--strict-tls') opts.strictTls = true;
    else if (a === '--snapshot') opts.snapshot = true;
    else if (a.startsWith('--')) throw new Error(`不明なオプション: ${a}`);
    else opts.urls.push(a);
  }
  if (!Number.isFinite(opts.waitMs) || opts.waitMs < 0) throw new Error('--wait には 0 以上の数値を指定してください');
  if (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs < 1000) throw new Error('--timeout には 1000 以上の数値を指定してください');
  return opts;
}

/** サイト一覧ファイルを読む（空行と # 以降を除く。重複は 1 件にまとめる） */
export function parseSitesFile(text) {
  const urls = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    let u;
    try {
      u = new URL(line);
    } catch {
      throw new Error(`URL として解釈できない行があります: ${raw}`);
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new Error(`http / https 以外の URL は指定できません: ${raw}`);
    }
    if (!urls.includes(u.href)) urls.push(u.href);
  }
  return urls;
}

/** ポップアップの Markdown 出力と同じファイル名（downloadMarkdownReport と同じ規則） */
export function reportBaseName(report) {
  const cleanHost = String(report.hostname).replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStr = new Date(report.inspectedAt).toISOString().slice(0, 10);
  return `web-inspector-report-${cleanHost}-${dateStr}`;
}

/** スナップショット保存用のベースファイル名（ホスト名ベース） */
export function snapshotBaseName(hostnameOrReport) {
  const host =
    typeof hostnameOrReport === 'string'
      ? hostnameOrReport
      : String(hostnameOrReport?.hostname || '');
  return host.toLowerCase().replace(/[^a-z0-9.-]/g, '_') || 'snapshot';
}

/**
 * Set-Cookie ヘッダー文字列から Cookie の値（Value）を取り除き、名前と属性だけを残す
 * 例: "ASPSESSIONIDQCSRDTBS=SECRET123; path=/; HttpOnly" -> "ASPSESSIONIDQCSRDTBS=; path=/; HttpOnly"
 */
export function maskSetCookieValue(rawSetCookie) {
  const str = String(rawSetCookie ?? '').trim();
  if (!str) return '';
  const parts = str.split(';');
  const first = parts[0] || '';
  const eqIdx = first.indexOf('=');
  const maskedFirst = eqIdx >= 0 ? `${first.slice(0, eqIdx).trim()}=` : first.trim();
  const attrs = parts
    .slice(1)
    .map((p) => p.trim())
    .filter(Boolean);
  return [maskedFirst, ...attrs].join('; ');
}

/**
 * スナップショット保存用にメイン文書のレスポンスヘッダーをサニタイズする（Cookie値や機密ヘッダーを含めない）
 */
export function sanitizeSnapshotHeaders(rawHeaders) {
  const result = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return result;

  const forbiddenHeaders = new Set(['authorization', 'proxy-authorization', 'cookie']);

  if (Array.isArray(rawHeaders)) {
    for (const h of rawHeaders) {
      const k = String(h?.name || '').toLowerCase().trim();
      if (!k || forbiddenHeaders.has(k)) continue;
      if (!result[k]) result[k] = [];
      const val = String(h?.value ?? '');
      result[k].push(k === 'set-cookie' ? maskSetCookieValue(val) : val);
    }
    return result;
  }

  for (const [rawKey, rawVal] of Object.entries(rawHeaders)) {
    const k = String(rawKey || '').toLowerCase().trim();
    if (!k || forbiddenHeaders.has(k)) continue;
    const list = Array.isArray(rawVal) ? rawVal : [String(rawVal ?? '')];
    result[k] = list.map((v) => (k === 'set-cookie' ? maskSetCookieValue(v) : String(v ?? '')));
  }
  return result;
}

/**
 * スナップショット保存用に Cookie リストから値（value）を除去し、属性のみを残す
 */
export function sanitizeSnapshotCookies(rawCookies) {
  if (!Array.isArray(rawCookies)) return [];
  return rawCookies.map((c) => ({
    name: String(c?.name ?? ''),
    domain: String(c?.domain ?? ''),
    path: String(c?.path ?? '/'),
    secure: Boolean(c?.secure),
    httpOnly: Boolean(c?.httpOnly),
    sameSite: String(c?.sameSite ?? 'unspecified'),
    session: Boolean(c?.session),
    hostOnly: Boolean(c?.hostOnly),
    partitioned: Boolean(c?.partitioned),
  }));
}

/** 出力先の既定値 reports/<YYYY-MM-DD_HHmm>（ローカル時刻） */
export function defaultOutDir(now = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  const stamp = `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}_${p(now.getHours())}${p(now.getMinutes())}`;
  return path.join(ROOT_DIR, 'reports', stamp);
}

function resolveSites(opts) {
  if (opts.urls.length > 0) return parseSitesFile(opts.urls.join('\n'));
  const file = opts.sites
    ? path.resolve(process.cwd(), opts.sites)
    : fs.existsSync(LOCAL_SITES)
      ? LOCAL_SITES
      : EXAMPLE_SITES;
  if (!fs.existsSync(file)) throw new Error(`サイト一覧が見つかりません: ${file}`);
  console.log(`[collect] サイト一覧: ${path.relative(ROOT_DIR, file) || file}`);
  return parseSitesFile(fs.readFileSync(file, 'utf8'));
}

/** Markdown 生成関数を src/export/markdown.ts から読み込む（拡張と同じコードを使う） */
async function loadMarkdownGenerator() {
  const server = await createServer({
    root: ROOT_DIR,
    configFile: false,
    logLevel: 'error',
    appType: 'custom',
    server: { middlewareMode: true, hmr: false },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  const mod = await server.ssrLoadModule('/src/export/markdown.ts');
  return { generateMarkdownReport: mod.generateMarkdownReport, close: () => server.close() };
}

/** 現在の Service Worker を返す（MV3 の SW は停止・再起動されることがあるため毎回取り直す） */
async function getServiceWorker(context) {
  const sw = context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));
  if (sw) return sw;
  return await context.waitForEvent('serviceworker', { timeout: 15000 });
}

function mdCell(s) {
  return String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

export function buildSummary(results, meta = {}) {
  const okResults = results.filter((r) => r.ok);
  const failResults = results.filter((r) => !r.ok);
  const lintedResults = okResults.filter((r) => r.lint);
  const lintPassed = lintedResults.filter((r) => r.lint.ok).length;
  const lintFailed = lintedResults.filter((r) => !r.lint.ok).length;
  const pendingDefs = Array.isArray(meta.pendingChecks) ? meta.pendingChecks : getPendingChecks();
  const pendingText =
    pendingDefs.length > 0
      ? `${pendingDefs.length} 項目（${pendingDefs.map((d) => `${d.id}: ${d.pendingUntil}`).join(', ')}）`
      : '0 項目';

  const lines = [
    '# レポート一括取得の結果',
    '',
    `- 実行日時: ${meta.startedAt}`,
    `- 拡張: ${meta.extensionVersion ?? '不明'}（dist/）`,
    `- 成功: ${okResults.length} 件 / 失敗: ${failResults.length} 件`,
    `- 整合性チェック: 合格 ${lintPassed} 件 / 不合格 ${lintFailed} 件（保留: ${pendingText}）`,
    '',
    '| URL | 結果 | 最終 URL | 要確認 | 技術数 | 整合性 | ファイル | 備考 |',
    '|---|---|---|---:|---:|---|---|---|',
  ];
  for (const r of results) {
    const lintCell = !r.ok
      ? '-'
      : !r.lint
        ? '-'
        : r.lint.ok
          ? '合格'
          : `不合格 (${r.lint.violations.map((v) => v.id).join(', ')})`;
    lines.push(
      `| ${mdCell(r.url)} | ${r.ok ? '成功' : `失敗: ${mdCell(r.error)}`} | ${mdCell(r.finalUrl ?? '-')} | ${r.ok ? r.attention : '-'} | ${r.ok ? r.techCount : '-'} | ${mdCell(lintCell)} | ${r.ok ? mdCell(r.file) : '-'} | ${mdCell((r.notes || []).join(' / ') || '-')} |`
    );
  }

  const failedLintItems = lintedResults.filter((r) => !r.lint.ok);
  if (failedLintItems.length > 0) {
    lines.push('', '## 整合性チェックの違反詳細', '');
    for (const r of failedLintItems) {
      lines.push(`### ${mdCell(r.file)} (${mdCell(r.url)})`);
      for (const v of r.lint.violations) {
        lines.push(`- **(${v.number}) [${v.id}] ${mdCell(v.title)}**: ${mdCell(v.message)}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n') + '\n';
}

/**
 * https の URL について、ブラウザとは別に証明書を検証する。
 * ブラウザ側は証明書エラーを無視して開くため、ここで警告を記録する。
 * @returns {Promise<string|null>} 問題があればエラーコード、なければ null
 */
export function checkCertificate(url, timeoutMs = 10000) {
  const u = new URL(url);
  if (u.protocol !== 'https:') return Promise.resolve(null);
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: u.hostname,
      port: Number(u.port) || 443,
      servername: u.hostname,
      rejectUnauthorized: true,
      timeout: timeoutMs,
    });
    const done = (v) => {
      socket.destroy();
      resolve(v);
    };
    socket.once('secureConnect', () => done(null));
    socket.once('error', (e) => done(e.code || e.message));
    socket.once('timeout', () => done('TLS_TIMEOUT'));
  });
}

/** Chrome のエラー画面・警告画面（chrome-error://）かどうか */
function isErrorPage(url) {
  return !/^https?:/.test(url || '');
}

async function inspectOne(context, url, opts) {
  const notes = [];

  if (url.startsWith('https:')) {
    const certError = await checkCertificate(url);
    if (certError && certError !== 'TLS_TIMEOUT') {
      if (opts.strictTls) throw new Error(`証明書エラー（${certError}）`);
      notes.push(`証明書エラー（${certError}）を無視して取得`);
    }
  }

  // サイトごとに新しいタブを使う（前のサイトの遅れたナビゲーションに巻き込まれないため）
  const page = await context.newPage();
  let mainStatusCode = null;
  let mainResponseHeaders = {};

  page.on('response', async (res) => {
    try {
      if (res.frame() === page.mainFrame() && res.request().isNavigationRequest()) {
        mainStatusCode = res.status();
        const hdrArray = await res.headersArray().catch(() => []);
        mainResponseHeaders = sanitizeSnapshotHeaders(hdrArray);
      }
    } catch {
      // レスポンスヘッダー取得例外は無視
    }
  });

  try {
    let gotoError = null;
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: opts.timeoutMs });
    } catch (err) {
      gotoError = err;
    }

    // HTTPS への自動切り替えの警告画面などが出た場合は「サイトへ進む」を試す
    if (isErrorPage(page.url())) {
      const proceed = page.locator('#proceed-button, #proceed-link');
      if (await proceed.count().catch(() => 0)) {
        await proceed.first().click().catch(() => {});
        await page.waitForURL(/^https?:/, { timeout: opts.timeoutMs }).catch(() => {});
        if (!isErrorPage(page.url())) notes.push('警告画面を通過して取得');
      }
    }

    const finalUrl = page.url();
    if (isErrorPage(finalUrl) || finalUrl === 'about:blank') {
      const reason = gotoError ? String(gotoError.message).split('\n')[0] : `エラー画面（${finalUrl}）`;
      throw new Error(`ページを表示できませんでした: ${reason}`);
    }
    if (gotoError) notes.push('読み込みが時間内に終わらず、表示できた範囲で取得');

    let loaded = true;
    await page.waitForLoadState('load', { timeout: 20000 }).catch(() => (loaded = false));
    if (!loaded) {
      // 読み込みが終わらないページでは、拡張のスクリプト注入（document_idle 待ち）が始まらない。
      // 読み込みを止めて、表示できた範囲で診断する
      await page.evaluate(() => window.stop()).catch(() => {});
      notes.push('読み込みが終わらないため途中で停止して取得');
    }
    await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});
    await page.waitForTimeout(opts.waitMs);

    const target = page.url();
    const sw = await getServiceWorker(context);
    const inspection = sw.evaluate(async (targetUrl) => {
      const strip = (u) => (u || '').split('#')[0];
      const tabs = await chrome.tabs.query({});
      const tab =
        tabs.find((t) => strip(t.url) === strip(targetUrl)) ||
        tabs.find((t) => t.active && /^https?:/.test(t.url || ''));
      if (!tab || !tab.id) throw new Error(`対象のタブが見つかりません: ${targetUrl}`);
      if (typeof globalThis.runInspection !== 'function') {
        throw new Error('runInspection が公開されていません（dist/ のビルドを確認してください）');
      }
      return await globalThis.runInspection(tab.id);
    }, target);
    let timer;
    const report = await Promise.race([
      inspection,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`診断が ${opts.inspectTimeoutMs / 1000} 秒以内に終わりませんでした`)), opts.inspectTimeoutMs);
      }),
    ]).finally(() => clearTimeout(timer));

    let snapshot = null;
    if (opts.snapshot) {
      const html = await page.content().catch(() => '');
      const resourceTiming = await page
        .evaluate(() => {
          try {
            return performance.getEntriesByType('resource').map((entry) => ({
              name: String(entry.name || ''),
              initiatorType: String(entry.initiatorType || 'other'),
              transferSize: typeof entry.transferSize === 'number' ? entry.transferSize : 0,
              encodedBodySize: typeof entry.encodedBodySize === 'number' ? entry.encodedBodySize : 0,
              decodedBodySize: typeof entry.decodedBodySize === 'number' ? entry.decodedBodySize : 0,
              startTime: typeof entry.startTime === 'number' ? Math.round(entry.startTime) : 0,
              duration: typeof entry.duration === 'number' ? Math.round(entry.duration) : 0,
            }));
          } catch {
            return [];
          }
        })
        .catch(() => []);

      snapshot = {
        url,
        finalUrl: target,
        hostname: report.hostname || new URL(target).hostname,
        statusCode: mainStatusCode,
        capturedAt: report.inspectedAt || new Date().toISOString(),
        responseHeaders: mainResponseHeaders,
        resourceTiming,
        cookies: sanitizeSnapshotCookies(report.cookies || []),
        html,
      };
    }

    return { finalUrl: target, report, notes, snapshot };
  } finally {
    await page.close().catch(() => {});
  }
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  const sites = resolveSites(opts);
  if (sites.length === 0) throw new Error('対象の URL がありません。');

  if (!fs.existsSync(path.join(DIST_PATH, 'manifest.json'))) {
    throw new Error('dist/ が見つかりません。先に npm run build を実行してください。');
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(DIST_PATH, 'manifest.json'), 'utf8'));

  const outDir = opts.out ? path.resolve(process.cwd(), opts.out) : defaultOutDir();
  fs.mkdirSync(outDir, { recursive: true });
  const snapshotsDir = opts.snapshot ? path.join(outDir, 'snapshots') : null;
  if (snapshotsDir) {
    fs.mkdirSync(snapshotsDir, { recursive: true });
  }
  console.log(`[collect] 対象 ${sites.length} 件、出力先: ${path.relative(ROOT_DIR, outDir) || outDir}`);

  const md = await loadMarkdownGenerator();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'web-inspector-collect-'));
  // 「常に安全な接続を使用する」（HTTP サイトで警告画面を出す設定）を切る
  fs.mkdirSync(path.join(userDataDir, 'Default'), { recursive: true });
  fs.writeFileSync(
    path.join(userDataDir, 'Default', 'Preferences'),
    JSON.stringify({ https_only_mode_enabled: false, https_only_mode_auto_enabled: false })
  );
  const startedAt = new Date().toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' });
  const results = [];
  let context;

  try {
    context = await chromium.launchPersistentContext(userDataDir, {
      headless: opts.headless,
      ignoreHTTPSErrors: !opts.strictTls,
      ...(opts.headless && !opts.executable ? { channel: 'chromium' } : {}),
      ...(opts.executable ? { executablePath: opts.executable } : {}),
      args: [
        `--disable-extensions-except=${DIST_PATH}`,
        `--load-extension=${DIST_PATH}`,
        // Google Chrome 137 以降は既定で --load-extension が無効。Chromium では不要だが害はない
        // HTTPS への自動切り替え・警告画面を止める（存在しない機能名は無視される）
        '--disable-features=DisableLoadExtensionCommandLineSwitch,HttpsUpgrades,HttpsFirstModeV2,HttpsFirstModeV2ForEngagedSites,HttpsFirstModeV2ForTypicallySecureUsers,HttpsFirstBalancedMode,HttpsFirstBalancedModeAutoEnable,HttpsFirstModeIncognito',
      ],
    });

    const sw = await getServiceWorker(context);
    console.log(`[collect] 拡張を読み込みました: ${sw.url().split('/')[2]}（v${manifest.version}）`);

    for (const [i, url] of sites.entries()) {
      const label = `[${i + 1}/${sites.length}] ${url}`;
      try {
        const { finalUrl, report, notes, snapshot } = await inspectOne(context, url, opts);
        const base = reportBaseName(report);
        // 同じホスト・同じ日付が複数ある場合（パス違いなど）は連番を付ける
        let name = base;
        for (let n = 2; fs.existsSync(path.join(outDir, `${name}.md`)); n++) name = `${base}-${n}`;

        const markdownText = md.generateMarkdownReport(report, null, []);
        fs.writeFileSync(path.join(outDir, `${name}.md`), markdownText, 'utf8');
        fs.writeFileSync(path.join(outDir, `${name}.json`), JSON.stringify(report, null, 2) + '\n', 'utf8');

        const lint = lintReportPair(report, markdownText);

        let snapshotFile = null;
        if (snapshotsDir && snapshot) {
          const snapBase = snapshotBaseName(snapshot.hostname || report.hostname);
          let snapName = snapBase;
          for (let n = 2; fs.existsSync(path.join(snapshotsDir, `${snapName}.json`)); n++) {
            snapName = `${snapBase}-${n}`;
          }
          fs.writeFileSync(
            path.join(snapshotsDir, `${snapName}.json`),
            JSON.stringify(snapshot, null, 2) + '\n',
            'utf8'
          );
          fs.writeFileSync(path.join(snapshotsDir, `${snapName}.html`), snapshot.html || '', 'utf8');
          snapshotFile = `snapshots/${snapName}.json`;
        }

        const attention = report.summary?.requiresAttentionCount ?? '-';
        const techCount = report.summary?.totalTechnologies ?? report.technologies?.length ?? '-';
        results.push({
          url,
          ok: true,
          finalUrl,
          attention,
          techCount,
          file: `${name}.md`,
          notes,
          lint,
          snapshotFile,
        });
        const lintBadge = lint.ok ? '整合性:OK' : `整合性:NG(${lint.violations.map((v) => v.id).join(',')})`;
        const noteText = notes.length ? `　※${notes.join(' / ')}` : '';
        console.log(`  ✓ ${label} → ${name}.md（要確認 ${attention} 件、技術 ${techCount} 件、${lintBadge}）${noteText}`);
      } catch (err) {
        const message = String(err?.message || err).split('\n')[0];
        results.push({ url, ok: false, error: message, finalUrl: null });
        console.log(`  ✗ ${label} → 失敗: ${message}`);
      }
    }
  } finally {
    if (context) await context.close().catch(() => {});
    await md.close().catch(() => {});
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
    } catch {
      console.log(`[collect] 一時プロファイルを削除できませんでした（残っていても問題ありません）: ${userDataDir}`);
    }
  }

  fs.writeFileSync(
    path.join(outDir, '_summary.md'),
    buildSummary(results, {
      startedAt,
      extensionVersion: manifest.version,
      pendingChecks: getPendingChecks(),
    }),
    'utf8'
  );
  const ok = results.filter((r) => r.ok).length;
  console.log(`[collect] 完了: 成功 ${ok} 件 / 失敗 ${results.length - ok} 件（一覧: _summary.md）`);
  return ok > 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(`[collect] エラー: ${err?.message || err}`);
      process.exit(1);
    });
}
