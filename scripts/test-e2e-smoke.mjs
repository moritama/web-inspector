/**
 * Web Technology & Security Inspector
 * Playwright 実拡張機能 包括的スモークE2Eテスト (scripts/test-e2e-smoke.mjs)
 * 
 * 実際のdist/ビルド拡張機能をChromiumに読み込み、以下を自動検証します：
 * 1. 肯定コントロール: React 18, Apache 2.4.58, PHP 8.2.14, Laravel (Cookie)
 * 2. 否定コントロール: Apache-Coyote (Apache未検出), Rails Cookie (Laravel未検出), loading-spinner (AngularJS未検出)
 * 3. エッジケース: Vue 3 (data-v- scoped CSS), GTM (noscript iframe), AWS ALB (Cookie)
 * 4. AngularJS EOL & 脆弱性診断: EOL表示、CVE-2022-25869 「修正版なし・移行推奨」文言の厳格なassert
 * 5. エクスポート保存: downloads権限廃止後のアンカー方式による Markdown / CSV / JSON ダウンロード実動
 * 6. 一般外部サイト: GitHub.com 調査 (soft fail)
 */

import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_PATH = path.join(ROOT_DIR, 'dist');

async function runSmokeTest() {
  console.log('[e2e-smoke] 拡張機能 包括的スモークE2Eテストを開始します...');

  if (!fs.existsSync(DIST_PATH)) {
    throw new Error('dist/ ディレクトリが見つかりません。先に npm run build を実行してください。');
  }

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-smoke-'));

  let context;
  try {
    context = await chromium.launchPersistentContext(userDataDir, {
      headless: false,
      acceptDownloads: true,
      args: [
        `--disable-extensions-except=${DIST_PATH}`,
        `--load-extension=${DIST_PATH}`,
      ],
    });

    console.log('[e2e-smoke] Chromiumを起動し、dist/ 拡張機能をロードしました。');

    // 1. Service Worker の起動待機
    let serviceWorker = context.serviceWorkers()[0];
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent('serviceworker', { timeout: 10000 });
    }
    console.log('[e2e-smoke] Service Workerが正常に起動しました:', serviceWorker.url());

    const extensionId = serviceWorker.url().split('/')[2];
    console.log('[e2e-smoke] 拡張機能ID:', extensionId);

    const page = await context.newPage();

    // 補助関数: 指定URLに遷移してService WorkerのrunInspectionを実行
    async function inspectUrl(url) {
      await page.goto(url, { waitUntil: 'networkidle' });
      await page.waitForTimeout(800);
      return await serviceWorker.evaluate(async () => {
        const tabs = await chrome.tabs.query({ url: '*://localhost/*' });
        if (tabs.length === 0) throw new Error('localhost タブが見つかりません');
        return await globalThis.runInspection(tabs[0].id);
      });
    }

    // -------------------------------------------------------------
    // 検証 1: 肯定コントロール (/react18-app)
    // -------------------------------------------------------------
    console.log('[e2e-smoke] [1/6] 肯定コントロール: /react18-app を検証中...');
    const reactReport = await inspectUrl('http://localhost:3000/react18-app');
    if (!reactReport || !reactReport.technologies || reactReport.technologies.length === 0) {
      throw new Error('/react18-app: 技術が0件しか検出されませんでした (全滅バグ再発の疑い)。');
    }
    const reactTech = reactReport.technologies.find((t) => t.technology === 'React');
    if (!reactTech || reactTech.version !== '18.2.0' || reactTech.runtimeStatus !== 'confirmed') {
      throw new Error(`/react18-app: React 18.2.0 (confirmed) が検出されませんでした (実際: ${JSON.stringify(reactTech)})`);
    }
    console.log(`  ✓ React 18.2.0 (confirmed) を正常検出`);

    // -------------------------------------------------------------
    // 検証 2: 肯定コントロール (/apache-positive, /laravel-positive)
    // -------------------------------------------------------------
    console.log('[e2e-smoke] [2/6] 肯定コントロール: /apache-positive & /laravel-positive を検証中...');
    const apacheReport = await inspectUrl('http://localhost:3000/apache-positive');
    const apacheTech = apacheReport.technologies.find((t) => t.technology === 'Apache');
    const phpTech = apacheReport.technologies.find((t) => t.technology === 'PHP');
    if (!apacheTech || apacheTech.version !== '2.4.58') {
      throw new Error(`/apache-positive: Apache 2.4.58 が未検出です (実際: ${JSON.stringify(apacheTech)})`);
    }
    if (!phpTech || phpTech.version !== '8.2.14') {
      throw new Error(`/apache-positive: PHP 8.2.14 が未検出です (実際: ${JSON.stringify(phpTech)})`);
    }
    console.log(`  ✓ Apache 2.4.58 (ヘッダー直接) & PHP 8.2.14 を正常検出`);

    const laravelReport = await inspectUrl('http://localhost:3000/laravel-positive');
    const laravelTech = laravelReport.technologies.find((t) => t.technology === 'Laravel');
    if (!laravelTech || laravelTech.confidence < 80) {
      throw new Error(`/laravel-positive: Laravel が未検出または確信度不足です (実際: ${JSON.stringify(laravelTech)})`);
    }
    console.log(`  ✓ Laravel (Cookie直接, 確信度=${laravelTech.confidence}%) を正常検出`);

    // -------------------------------------------------------------
    // 検証 3: 否定コントロール & エッジケース (/edge-cases, /rails-session, /negative-angular)
    // -------------------------------------------------------------
    console.log('[e2e-smoke] [3/6] 否定コントロール & エッジケースを検証中...');
    
    // Cookieをクリアしてクリーンな状態で検証
    await page.goto('http://localhost:3000/clear-cookies', { waitUntil: 'networkidle' });

    const edgeReport = await inspectUrl('http://localhost:3000/edge-cases');
    
    // 否定: Apache-Coyote/1.1 で Apache が誤検出されないこと
    const falseApache = edgeReport.technologies.find((t) => t.technology === 'Apache');
    if (falseApache) {
      throw new Error(`/edge-cases: Apache-Coyote/1.1 から Apache が誤検出されました (検出: ${JSON.stringify(falseApache)})`);
    }
    console.log(`  ✓ 否定: Apache-Coyote から Apache が除外されていることを確認`);

    // エッジケース: Vue 3 (data-v- scoped CSS)
    const vueTech = edgeReport.technologies.find((t) => t.technology === 'Vue.js');
    if (!vueTech) {
      throw new Error(`/edge-cases: Vue.js (data-v- scoped CSS) が未検出です`);
    }
    console.log(`  ✓ エッジケース: Vue.js (data-v- scoped CSS) を正常検出`);

    // エッジケース: GTM (noscript iframe)
    const gtmTech = edgeReport.technologies.find((t) => t.technology === 'Google Tag Manager');
    if (!gtmTech) {
      throw new Error(`/edge-cases: Google Tag Manager (noscript iframe) が未検出です`);
    }
    console.log(`  ✓ エッジケース: GTM (noscript iframe) を正常検出`);

    // エッジケース: AWS ALB (Cookie)
    const albTech = edgeReport.technologies.find((t) => t.technology === 'AWS Application Load Balancer');
    if (!albTech) {
      throw new Error(`/edge-cases: AWS Application Load Balancer (AWSALB Cookie) が未検出です`);
    }
    console.log(`  ✓ エッジケース: AWS ALB (Cookie) を正常検出`);

    // 否定: Rails Cookie 単独 (_myapp_session) で Laravel が誤検出されないこと
    await page.goto('http://localhost:3000/clear-cookies', { waitUntil: 'networkidle' });
    const railsReport = await inspectUrl('http://localhost:3000/rails-session');
    const falseLaravel = railsReport.technologies.find((t) => t.technology === 'Laravel');
    if (falseLaravel) {
      throw new Error(`/rails-session: _myapp_session 単独から Laravel が誤検出されました (検出: ${JSON.stringify(falseLaravel)})`);
    }
    console.log(`  ✓ 否定: _myapp_session 単独から Laravel が除外されていることを確認`);

    // 否定: loading-spinner 等で AngularJS が誤検出されないこと
    const negAngularReport = await inspectUrl('http://localhost:3000/negative-angular');
    const falseAngular = negAngularReport.technologies.find((t) => t.technology === 'AngularJS');
    if (falseAngular) {
      throw new Error(`/negative-angular: loading-spinner から AngularJS が誤検出されました (検出: ${JSON.stringify(falseAngular)})`);
    }
    console.log(`  ✓ 否定: loading-spinner から AngularJS が除外されていることを確認`);

    // -------------------------------------------------------------
    // 検証 4: AngularJS EOL & CVE-2022-25869 修正版なし案内 (assert)
    // -------------------------------------------------------------
    console.log('[e2e-smoke] [4/6] AngularJS EOL & CVE案内文のassert検証中...');
    const angularReport = await inspectUrl('http://localhost:3000/angularjs-advisory');
    const ngTech = angularReport.technologies.find((t) => t.technology === 'AngularJS');
    if (!ngTech || ngTech.supportStatus !== 'EOL') {
      throw new Error(`/angularjs-advisory: AngularJS EOL が判定されていません`);
    }

    const cveCheck = angularReport.securityChecks.find((c) => c.checkId.includes('SEC-CVE-ANGULARJS'));
    if (!cveCheck) {
      throw new Error(`/angularjs-advisory: SEC-CVE-ANGULARJS 診断項目が見つかりません`);
    }

    console.log(`  - CVE recommendation: "${cveCheck.recommendation}"`);

    // 厳格なassert: 「移行」を含み、「更新」を含まないこと
    if (!cveCheck.recommendation.includes('移行')) {
      throw new Error(`AngularJS CVE recommendation に「移行」が含まれていません: "${cveCheck.recommendation}"`);
    }
    if (cveCheck.recommendation.includes('更新')) {
      throw new Error(`AngularJS CVE recommendation に誤った「更新」が含まれています: "${cveCheck.recommendation}"`);
    }
    console.log(`  ✓ AngularJS CVE案内文のassert合格: 「移行」を含み「更新」を含まないことを確認`);

    // observed 文言の検証: 不正確な「CVSS: 6」を含まず「重大度」を含むこと
    if (cveCheck.observed.includes('CVSS: 6')) {
      throw new Error(`AngularJS CVE observed に不正確な「CVSS: 6」が含まれています: "${cveCheck.observed}"`);
    }
    if (!cveCheck.observed.includes('重大度')) {
      throw new Error(`AngularJS CVE observed に「重大度」が含まれていません: "${cveCheck.observed}"`);
    }
    console.log(`  ✓ AngularJS CVE observed文言のassert合格: "${cveCheck.observed}"`);

    // -------------------------------------------------------------
    // 検証 5: エクスポート保存 (Markdown, CSV, JSON) 実動テスト
    // -------------------------------------------------------------
    console.log('[e2e-smoke] [5/6] エクスポート保存 (downloads権限廃止・アンカー方式) を検証中...');
    
    // ダッシュボードページを開く
    const dashPage = await context.newPage();
    await dashPage.goto(`chrome-extension://${extensionId}/dashboard.html`, { waitUntil: 'networkidle' });
    await dashPage.waitForTimeout(1000);

    // Markdown ダウンロード検証
    const [mdDownload] = await Promise.all([
      dashPage.waitForEvent('download', { timeout: 5000 }),
      dashPage.click('#exportMdBtn'),
    ]);
    const mdFilename = mdDownload.suggestedFilename();
    const mdPath = await mdDownload.path();
    const mdStat = fs.statSync(mdPath);
    console.log(`  ✓ Markdown保存成功: ${mdFilename} (${mdStat.size} bytes)`);
    if (!mdFilename.endsWith('.md') || mdStat.size === 0) {
      throw new Error(`Markdown ダウンロードファイルが不正です: ${mdFilename}, size=${mdStat.size}`);
    }

    // CSV ダウンロード検証
    const [csvDownload] = await Promise.all([
      dashPage.waitForEvent('download', { timeout: 5000 }),
      dashPage.click('#exportCsvBtn'),
    ]);
    const csvFilename = csvDownload.suggestedFilename();
    const csvPath = await csvDownload.path();
    const csvStat = fs.statSync(csvPath);
    console.log(`  ✓ CSV保存成功: ${csvFilename} (${csvStat.size} bytes)`);
    if (!csvFilename.endsWith('.csv') || csvStat.size === 0) {
      throw new Error(`CSV ダウンロードファイルが不正です: ${csvFilename}, size=${csvStat.size}`);
    }

    // JSON ダウンロード検証
    const [jsonDownload] = await Promise.all([
      dashPage.waitForEvent('download', { timeout: 5000 }),
      dashPage.click('#exportJsonBtn'),
    ]);
    const jsonFilename = jsonDownload.suggestedFilename();
    const jsonPath = await jsonDownload.path();
    const jsonStat = fs.statSync(jsonPath);
    console.log(`  ✓ JSON保存成功: ${jsonFilename} (${jsonStat.size} bytes)`);
    if (!jsonFilename.endsWith('.json') || jsonStat.size === 0) {
      throw new Error(`JSON ダウンロードファイルが不正です: ${jsonFilename}, size=${jsonStat.size}`);
    }

    // スクリーンショット保存（目視確認用）
    if (!fs.existsSync(path.join(ROOT_DIR, '.tmp'))) {
      fs.mkdirSync(path.join(ROOT_DIR, '.tmp'), { recursive: true });
    }
    await dashPage.screenshot({ path: path.join(ROOT_DIR, '.tmp', 'dashboard-e2e.png') });
    console.log(`  ✓ ダッシュボード画面キャプチャ保存: .tmp/dashboard-e2e.png`);

    await dashPage.close();

    // ポップアップ画面の表示とキャプチャ
    const popupPage = await context.newPage();
    await popupPage.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: 'networkidle' });
    await popupPage.waitForTimeout(500);
    await popupPage.screenshot({ path: path.join(ROOT_DIR, '.tmp', 'popup-e2e.png') });
    console.log(`  ✓ ポップアップ画面キャプチャ保存: .tmp/popup-e2e.png`);
    await popupPage.close();

    // -------------------------------------------------------------
    // 検証 6: 一般外部サイト (GitHub.com, optional)
    // -------------------------------------------------------------
    console.log('[e2e-smoke] [6/6] 一般外部サイト (https://github.com) を検証中 (optional)...');
    try {
      await page.goto('https://github.com', { waitUntil: 'domcontentloaded', timeout: 15000 });
      await page.waitForTimeout(2000);

      const githubReport = await serviceWorker.evaluate(async () => {
        const tabs = await chrome.tabs.query({ url: '*://github.com/*' });
        if (tabs.length === 0) return null;
        return await globalThis.runInspection(tabs[0].id);
      });

      if (githubReport && githubReport.technologies.length > 0) {
        console.log(`  ✓ GitHub.com 調査成功: 検出技術数 ${githubReport.technologies.length} 件 (${githubReport.technologies.map((t) => t.technology).join(', ')})`);
      } else {
        console.log('  ⚠️ GitHub.com: 検出0件またはタブ取得スキップ (外部ネットワーク環境による制限)');
      }
    } catch (e) {
      console.warn('  ⚠️ GitHub.com アクセススキップ (ネットワーク制限):', e.message);
    }

    // -------------------------------------------------------------
    // 検証 7: レスポンスヘッダーキャッシュ機密情報保護 (Set-Cookie / 認証情報 / URLクエリ遮断)
    // -------------------------------------------------------------
    console.log('[e2e-smoke] [7/7] レスポンスヘッダーキャッシュ機密情報保護 (Canaryテスト) を検証中...');

    // 1. /cookie-canary へのアクセス
    await page.goto('http://localhost:3000/cookie-canary', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);

    // 2. /login-redirect (302 + Set-Cookie) へのアクセス
    await page.goto('http://localhost:3000/login-redirect', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);

    // 3. /login-200 (200 + Set-Cookie) へのアクセス
    await page.goto('http://localhost:3000/login-200', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);

    // 4. /token-redirect (302 + Location: ...token=CANARY_TOKEN) へのアクセス
    await page.goto('http://localhost:3000/token-redirect', { waitUntil: 'networkidle' });
    await page.waitForTimeout(500);

    // chrome.storage.session 内の全データを取得してスキャン
    const sessionDump = await serviceWorker.evaluate(async () => {
      if (!chrome.storage?.session) return {};
      return await chrome.storage.session.get(null);
    });

    const sessionStr = JSON.stringify(sessionDump);
    const canaryMatches = sessionStr.match(/CANARY_[A-Za-z0-9_]+/g);

    if (canaryMatches && canaryMatches.length > 0) {
      throw new Error(
        `chrome.storage.session に機密情報 (CANARY_) が漏洩・保存されています: ${[...new Set(canaryMatches)].join(', ')}`
      );
    }
    console.log(`  ✓ sessionストレージに CANARY_ 機密情報が保存されていないことを確認`);

    console.log('[e2e-smoke] ✅ 包括的スモークE2Eテスト完全合格！全検証（肯定/否定/エッジケース/CVE文言assert/エクスポート保存/Canary保護）が実機で確認されました。');
  } finally {
    if (context) {
      await context.close();
    }
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true });
    } catch {}
  }
}

runSmokeTest().catch((err) => {
  console.error('[e2e-smoke] ❌ スモークテスト失敗:', err);
  process.exit(1);
});
