// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * v1.8.0 T04: WAF・ボット確認画面（interstitial）の検出と表示 (tests/interstitial.test.ts)
 *
 * - 印は Cloudflare（cf-mitigated: challenge、/cdn-cgi/challenge-platform/）、AWS WAF（x-amzn-waf-action）、
 *   Fastly（タイトル Client Challenge、id="fastlyLogo"、id="captchaTitle"）
 * - 判定には「同じベンダーの印が 2 つ以上」か「ベンダーのヘッダー 1 つ」が必要。タイトルだけでは判定しない
 * - 結果はレポートの interstitial: { vendor, evidence[] }。ポップアップと Markdown の先頭に注意を出し、完全性を partial にする
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ALLOWED_RESPONSE_HEADERS,
  executeInspection,
  filterAndSanitizeHeaders,
} from '../src/background/service-worker';
import { extractDomSignals } from '../src/content/content-script';
import { generateMarkdownReport } from '../src/export/markdown';
import * as popupRender from '../src/popup/render';
import { InspectedCookieInfo, InspectionReport } from '../src/shared/types';
import { DOM_SIGNAL_FIXTURES } from './fixtures/dom-signal-fixtures';
// @ts-expect-error .mjs スクリプトをテストから直接インポート
import { lintDirectory, lintReportPair } from '../scripts/report-lint.mjs';

const SNAPSHOTS_DIR = path.resolve(__dirname, 'fixtures', 'snapshots');
const REPORT_FIXTURES_DIR = path.resolve(__dirname, 'fixtures', 'reports');
const FASTLY_SNAPSHOT = 'www.drupal.org';

/** G6 が指定する注意の文言 */
const NOTICE_PHRASE = '確認画面を診断している可能性';
/** 調査の完全性・技術検出の扱い（指示書 T04・G6） */
const INCOMPLETE_WORD = '不完全';

/** 実装前でも型検査に依存しないよう、interstitial を緩く読む */
interface InterstitialLike {
  vendor: string;
  evidence: string[];
}
function getInterstitial(report: InspectionReport): InterstitialLike | null | undefined {
  return (report as InspectionReport & { interstitial?: InterstitialLike | null }).interstitial;
}

interface SnapshotJson {
  url: string;
  finalUrl?: string;
  responseHeaders?: Record<string, string[]>;
  resourceTiming?: Array<{ name: string; initiatorType?: string }>;
  cookies?: InspectedCookieInfo[];
  html?: string;
}

interface InspectOptions {
  pageUrl?: string;
  headers?: Record<string, string[]>;
  /** false のときヘッダー未観測（キャッシュなし） */
  headersObserved?: boolean;
  /** ヘッダーのキャッシュの URL（origin 不一致の模擬に使う） */
  cachedUrl?: string;
  resourceTiming?: Array<{ name: string; initiatorType?: string }>;
  cookies?: InspectedCookieInfo[];
}

const originalConsoleError = console.error;
afterEach(() => {
  console.error = originalConsoleError;
  vi.restoreAllMocks();
});

function silenceHappyDomNoise(): void {
  console.error = (...args: unknown[]) => {
    const first = args[0];
    const msg =
      first && typeof first === 'object' && 'message' in (first as Record<string, unknown>)
        ? String((first as Record<string, unknown>).message)
        : String(first ?? '');
    if (
      msg.includes('CSS file loading is disabled') ||
      msg.includes('JavaScript file loading is disabled') ||
      msg.includes('Iframe page loading is disabled')
    ) {
      return;
    }
    originalConsoleError(...args);
  };
}

/** HTML を文書に入れ、extractDomSignals → executeInspection を通してレポートを作る */
async function inspectHtml(html: string, opts: InspectOptions = {}): Promise<InspectionReport> {
  silenceHappyDomNoise();
  const pageUrl = opts.pageUrl ?? 'https://site.example.test/';
  document.documentElement.innerHTML = html;
  const spy = vi.spyOn(performance, 'getEntriesByType').mockImplementation((type: string) => {
    if (type === 'resource') {
      return (opts.resourceTiming || []) as unknown as PerformanceEntry[];
    }
    return [];
  });
  let signals;
  try {
    signals = extractDomSignals(pageUrl);
  } finally {
    spy.mockRestore();
  }
  const headersObserved = opts.headersObserved ?? true;
  return executeInspection({
    tab: { id: 1, url: pageUrl },
    fetchDomSignals: async () => signals,
    fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: async () =>
      headersObserved
        ? { url: opts.cachedUrl ?? pageUrl, headers: opts.headers || {}, observed: true }
        : undefined,
    getInspectedCookies: async () => opts.cookies || [],
    getAllFindingExceptions: async () => [],
    saveReport: async () => {},
    hasWebRequestPermission: true,
  });
}

function loadSnapshot(base: string): { snap: SnapshotJson; html: string; pageUrl: string } {
  const snap = JSON.parse(
    fs.readFileSync(path.join(SNAPSHOTS_DIR, `${base}.json`), 'utf-8')
  ) as SnapshotJson;
  const htmlPath = path.join(SNAPSHOTS_DIR, `${base}.html`);
  const html = snap.html || (fs.existsSync(htmlPath) ? fs.readFileSync(htmlPath, 'utf-8') : '');
  return { snap, html, pageUrl: snap.finalUrl || snap.url };
}

async function inspectSnapshot(
  base: string,
  opts: Pick<InspectOptions, 'headersObserved'> = {}
): Promise<InspectionReport> {
  const { snap, html, pageUrl } = loadSnapshot(base);
  return inspectHtml(html, {
    pageUrl,
    headers: snap.responseHeaders || {},
    headersObserved: opts.headersObserved,
    resourceTiming: snap.resourceTiming || [],
    cookies: snap.cookies || [],
  });
}

function otherSnapshotBases(): string[] {
  return fs
    .readdirSync(SNAPSHOTS_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.slice(0, -'.json'.length))
    .filter((b) => b !== FASTLY_SNAPSHOT)
    .sort();
}

/** 確認画面ではない普通のページ（合成データ） */
const ORDINARY_PAGE =
  '<html><head><title>Welcome</title></head><body><main><h1>Hello</h1><p>content</p></main></body></html>';

function expectNoInterstitial(report: InspectionReport): void {
  expect(getInterstitial(report) == null).toBe(true);
  const md = generateMarkdownReport(report);
  expect(md).not.toContain(NOTICE_PHRASE);
  const reasons = report.coverage?.details?.partialReasons || [];
  expect(reasons.some((r) => r.includes('確認画面'))).toBe(false);
}

function expectVendor(report: InspectionReport, vendor: string): InterstitialLike {
  const info = getInterstitial(report);
  expect(info).toBeTruthy();
  expect(info?.vendor).toBe(vendor);
  expect(Array.isArray(info?.evidence)).toBe(true);
  expect(info!.evidence.length).toBeGreaterThanOrEqual(1);
  for (const e of info!.evidence) {
    expect(typeof e).toBe('string');
  }
  return info!;
}

describe('v1.8.0 T04: 受け入れ条件 1 — Fastly の確認画面のスナップショット', () => {
  it('前提: テストの文書の組み立てで、スナップショットのタイトルと id が読めること（フィクスチャの確認）', () => {
    const { html, pageUrl } = loadSnapshot(FASTLY_SNAPSHOT);
    silenceHappyDomNoise();
    document.documentElement.innerHTML = html;
    expect(extractDomSignals(pageUrl).title).toBe('Client Challenge');
    expect(document.getElementById('fastlyLogo')).not.toBeNull();
    expect(document.getElementById('captchaTitle')).not.toBeNull();
    document.documentElement.innerHTML =
      '<html><head><title>Client Challenge</title></head><body><p>x</p></body></html>';
    expect(extractDomSignals('https://site.example.test/').title).toBe('Client Challenge');
  });

  it('スナップショット（Fastly の Client Challenge）で vendor が Fastly、evidence に印が 2 つ以上あること', async () => {
    const report = await inspectSnapshot(FASTLY_SNAPSHOT);
    const info = expectVendor(report, 'Fastly');
    expect(info.evidence.length).toBeGreaterThanOrEqual(2);
    // evidence はどれも Fastly の印のいずれかを示す
    for (const e of info.evidence) {
      expect(e).toMatch(/Client Challenge|fastlyLogo|captchaTitle/);
    }
  });

  it('ヘッダーが未観測でも、ページ内の印だけで Fastly と判定されること', async () => {
    const report = await inspectSnapshot(FASTLY_SNAPSHOT, { headersObserved: false });
    expectVendor(report, 'Fastly');
  });

  it('調査の完全性が partial になり、理由に確認画面のことが書かれること（G6）', async () => {
    const report = await inspectSnapshot(FASTLY_SNAPSHOT);
    expect(report.coverage?.overallStatus).toBe('partial');
    const reasons = report.coverage?.details?.partialReasons || [];
    expect(reasons.some((r) => r.includes('確認画面'))).toBe(true);
  });

  it('診断は止めないこと（セキュリティ診断の結果が残る）', async () => {
    const report = await inspectSnapshot(FASTLY_SNAPSHOT);
    expect(report.securityChecks.length).toBeGreaterThan(0);
    expect(Array.isArray(report.technologies)).toBe(true);
  });

  it('Markdown の先頭（1. 調査概要より前）に、ベンダー名・G6 の文言・「不完全」を含む注意が出ること', async () => {
    const report = await inspectSnapshot(FASTLY_SNAPSHOT);
    const md = generateMarkdownReport(report);
    const noticeIdx = md.indexOf(NOTICE_PHRASE);
    const overviewIdx = md.indexOf('## 1. 調査概要');
    expect(noticeIdx).toBeGreaterThanOrEqual(0);
    expect(overviewIdx).toBeGreaterThan(noticeIdx);
    const head = md.slice(0, overviewIdx);
    expect(head).toContain('Fastly');
    expect(head).toContain(INCOMPLETE_WORD);
  });

  it('interstitial は JSON の保存・読み込みで失われないこと（レポートに持たせる）', async () => {
    const report = await inspectSnapshot(FASTLY_SNAPSHOT);
    const restored = JSON.parse(JSON.stringify(report)) as InspectionReport;
    expect(getInterstitial(restored)).toEqual(getInterstitial(report));
    // 読み込んだレポートからも Markdown の注意が出る
    expect(generateMarkdownReport(restored)).toContain(NOTICE_PHRASE);
  });
});

describe('v1.8.0 T04: 受け入れ条件 3 — レポートの整合性チェッカー', () => {
  it('Fastly の確認画面のレポートと Markdown の組が lintReportPair を通ること', async () => {
    const report = await inspectSnapshot(FASTLY_SNAPSHOT);
    const md = generateMarkdownReport(report);
    const res = lintReportPair(report, md);
    expect(res.violations).toEqual([]);
    expect(res.ok).toBe(true);
  });

  it('ヘッダーで判定した確認画面（Cloudflare・AWS WAF）のレポートも lintReportPair を通ること', async () => {
    const cases: Array<Record<string, string[]>> = [
      { 'cf-mitigated': ['challenge'] },
      { 'x-amzn-waf-action': ['captcha'] },
    ];
    for (const headers of cases) {
      const report = await inspectHtml(ORDINARY_PAGE, { headers });
      expect(getInterstitial(report)).toBeTruthy();
      const res = lintReportPair(report, generateMarkdownReport(report));
      expect(res.violations).toEqual([]);
      expect(res.ok).toBe(true);
    }
  });

  it('既存のレポートのフィクスチャ（tests/fixtures/reports）が lintDirectory を通ること', () => {
    const res = lintDirectory(REPORT_FIXTURES_DIR);
    expect(res.ok).toBe(true);
  });
});

describe('v1.8.0 T04: 受け入れ条件 2 — 誤判定が 0 件', () => {
  it('Fastly の確認画面以外の全スナップショットで interstitial が無く、注意も出ないこと', async () => {
    const bases = otherSnapshotBases();
    expect(bases.length).toBeGreaterThan(0);
    const falsePositives: string[] = [];
    for (const base of bases) {
      const report = await inspectSnapshot(base);
      const info = getInterstitial(report);
      if (info != null) falsePositives.push(`${base}: ${info.vendor}`);
      expect(generateMarkdownReport(report)).not.toContain(NOTICE_PHRASE);
    }
    expect(falsePositives).toEqual([]);
  });

  it('DOM シグナルのフィクスチャ（dom-signal-fixtures.ts）の全件で interstitial が無いこと', async () => {
    const falsePositives: string[] = [];
    for (const [key, fixture] of Object.entries(DOM_SIGNAL_FIXTURES)) {
      const title = fixture.title ? `<title>${fixture.title}</title>` : '';
      const html = `<html><head>${title}${fixture.headHtml || ''}</head><body>${fixture.html}</body></html>`;
      const report = await inspectHtml(html);
      if (getInterstitial(report) != null) falsePositives.push(key);
    }
    expect(falsePositives).toEqual([]);
  });

  it('レポートのフィクスチャ（tests/fixtures/reports/*.json）に interstitial が無く、Markdown に注意が出ないこと（過去のレポートとの互換）', () => {
    const files = fs.readdirSync(REPORT_FIXTURES_DIR).filter((f) => f.endsWith('.json'));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const report = JSON.parse(
        fs.readFileSync(path.join(REPORT_FIXTURES_DIR, f), 'utf-8')
      ) as InspectionReport;
      expect(getInterstitial(report) == null).toBe(true);
      expect(generateMarkdownReport(report)).not.toContain(NOTICE_PHRASE);
    }
  });

  it('確認画面ではない普通のページでは interstitial が無く、完全性の理由にも確認画面が出ないこと', async () => {
    expectNoInterstitial(await inspectHtml(ORDINARY_PAGE, { headers: { server: ['nginx'] } }));
  });
});

describe('v1.8.0 T04: 判定の規則（印が 2 つ以上、またはベンダーのヘッダー 1 つ）', () => {
  describe('Fastly（ページ内の印）', () => {
    it('陰性: タイトル Client Challenge だけでは判定しないこと', async () => {
      expectNoInterstitial(
        await inspectHtml('<html><head><title>Client Challenge</title></head><body><p>x</p></body></html>')
      );
    });

    it('陰性: id="fastlyLogo" だけ（印 1 つ）では判定しないこと', async () => {
      expectNoInterstitial(
        await inspectHtml('<html><head><title>Status</title></head><body><img id="fastlyLogo" alt=""></body></html>')
      );
    });

    it('陰性: id="captchaTitle" だけ（印 1 つ）では判定しないこと', async () => {
      expectNoInterstitial(
        await inspectHtml('<html><head><title>Sign up</title></head><body><h2 id="captchaTitle">Type the characters</h2></body></html>')
      );
    });

    it('陽性: タイトル Client Challenge と id="fastlyLogo" の 2 つで Fastly と判定されること', async () => {
      const report = await inspectHtml(
        '<html><head><title>Client Challenge</title></head><body><img id="fastlyLogo" alt=""></body></html>'
      );
      const info = expectVendor(report, 'Fastly');
      expect(info.evidence.length).toBeGreaterThanOrEqual(2);
    });

    it('陽性: id="fastlyLogo" と id="captchaTitle" の 2 つで Fastly と判定されること', async () => {
      const report = await inspectHtml(
        '<html><head><title>Please wait</title></head><body><img id="fastlyLogo" alt=""><div id="captchaTitle">Type</div></body></html>'
      );
      const info = expectVendor(report, 'Fastly');
      expect(info.evidence.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Cloudflare', () => {
    it('陽性: ヘッダー cf-mitigated: challenge だけで Cloudflare と判定され、evidence にヘッダー名が出ること', async () => {
      const report = await inspectHtml(ORDINARY_PAGE, { headers: { 'cf-mitigated': ['challenge'] } });
      const info = expectVendor(report, 'Cloudflare');
      expect(info.evidence.some((e) => e.includes('cf-mitigated'))).toBe(true);
      expect(report.coverage?.overallStatus).toBe('partial');
      expect(generateMarkdownReport(report)).toContain(NOTICE_PHRASE);
    });

    it('陰性: cf-mitigated の値が challenge 以外なら判定しないこと（challenge が唯一の値と文書化されている）', async () => {
      expectNoInterstitial(await inspectHtml(ORDINARY_PAGE, { headers: { 'cf-mitigated': ['other'] } }));
    });

    it('陰性: ページ内の /cdn-cgi/challenge-platform/ だけ（印 1 つ。普通のページにも挿入される）では判定しないこと', async () => {
      const html =
        '<html><head><title>Shop</title><script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script></head><body><main>items</main></body></html>';
      expectNoInterstitial(
        await inspectHtml(html, {
          headers: { server: ['cloudflare'], 'cf-ray': ['0123456789abcdef-NRT'] },
          resourceTiming: [
            {
              name: 'https://site.example.test/cdn-cgi/challenge-platform/scripts/jsd/main.js',
              initiatorType: 'script',
            },
          ],
        })
      );
    });

    it('陰性: cf-mitigated: challenge のキャッシュが別の origin のもの（ヘッダー未観測扱い）なら判定しないこと', async () => {
      expectNoInterstitial(
        await inspectHtml(ORDINARY_PAGE, {
          headers: { 'cf-mitigated': ['challenge'] },
          cachedUrl: 'https://other.example.test/',
        })
      );
    });
  });

  describe('AWS WAF', () => {
    it.each(['captcha', 'challenge'])(
      '陽性: ヘッダー x-amzn-waf-action: %s だけで AWS WAF と判定され、evidence にヘッダー名が出ること',
      async (value) => {
        const report = await inspectHtml(ORDINARY_PAGE, { headers: { 'x-amzn-waf-action': [value] } });
        const info = expectVendor(report, 'AWS WAF');
        expect(info.evidence.some((e) => e.includes('x-amzn-waf-action'))).toBe(true);
      }
    );

    it('陰性: x-amzn-waf-action が無い AWS のレスポンス（x-amz-cf-id 等）では判定しないこと', async () => {
      expectNoInterstitial(
        await inspectHtml(ORDINARY_PAGE, {
          headers: { 'x-amz-cf-id': ['abc'], via: ['1.1 abc.cloudfront.net (CloudFront)'] },
        })
      );
    });
  });

  it('陰性: 別のベンダーの印を 1 つずつ足しても（Fastly のタイトル + Cloudflare のパス）判定しないこと', async () => {
    const html =
      '<html><head><title>Client Challenge</title><script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script></head><body><p>x</p></body></html>';
    expectNoInterstitial(await inspectHtml(html));
  });
});

describe('v1.8.0 T04: 取得するヘッダー（G5）', () => {
  it('cf-mitigated と x-amzn-waf-action が取得するヘッダーの許可リストに入っていること', () => {
    expect(ALLOWED_RESPONSE_HEADERS.has('cf-mitigated')).toBe(true);
    expect(ALLOWED_RESPONSE_HEADERS.has('x-amzn-waf-action')).toBe(true);
  });

  it('filterAndSanitizeHeaders が 2 つのヘッダーを残し、許可されないヘッダー（set-cookie）は捨てること', () => {
    const filtered = filterAndSanitizeHeaders([
      { name: 'CF-Mitigated', value: 'challenge' },
      { name: 'X-Amzn-Waf-Action', value: 'captcha' },
      { name: 'Set-Cookie', value: 'sid=secret' },
    ]);
    expect(filtered['cf-mitigated']).toEqual(['challenge']);
    expect(filtered['x-amzn-waf-action']).toEqual(['captcha']);
    expect(filtered['set-cookie']).toBeUndefined();
  });
});

describe('v1.8.0 T04: ポップアップの注意（src/popup/render.ts の renderInterstitialNoticeHtml）', () => {
  type RenderFn = (info: InterstitialLike | null | undefined) => string;
  const getRender = (): RenderFn =>
    (popupRender as unknown as { renderInterstitialNoticeHtml: RenderFn }).renderInterstitialNoticeHtml;

  it('陽性: 確認画面のときは、ベンダー名・G6 の文言・「不完全」を含む HTML を返すこと', () => {
    const html = getRender()({ vendor: 'Fastly', evidence: ['title: Client Challenge', 'id="fastlyLogo"'] });
    expect(html).toContain(NOTICE_PHRASE);
    expect(html).toContain(INCOMPLETE_WORD);
    expect(html).toContain('Fastly');
  });

  it('陰性: interstitial が無いときは空文字を返すこと', () => {
    expect(getRender()(undefined)).toBe('');
    expect(getRender()(null)).toBe('');
  });

  it('ページ由来の値はエスケープされ、インラインイベントハンドラが出ないこと', () => {
    const html = getRender()({
      vendor: 'Fastly',
      evidence: ['title: <img src=x onerror=alert(1)>', '<script>alert(1)</script>'],
    });
    expect(html).not.toContain('<img');
    expect(html).not.toContain('<script');
    const container = document.createElement('div');
    container.innerHTML = html;
    expect(container.querySelectorAll('img, script').length).toBe(0);
    for (const el of Array.from(container.querySelectorAll('*'))) {
      for (const attr of Array.from(el.attributes)) {
        expect(attr.name.toLowerCase().startsWith('on')).toBe(false);
      }
    }
  });

  it('popup.ts が renderInterstitialNoticeHtml を使って注意を表示すること', () => {
    const src = fs.readFileSync(path.resolve(__dirname, '..', 'src', 'popup', 'popup.ts'), 'utf-8');
    expect(src).toMatch(/renderInterstitialNoticeHtml\s*\(/);
  });
});
