// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * v1.6.5 レビュー指摘の受け入れテスト (tests/review-v1.6.5-acceptance.test.ts)
 *
 * 各テストは docs/REVIEW_v1.6.5.md の指摘IDに対応する。現状 (v1.6.5) の実装では失敗するため it.skip としている。
 * 開発担当は該当指摘を修正したら、対応するテストの .skip を外して緑になることを確認すること。
 * (期待値はレビューで合意した仕様。仕様を変える場合はレビュー文書とセットで更新する)
 */

import { describe, expect, it } from 'vitest';
import { executeInspection } from '../src/background/service-worker';
import { extractDomSignals } from '../src/content/content-script';
import { matchOfflineAdvisories } from '../src/detection/advisory';
import { DetectionEngine } from '../src/detection/engine';
import { analyzeCSPPolicies, parseCSPPolicy } from '../src/security/csp-parser';
import { checkHttpHeaders } from '../src/security/headers';
import { DomSignals, NetworkSignals } from '../src/shared/types';

const emptyDom = (): DomSignals => ({
  url: 'https://example.com/',
  title: 'x',
  metaTags: [],
  scriptUrls: [],
  linkUrls: [],
  domMarkers: [],
  htmlSnippets: [],
  mixedContent: [],
  cookiesFromDocument: [],
  cssAssets: [],
});
const net = (headers: Record<string, string[]>): NetworkSignals => ({ url: 'https://example.com/', responseHeaders: headers, cookies: [] });
const engine = new DetectionEngine();
const techNames = (dom: DomSignals, network?: NetworkSignals, runtimeVersions?: Record<string, string | null>) =>
  engine.detect({ url: dom.url, dom, network, runtimeVersions }).map((t) => t.technology);

describe('SPEC-01: ヘッダー未観測時はヘッダー依存の診断を「未観測」とし要確認件数に含めない', () => {
  it('headers 未取得 (getCachedHeaders = undefined) のとき HSTS/CSP/XFO 等は warning にならない', async () => {
    const report = await executeInspection({
      tab: { id: 1, url: 'https://example.com/' },
      fetchDomSignals: async () => ({ ...emptyDom(), title: 't' }),
      fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
      getCachedHeaders: async () => undefined,
      getInspectedCookies: async () => [],
      getAllFindingExceptions: async () => [],
    });
    const headerChecks = report.securityChecks.filter((c) => /^SEC-(HSTS|CSP|XFO|XCTO|REF|PERM)/.test(c.checkId));
    expect(headerChecks.every((c) => c.status === 'unknown' || c.status === 'info')).toBe(true);
    expect(report.summary.requiresAttentionCount).toBe(0);
  });
});

describe('SPEC-02: Linux ディストリビューション版のバックポート考慮', () => {
  it('Server: Apache/2.4.41 (Ubuntu) / X-Powered-By: PHP/7.4.3-4ubuntu2.19 は Potentially Affected と断定しない', () => {
    const r = engine.detect({ url: 'https://e.com/', dom: emptyDom(), network: net({ server: ['Apache/2.4.41 (Ubuntu)'], 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] }) });
    for (const name of ['Apache', 'PHP']) {
      const t = r.find((x) => x.technology === name)!;
      expect(t.advisoryMatchStatus).toBe('Needs Review');
    }
  });
});

describe('SPEC-04: EOL 判定で未知の旧サイクルを Supported としない', () => {
  it.each([
    ['Angular', '8.2.14'],
    ['Laravel', '5.4.36'],
    ['Nginx', '0.8.55'],
    ['PHP', '4.4.9'],
    ['Node.js', '0.12.18'],
    ['Bootstrap', '1.4.0'],
  ])('%s %s は Supported ではない (EOL もしくは Unknown)', (tech, version) => {
    expect(matchOfflineAdvisories(tech, version).eolInfo.status).not.toBe('Supported');
  });
});

describe('SPEC-06: 解析不能なバージョン文字列で CVE を該当させない', () => {
  it('jQuery "custom-build" は Unknown Version / Needs Review', () => {
    const r = matchOfflineAdvisories('jQuery', 'custom-build');
    expect(r.advisories).toHaveLength(0);
    expect(r.offlineMatchStatus).toBe('Unknown Version');
  });
});

describe('SPEC-07 / SPEC-08: CSP 評価', () => {
  it.skip('複数の強制ポリシーは積集合で評価する (片方が厳格なら unsafe-inline を high にしない)', () => {
    const p1 = parseCSPPolicy("script-src 'self' 'unsafe-inline'", 'response-header', 'enforce');
    const p2 = parseCSPPolicy("script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", 'response-header', 'enforce');
    const { results } = analyzeCSPPolicies([p1, p2], 'https://e.com/');
    expect(results.find((c) => c.checkId.startsWith('SEC-CSP'))?.severity).not.toBe('high');
  });

  it.skip('scheme-source (https:) は任意ホスト許可として検出する', () => {
    const p = parseCSPPolicy("script-src https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", 'response-header', 'enforce');
    expect(analyzeCSPPolicies([p], 'https://e.com/').issues.map((i) => i.id)).toContain('CSP-SCRIPT-WILDCARD');
  });

  it.skip('nonce + strict-dynamic の堅牢な CSP は PASS (info 注記で warning にしない)', () => {
    const p = parseCSPPolicy("script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", 'response-header', 'enforce');
    expect(analyzeCSPPolicies([p], 'https://e.com/').results[0].status).toBe('pass');
  });
});

describe('SPEC-09: 誤検知の抑制', () => {
  it('Bootstrap のユーティリティクラス (d-flex justify-content-between) を Tailwind と判定しない', () => {
    expect(techNames({ ...emptyDom(), htmlSnippets: ['d-flex justify-content-between align-items-center'] })).not.toContain('Tailwind CSS');
  });
  it('テーマの small.css / all.css を Font Awesome と判定しない', () => {
    expect(techNames({ ...emptyDom(), linkUrls: [{ rel: 'stylesheet', href: '/themes/t/css/small.css' }] })).not.toContain('Font Awesome');
  });
  it('orgchart.js / md3.js を Chart.js / D3.js と判定しない', () => {
    const names = techNames({ ...emptyDom(), scriptUrls: ['/js/orgchart.js', '/static/md3.js'] });
    expect(names).not.toContain('Chart.js');
    expect(names).not.toContain('D3.js');
  });
  it('X-Powered-By: Phusion Passenger 単独で Ruby on Rails を高確信度にしない', () => {
    const r = engine.detect({ url: 'https://e.com/', dom: emptyDom(), network: net({ 'x-powered-by': ['Phusion Passenger(R) 6.0.17'] }) });
    expect(r.find((t) => t.technology === 'Ruby on Rails')?.confidenceLevel ?? 'low').not.toBe('high');
  });
});

describe('SPEC-10: 同一ライブラリの複数バージョン同居', () => {
  it.skip('jquery-1.12.4 と 3.7.1 が同居する場合、1.12.4 の CVE も報告する', () => {
    const r = engine.detect({ url: 'https://e.com/', dom: { ...emptyDom(), scriptUrls: ['/js/jquery-1.12.4.min.js', '/js/jquery-3.7.1.min.js'] }, runtimeVersions: { jquery: '3.7.1' } });
    const ids = r.filter((t) => t.technology === 'jQuery').flatMap((t) => (t.advisories || []).map((a) => a.id));
    expect(ids).toContain('CVE-2020-11022');
  });
});

describe('SPEC-12: ヘッダー値の妥当性', () => {
  it.skip('X-Frame-Options: ALLOWALL は PASS にしない / HSTS max-age=0 は medium 以上', () => {
    const r = checkHttpHeaders({ 'x-frame-options': ['ALLOWALL'], 'strict-transport-security': ['max-age=0'] }, 'https://e.com/', true);
    expect(r.find((c) => c.checkId.startsWith('SEC-XFO'))?.status).not.toBe('pass');
    expect(['medium', 'high']).toContain(r.find((c) => c.checkId.startsWith('SEC-HSTS'))?.severity);
  });
});

describe('DOC-01: 仕様書に記載された DOM シグナルが実際に発火する', () => {
  it.each([
    ['Alpine.js', '<div x-data="{o:false}"></div>'],
    ['htmx', '<button hx-get="/a">x</button>'],
    ['Material UI', '<div class="MuiButton-root"></div>'],
    ['Spring Security', '<form><input name="_csrf" value="x"></form>'],
    ['Ruby on Rails', '<meta name="csrf-param" content="authenticity_token">'],
  ])('%s', (tech, html) => {
    document.head.innerHTML = '';
    document.body.innerHTML = html;
    if (html.startsWith('<meta')) document.head.innerHTML = html;
    const dom = extractDomSignals();
    expect(techNames(dom)).toContain(tech);
  });
});

describe('DOC-02: Lodash / Moment.js の検出', () => {
  it('実行時バージョン (window._.VERSION / window.moment.version) から検出し CVE 照合する', () => {
    const r = engine.detect({ url: 'https://e.com/', dom: emptyDom(), runtimeVersions: { lodash: '4.17.15', moment: '2.29.1' } });
    expect(r.map((t) => t.technology)).toEqual(expect.arrayContaining(['Lodash', 'Moment.js']));
    expect(r.find((t) => t.technology === 'Lodash')?.advisoryMatchStatus).toBe('Potentially Affected');
  });
});
