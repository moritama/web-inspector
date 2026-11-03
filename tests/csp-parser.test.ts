// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * CSPディレクティブ構文解析・診断エンジン単体テスト (tests/csp-parser.test.ts) - IMP-02 & IMP-05 (Rev.2.1)
 */

import { describe, expect, it } from 'vitest';
import {
  analyzeCSPHeader,
  analyzeCSPPolicies,
  evaluateCSPDirectives,
  parseCSP,
  parseCSPHeaderValues,
  parseCSPPolicy,
} from '../src/security/csp-parser';
import { checkHttpHeaders } from '../src/security/headers';
import { executeInspection } from '../src/background/service-worker';
import { extractDomSignals } from '../src/content/content-script';
import { DomSignals } from '../src/shared/types';

describe('CSP構文解析・ディレクティブ診断テスト (IMP-02 & IMP-05)', () => {
  it('セミコロン区切り・空白混在のCSPが正常にディレクティブ辞書にパースされること', () => {
    const rawCsp =
      "  default-src 'self' ;  script-src 'self' https://cdn.example.com 'unsafe-inline'  ; style-src 'self' 'unsafe-inline';  ";
    const parsed = parseCSP(rawCsp);

    expect(parsed['default-src']).toEqual(["'self'"]);
    expect(parsed['script-src']).toEqual(["'self'", 'https://cdn.example.com', "'unsafe-inline'"]);
    expect(parsed['style-src']).toEqual(["'self'", "'unsafe-inline'"]);
  });

  // --- Rev.2.1 P11〜P14: meta CSP の解析と制限 ---
  it('P11: meta CSPが正常にパースされ、source: meta として認識されること', () => {
    const policy = parseCSPPolicy("default-src 'self'; script-src 'self';", 'meta', 'enforce');
    expect(policy.source).toBe('meta');
    expect(policy.mode).toBe('enforce');
    expect(policy.directives['default-src']).toEqual(["'self'"]);
  });

  it('P12 & P13 & P14: meta CSPで無効なディレクティブ（frame-ancestors, sandbox, report-uri）が検出されること', () => {
    const rawCsp = "default-src 'self'; frame-ancestors 'none'; sandbox allow-scripts; report-uri /csp-report;";
    const policy = parseCSPPolicy(rawCsp, 'meta', 'enforce');
    const { issues } = analyzeCSPPolicies([policy], 'https://example.com');

    // meta内無効ディレクティブの警告
    const invalidMetaIssues = issues.filter((i) => i.id.includes('META-INVALID'));
    expect(invalidMetaIssues.length).toBeGreaterThanOrEqual(2);

    const patterns = invalidMetaIssues.map((i) => i.pattern);
    expect(patterns).toContain('frame-ancestors');
    expect(patterns).toContain('sandbox');
  });

  // --- Rev.2.1 P15: 複数CSPポリシーの独立保持 ---
  it('P15: 複数のCSPヘッダー・ポリシーが単一辞書にマージされず個別に保持されること', () => {
    const policy1 = parseCSPPolicy("default-src 'self';", 'response-header', 'enforce');
    const policy2 = parseCSPPolicy("script-src 'self' https://trusted.cdn.com;", 'response-header', 'enforce');

    const { policies } = analyzeCSPPolicies([policy1, policy2], 'https://example.com');
    expect(policies.length).toBe(2);
    expect(policies[0].directives['default-src']).toBeDefined();
    expect(policies[1].directives['script-src']).toBeDefined();
  });

  // --- Rev.2.1 P16: nonce/hash と unsafe-inline の実効性評価 ---
  it('P16: nonce または sha256 が存在する場合、unsafe-inline の実効的無効化を考慮しHigh警告を抑制すること', () => {
    const cspWithNonce =
      "default-src 'self'; script-src 'self' 'nonce-random123' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const policy = parseCSPPolicy(cspWithNonce, 'response-header', 'enforce');
    const { issues } = analyzeCSPPolicies([policy], 'https://example.com');

    const inlineIssue = issues.find((i) => i.id === 'CSP-SCRIPT-UNSAFE-INLINE');
    // nonceが存在するため、実効的にはunsafe-inlineは無視される -> 重大度は抑制されMedium以下、または実効性注記
    if (inlineIssue) {
      expect(inlineIssue.severity).not.toBe('high');
      expect(inlineIssue.description).toContain('実効的');
    }
  });

  // --- Rev.2.1 P17: strict-dynamic の解析 ---
  it('P17: strict-dynamic が指定されている場合、ホワイトリスト無効化の挙動が考慮されること', () => {
    const cspStrict =
      "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic' https://example.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const policy = parseCSPPolicy(cspStrict, 'response-header', 'enforce');
    const { issues } = analyzeCSPPolicies([policy], 'https://example.com');

    // strict-dynamic 存在下では https://example.com などのホスト指定は無視されるため不要な設定として指摘または情報
    const strictNote = issues.find((i) => i.id.includes('STRICT-DYNAMIC') || i.description.includes('strict-dynamic'));
    expect(strictNote).toBeDefined();
  });

  // --- Rev.2.1 P18: object-src の default-src フォールバック ---
  it("P18: object-src が未指定でも default-src が 'none' であれば合格と評価されること", () => {
    const csp = "default-src 'none'; script-src 'self'; base-uri 'self'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    const objIssue = issues.find((i) => i.id.includes('OBJECT-SRC'));
    expect(objIssue).toBeUndefined();
  });

  // --- Rev.2.1 P19: base-uri は default-src にフォールバックしない ---
  it('P19: default-src が定義されていても base-uri が未指定なら独立ルールとして検出されること', () => {
    const csp = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    const baseIssue = issues.find((i) => i.id === 'CSP-BASE-URI-MISSING');
    expect(baseIssue).toBeDefined();
  });

  // --- Rev.2.1 P20: Report-Only の区別 ---
  it('P20: Report-Only ポリシーが enforce と分離して扱われること', () => {
    const policy = parseCSPPolicy("default-src 'self';", 'response-header', 'report-only');
    expect(policy.mode).toBe('report-only');

    const { results } = analyzeCSPPolicies([policy], 'https://example.com');
    const check = results.find((r) => r.checkId === 'SEC-CSP-02');
    expect(check).toBeDefined();
    expect(check?.status).toBe('info');
  });

  // --- Rev.2.1 P21: 重複ディレクティブのブラウザ仕様準拠評価 ---
  it('P21: 同一ポリシー内に重複ディレクティブがある場合、最初の定義が優先されること', () => {
    // script-src 'self'; script-src 'unsafe-inline' -> ブラウザは最初の 'self' のみを有効とする
    const cspDuplicate = "default-src 'self'; script-src 'self'; script-src 'unsafe-inline'; object-src 'none';";
    const policy = parseCSPPolicy(cspDuplicate, 'response-header', 'enforce');

    expect(policy.directives['script-src']).toEqual(["'self'"]);
    expect(policy.warnings.some((w) => w.includes('重複'))).toBe(true);
  });

  it("script-src に 'unsafe-inline' のみがある場合にHighリスクを返却すること", () => {
    const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    const inlineIssue = issues.find((i) => i.id === 'CSP-SCRIPT-UNSAFE-INLINE');
    expect(inlineIssue).toBeDefined();
    expect(inlineIssue?.severity).toBe('high');
    expect(inlineIssue?.directive).toBe('script-src');
  });

  it('script-src にワイルドカード(*) や data: スキームがある場合にHighリスクとして検出されること', () => {
    const csp = "script-src * data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    expect(issues.some((i) => i.id === 'CSP-SCRIPT-WILDCARD')).toBe(true);
    expect(issues.some((i) => i.id === 'CSP-SCRIPT-DATA-SCHEME')).toBe(true);
  });

  it('堅牢で完全なCSPポリシーが設定されている場合、PASS (SEC-CSP-00) を返却すること', () => {
    const strongCsp =
      "default-src 'self'; script-src 'self' 'nonce-rAnd0m'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const results = analyzeCSPHeader(strongCsp, 'https://example.com', true);

    expect(results.length).toBe(1);
    expect(results[0].status).toBe('pass');
    expect(results[0].checkId).toBe('SEC-CSP-00');
  });

  // --- v1.7.0 T06 (SPEC-07, SPEC-08): 積集合評価・ヘッダー分割・任意ホスト・meta Report-Only ---
  it("T06: 'unsafe-inline' ポリシーと nonce+strict-dynamic ポリシーを (a) 2ヘッダー行、(b) 1行カンマ区切りで送っても headers.ts と SW の両方で同じ判定になること", async () => {
    const policyLoose = "default-src 'self'; script-src 'self' 'unsafe-inline'";
    const policyStrict =
      "script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

    const twoHeaderLines = [policyLoose, policyStrict];
    const commaJoinedLine = [`${policyLoose}, ${policyStrict}`];

    // 1. headers.ts (checkHttpHeaders) 経由の検証
    const resHeadersTwo = checkHttpHeaders(
      { 'content-security-policy': twoHeaderLines },
      'https://example.com/',
      true
    );
    const resHeadersComma = checkHttpHeaders(
      { 'content-security-policy': commaJoinedLine },
      'https://example.com/',
      true
    );
    const cspCheckHeadersTwo = resHeadersTwo.filter((c) => c.checkId.startsWith('SEC-CSP-'));
    const cspCheckHeadersComma = resHeadersComma.filter((c) => c.checkId.startsWith('SEC-CSP-'));

    expect(cspCheckHeadersTwo).toHaveLength(1);
    expect(cspCheckHeadersComma).toHaveLength(1);
    expect(cspCheckHeadersTwo[0].checkId).toBe('SEC-CSP-00');
    expect(cspCheckHeadersTwo[0].status).toBe('pass');
    expect(cspCheckHeadersComma[0]).toEqual(cspCheckHeadersTwo[0]);

    // 2. Service Worker (executeInspection) 経由の検証
    const emptyDom: DomSignals = {
      url: 'https://example.com/',
      title: 'Test',
      metaTags: [],
      scriptUrls: [],
      linkUrls: [],
      domMarkers: [],
      htmlSnippets: [],
      mixedContent: [],
      cookiesFromDocument: [],
      cssAssets: [],
      metaCsp: [],
      metaCspReportOnly: [],
    };

    const swReportTwo = await executeInspection({
      tab: { id: 1, url: 'https://example.com/' },
      fetchDomSignals: async () => emptyDom,
      fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
      getCachedHeaders: async () => ({
        url: 'https://example.com/',
        headers: { 'content-security-policy': twoHeaderLines },
        observed: true,
      }),
      getInspectedCookies: async () => [],
      getAllFindingExceptions: async () => [],
    });

    const swReportComma = await executeInspection({
      tab: { id: 1, url: 'https://example.com/' },
      fetchDomSignals: async () => emptyDom,
      fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
      getCachedHeaders: async () => ({
        url: 'https://example.com/',
        headers: { 'content-security-policy': commaJoinedLine },
        observed: true,
      }),
      getInspectedCookies: async () => [],
      getAllFindingExceptions: async () => [],
    });

    const swCspTwo = swReportTwo.securityChecks.filter((c) => c.checkId.startsWith('SEC-CSP-'));
    const swCspComma = swReportComma.securityChecks.filter((c) => c.checkId.startsWith('SEC-CSP-'));

    expect(swReportTwo.cspPolicies).toHaveLength(2);
    expect(swReportComma.cspPolicies).toHaveLength(2);
    expect(swCspTwo).toHaveLength(1);
    expect(swCspComma).toHaveLength(1);
    expect(swCspTwo[0].checkId).toBe('SEC-CSP-00');
    expect(swCspTwo[0].status).toBe('pass');
    expect(swCspComma[0]).toEqual(swCspTwo[0]);
  });

  it("T06: script-src 'self' *.cdn.example は medium、script-src https: は high として検出されること", () => {
    const subdomainPolicy = parseCSPPolicy(
      "script-src 'self' *.cdn.example; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      'response-header',
      'enforce'
    );
    const subEval = analyzeCSPPolicies([subdomainPolicy], 'https://example.com/');
    const subIssue = subEval.issues.find((i) => i.id === 'CSP-SCRIPT-WILDCARD');
    expect(subIssue).toBeDefined();
    expect(subIssue?.severity).toBe('medium');
    expect(subEval.results[0].checkId).toBe('SEC-CSP-03');
    expect(subEval.results[0].severity).toBe('medium');

    const httpsPolicy = parseCSPPolicy(
      "script-src https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      'response-header',
      'enforce'
    );
    const httpsEval = analyzeCSPPolicies([httpsPolicy], 'https://example.com/');
    const httpsIssue = httpsEval.issues.find((i) => i.id === 'CSP-SCRIPT-WILDCARD');
    expect(httpsIssue).toBeDefined();
    expect(httpsIssue?.severity).toBe('high');
    expect(httpsEval.results[0].checkId).toBe('SEC-CSP-03');
    expect(httpsEval.results[0].severity).toBe('high');
  });

  it("T06: nonce・hash と 'strict-dynamic' がある場合はホスト許可 (*, https:, *.example.com) と 'unsafe-inline' が無視され警告にならないこと", () => {
    const p = parseCSPPolicy(
      "script-src 'nonce-xyz987' 'strict-dynamic' https: * *.cdn.example 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      'response-header',
      'enforce'
    );
    const { issues, results } = analyzeCSPPolicies([p], 'https://example.com/');

    expect(issues.find((i) => i.id === 'CSP-SCRIPT-WILDCARD')).toBeUndefined();
    expect(issues.filter((i) => i.severity !== 'info')).toHaveLength(0);
    expect(results).toHaveLength(1);
    expect(results[0].checkId).toBe('SEC-CSP-00');
    expect(results[0].status).toBe('pass');
  });

  it('T06: 能力単位の積集合評価で eval / object-src / base-uri / frame-ancestors が片方のポリシーで遮断されていれば防御済みと判定されること', () => {
    const p1 = parseCSPHeaderValues(
      "script-src 'self' 'unsafe-eval', script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      'response-header',
      'enforce'
    );
    const { issues, results } = analyzeCSPPolicies(p1, 'https://example.com/');

    expect(issues.filter((i) => i.severity !== 'info')).toHaveLength(0);
    expect(results[0].checkId).toBe('SEC-CSP-00');
    expect(results[0].status).toBe('pass');
  });

  it('T06: meta の Report-Only だけがあるページでは CSP は「未設定」扱いになり、info の注記が 1 件出ること', async () => {
    // 1. analyzeCSPPolicies 直接呼び出しでの検証
    const metaRoPolicy = parseCSPPolicy("default-src 'self'", 'meta', 'report-only');
    const { results } = analyzeCSPPolicies([metaRoPolicy], 'https://example.com/');

    const missingCheck = results.find((r) => r.checkId === 'SEC-CSP-01');
    const infoNotes = results.filter((r) => r.status === 'info' && r.severity === 'info');

    expect(missingCheck).toBeDefined();
    expect(missingCheck?.status).toBe('warning');
    expect(missingCheck?.observed).toContain('未設定');
    expect(infoNotes).toHaveLength(1);
    expect(infoNotes[0].checkId).toBe('SEC-CSP-META-RO');

    // 2. DOM 抽出 (extractDomSignals) + Service Worker (executeInspection) 経由での検証
    document.head.innerHTML =
      '<meta http-equiv="Content-Security-Policy-Report-Only" content="default-src \'self\'">';
    document.body.innerHTML = '';
    const dom = extractDomSignals();

    expect(dom.metaCsp).toEqual([]);
    expect(dom.metaCspReportOnly).toEqual(["default-src 'self'"]);

    const report = await executeInspection({
      tab: { id: 1, url: 'https://example.com/' },
      fetchDomSignals: async () => dom,
      fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
      getCachedHeaders: async () => ({
        url: 'https://example.com/',
        headers: { 'strict-transport-security': ['max-age=31536000'] },
        observed: true,
      }),
      getInspectedCookies: async () => [],
      getAllFindingExceptions: async () => [],
    });

    const cspChecks = report.securityChecks.filter((c) => c.checkId.startsWith('SEC-CSP-'));
    const swMissing = cspChecks.find((c) => c.checkId === 'SEC-CSP-01');
    const swInfoNotes = cspChecks.filter((c) => c.status === 'info' && c.severity === 'info');

    expect(swMissing).toBeDefined();
    expect(swMissing?.status).toBe('warning');
    expect(swInfoNotes).toHaveLength(1);
    expect(swInfoNotes[0].checkId).toBe('SEC-CSP-META-RO');
  });
});
