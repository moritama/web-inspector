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
  parseCSPPolicy,
} from '../src/security/csp-parser';

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
});
