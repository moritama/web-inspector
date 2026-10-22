/**
 * Web Technology & Security Inspector
 * CSPディレクティブ構文解析・診断エンジン単体テスト (tests/csp-parser.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { analyzeCSPHeader, evaluateCSPDirectives, parseCSP } from '../src/security/csp-parser';

describe('CSP構文解析・ディレクティブ診断テスト (IMP-02)', () => {
  it('セミコロン区切り・空白混在のCSPが正常にディレクティブ辞書にパースされること', () => {
    const rawCsp =
      "  default-src 'self' ;  script-src 'self' https://cdn.example.com 'unsafe-inline'  ; style-src 'self' 'unsafe-inline';  ";
    const parsed = parseCSP(rawCsp);

    expect(parsed['default-src']).toEqual(["'self'"]);
    expect(parsed['script-src']).toEqual(["'self'", 'https://cdn.example.com', "'unsafe-inline'"]);
    expect(parsed['style-src']).toEqual(["'self'", "'unsafe-inline'"]);
  });

  it("script-src に 'unsafe-inline' がある場合にHighリスクを返却すること", () => {
    const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    const inlineIssue = issues.find((i) => i.id === 'CSP-SCRIPT-UNSAFE-INLINE');
    expect(inlineIssue).toBeDefined();
    expect(inlineIssue?.severity).toBe('high');
    expect(inlineIssue?.directive).toBe('script-src');
  });

  it('script-src が未定義で default-src の設定がフォールバックとして評価されること', () => {
    // script-srcがなく、default-srcに 'unsafe-inline' が含まれる場合
    const csp = "default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    const fallbackIssue = issues.find((i) => i.id === 'CSP-SCRIPT-UNSAFE-INLINE');
    expect(fallbackIssue).toBeDefined();
    expect(fallbackIssue?.severity).toBe('high');
    expect(fallbackIssue?.directive).toContain('default-src');
  });

  it('script-src にワイルドカード(*) や data: スキームがある場合にHighリスクとして検出されること', () => {
    const csp = "script-src * data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    expect(issues.some((i) => i.id === 'CSP-SCRIPT-WILDCARD')).toBe(true);
    expect(issues.some((i) => i.id === 'CSP-SCRIPT-DATA-SCHEME')).toBe(true);
  });

  it("object-src が未指定かつ default-src が 'none' でない場合に警告されること", () => {
    const csp = "default-src 'self'; script-src 'self'; base-uri 'self'; frame-ancestors 'none';";
    const parsed = parseCSP(csp);
    const issues = evaluateCSPDirectives(parsed, false);

    const objIssue = issues.find((i) => i.id === 'CSP-OBJECT-SRC-NOT-NONE' || i.id === 'CSP-OBJECT-SRC-MISSING');
    expect(objIssue).toBeDefined();
    expect(objIssue?.severity).toBe('medium');
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
