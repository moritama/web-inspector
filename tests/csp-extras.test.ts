/**
 * Web Technology & Security Inspector
 * v1.8.0 T07 NEW-03b: CSP の追加項目の受け入れテスト (tests/csp-extras.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.0/design/T07.md
 *
 * - SEC-CSPX-TT-01（Trusted Types）/ SEC-CSPX-UIR-01（upgrade-insecure-requests）/
 *   SEC-CSPX-FORM-01（form-action）/ SEC-CSPX-REPORT-01（report-to のグループ）
 * - 表の 4 項目それぞれに、単一ポリシー・複数ポリシー・meta のケース（陽性と陰性）を置く
 * - 複数の CSP は積集合の評価に合わせる（どれか 1 つの強制ポリシーが指定していれば「ある」）
 * - meta の CSP では report-to が無効、という既存の扱いを崩さない
 * - CSP の問題点の表（Markdown 第 8 節）にも同じ表現で出す
 * - csp-parser.ts の差分は 30 行以内、csp-parser.test.ts は変えない
 */

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  ALLOWED_RESPONSE_HEADERS,
  executeInspection,
  filterAndSanitizeHeaders,
  HEADER_DEPENDENT_CHECK_PREFIXES,
} from '../src/background/service-worker';
import { escapeMarkdownTableCell, generateMarkdownReport } from '../src/export/markdown';
import { checkCspExtras, CspExtrasContext, evaluateCspExtraIssues } from '../src/security/csp-extras';
import {
  analyzeCSPPolicies,
  CSPIssue,
  evaluatePolicyIssuesWithIntersection,
  parseCSPHeaderValues,
} from '../src/security/csp-parser';
import { isRequiresAttention } from '../src/shared/security-status';
import { CSPPolicy, DomSignals, InspectionReport, MixedContentItem, SecurityCheckResult } from '../src/shared/types';
// @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
import { lintReportPair as rawLintReportPair } from '../scripts/report-lint.mjs';

const lintReportPair = rawLintReportPair as (
  report: unknown,
  markdown: string,
  options?: { includePending?: boolean }
) => { ok: boolean; violations: unknown[] };

const REPO_ROOT = path.resolve(__dirname, '..');
const URL_HTTPS = 'https://csp-extras.example.test/';

/** 指示書 T07 の表（項目 → チェック ID / status / 重大度、問題点の表の指摘 ID / ディレクティブ） */
const ITEMS = {
  tt: {
    checkId: 'SEC-CSPX-TT-01',
    status: 'info',
    severity: 'info',
    issueId: 'CSP-TRUSTED-TYPES-MISSING',
    directive: 'require-trusted-types-for',
  },
  uir: {
    checkId: 'SEC-CSPX-UIR-01',
    status: 'info',
    severity: 'info',
    issueId: 'CSP-UPGRADE-INSECURE-REQUESTS-MISSING',
    directive: 'upgrade-insecure-requests',
  },
  form: {
    checkId: 'SEC-CSPX-FORM-01',
    status: 'warning',
    severity: 'low',
    issueId: 'CSP-FORM-ACTION-MISSING',
    directive: 'form-action',
  },
  report: {
    checkId: 'SEC-CSPX-REPORT-01',
    status: 'info',
    severity: 'info',
    issueId: 'CSP-REPORT-TO-UNDEFINED-GROUP',
    directive: 'report-to',
  },
} as const;
type ItemKey = keyof typeof ITEMS;
const ITEM_KEYS = Object.keys(ITEMS) as ItemKey[];
const NEW_CHECK_IDS: readonly string[] = ITEM_KEYS.map((k) => ITEMS[k].checkId);
const NEW_ISSUE_IDS: readonly string[] = ITEM_KEYS.map((k) => ITEMS[k].issueId);

// ---------------------------------------------------------------------------
// 入力を作る補助
// ---------------------------------------------------------------------------

const H = (v: string): CSPPolicy[] => parseCSPHeaderValues(v, 'response-header', 'enforce');
const RO = (v: string): CSPPolicy[] => parseCSPHeaderValues(v, 'response-header', 'report-only');
const M = (v: string): CSPPolicy[] => parseCSPHeaderValues(v, 'meta', 'enforce');
const MRO = (v: string): CSPPolicy[] => parseCSPHeaderValues(v, 'meta', 'report-only');

const RE_DEFINES_CSP_ENDPOINT = 'csp-endpoint="https://reports.example.test/csp"';

const ctx = (o: Partial<CspExtrasContext> = {}): CspExtrasContext => ({
  mixedContentDetected: false,
  reportingEndpoints: [],
  ...o,
});

const run = (policies: CSPPolicy[], c: CspExtrasContext = ctx()): SecurityCheckResult[] =>
  checkCspExtras(policies, URL_HTTPS, c);

const byId = (checks: SecurityCheckResult[], id: string): SecurityCheckResult[] =>
  checks.filter((c) => c.checkId === id);

/** 表の status / 重大度どおりに 1 件だけ出ることを確かめる */
function expectFires(checks: SecurityCheckResult[], key: ItemKey): SecurityCheckResult {
  const item = ITEMS[key];
  const found = byId(checks, item.checkId);
  expect(found.length, `${item.checkId} が 1 件ではありません`).toBe(1);
  expect(found[0].status).toBe(item.status);
  expect(found[0].severity).toBe(item.severity);
  expect(found[0].category).toBe('http-headers');
  expect(found[0].scope).toBe(URL_HTTPS);
  expect(found[0].name.length).toBeGreaterThan(0);
  expect(found[0].observed.length).toBeGreaterThan(0);
  expect(found[0].description.length).toBeGreaterThan(0);
  expect(found[0].recommendation.length).toBeGreaterThan(0);
  return found[0];
}

function expectSilent(checks: SecurityCheckResult[], key: ItemKey): void {
  const item = ITEMS[key];
  expect(byId(checks, item.checkId), `${item.checkId} が出ています`).toHaveLength(0);
}

const issueIds = (issues: CSPIssue[]): string[] => issues.map((i) => i.id);

// ---------------------------------------------------------------------------
// Trusted Types: 強制の CSP があり、require-trusted-types-for 'script' がない（info）
// ---------------------------------------------------------------------------

describe("v1.8.0 T07: SEC-CSPX-TT-01 — 強制の CSP に require-trusted-types-for 'script' がない", () => {
  describe('単一ポリシー', () => {
    it.each([
      "default-src 'self'",
      "default-src 'self'; trusted-types default",
      "default-src 'self'; require-trusted-types-for",
    ])('陽性: %j のとき info / info で出る', (csp) => {
      expectFires(run(H(csp)), 'tt');
    });

    it.each([
      "default-src 'self'; require-trusted-types-for 'script'",
      "default-src 'self'; trusted-types default; require-trusted-types-for 'script'",
      "default-src 'self'; Require-Trusted-Types-For 'script'",
    ])('陰性: %j のとき出ない', (csp) => {
      expectSilent(run(H(csp)), 'tt');
    });

    it('陰性: 強制の CSP がない（ポリシーなし / Report-Only だけ）ときは出ない', () => {
      expectSilent(run([]), 'tt');
      expectSilent(run(RO("default-src 'self'")), 'tt');
    });
  });

  describe('複数ポリシー（積集合: どれか 1 つの強制ポリシーが指定していれば「ある」）', () => {
    it('陽性: 2 つの強制ポリシーのどちらにもないとき 1 件だけ出る', () => {
      expectFires(run([...H("default-src 'self'"), ...H("script-src 'self'")]), 'tt');
    });

    it('陽性: 1 行のカンマ区切りで送られた 2 つのポリシーのどちらにもないとき出る', () => {
      expectFires(run(H("default-src 'self', script-src 'self'")), 'tt');
    });

    it('陰性: 片方の強制ポリシーだけが指定しているとき出ない', () => {
      expectSilent(run([...H("default-src 'self'"), ...H("require-trusted-types-for 'script'")]), 'tt');
    });

    it('陽性: Report-Only のポリシーだけが指定しているときは「ない」扱いで出る', () => {
      expectFires(run([...H("default-src 'self'"), ...RO("require-trusted-types-for 'script'")]), 'tt');
    });
  });

  describe('meta の CSP', () => {
    it('陽性: meta の強制ポリシーだけがあり、指定がないとき出る', () => {
      expectFires(run(M("default-src 'self'")), 'tt');
    });

    it('陰性: meta の強制ポリシーが指定しているとき出ない（ヘッダー側に無くても）', () => {
      expectSilent(run(M("default-src 'self'; require-trusted-types-for 'script'")), 'tt');
      expectSilent(run([...H("default-src 'self'"), ...M("require-trusted-types-for 'script'")]), 'tt');
    });

    it('陽性: meta の Report-Only（ブラウザが無視する）だけが指定しているときは「ない」扱いで出る', () => {
      expectFires(run([...H("default-src 'self'"), ...MRO("require-trusted-types-for 'script'")]), 'tt');
    });

    it('陰性: meta の Report-Only だけのページ（強制の CSP がない）では出ない', () => {
      expectSilent(run(MRO("default-src 'self'")), 'tt');
    });
  });
});

// ---------------------------------------------------------------------------
// upgrade-insecure-requests: 混在コンテンツが検出されていて、この指定がない（info）
// ---------------------------------------------------------------------------

describe('v1.8.0 T07: SEC-CSPX-UIR-01 — 混在コンテンツがあり upgrade-insecure-requests がない', () => {
  const mixed = ctx({ mixedContentDetected: true });

  describe('単一ポリシー', () => {
    it('陽性: 混在コンテンツがあり、強制の CSP に指定がないとき info / info で出る', () => {
      expectFires(run(H("default-src 'self'"), mixed), 'uir');
    });

    it.each([
      "default-src 'self'; upgrade-insecure-requests",
      "upgrade-insecure-requests; default-src 'self'",
      "default-src 'self'; upgrade-insecure-requests;",
      "default-src 'self'; Upgrade-Insecure-Requests",
    ])('陰性: %j（値を持たないディレクティブ）のとき出ない', (csp) => {
      expectSilent(run(H(csp), mixed), 'uir');
    });

    it('陰性: 混在コンテンツが検出されていないときは、指定がなくても出ない', () => {
      expectSilent(run(H("default-src 'self'"), ctx({ mixedContentDetected: false })), 'uir');
      expectSilent(run([], ctx({ mixedContentDetected: false })), 'uir');
    });

    it('陽性: 混在コンテンツがあり、CSP がまったくないときも出る（指示書の条件は「この指定がない」だけ）', () => {
      expectFires(run([], mixed), 'uir');
    });
  });

  describe('複数ポリシー', () => {
    it('陽性: 2 つの強制ポリシーのどちらにもないとき 1 件だけ出る', () => {
      expectFires(run([...H("default-src 'self'"), ...H("script-src 'self'")], mixed), 'uir');
    });

    it('陰性: 片方の強制ポリシーだけが指定しているとき出ない', () => {
      expectSilent(run([...H("default-src 'self'"), ...H('upgrade-insecure-requests')], mixed), 'uir');
    });

    it('陽性: Report-Only のポリシー（仕様上この指定は無視される）だけが指定しているときは出る', () => {
      expectFires(run([...H("default-src 'self'"), ...RO('upgrade-insecure-requests')], mixed), 'uir');
    });
  });

  describe('meta の CSP', () => {
    it('陽性: meta の強制ポリシーに指定がないとき出る', () => {
      expectFires(run(M("default-src 'self'"), mixed), 'uir');
    });

    it('陰性: meta の強制ポリシーが指定しているとき出ない（ヘッダー側に無くても）', () => {
      expectSilent(run(M("default-src 'self'; upgrade-insecure-requests"), mixed), 'uir');
      expectSilent(run([...H("default-src 'self'"), ...M('upgrade-insecure-requests')], mixed), 'uir');
    });

    it('陽性: meta の Report-Only だけが指定しているときは「ない」扱いで出る', () => {
      expectFires(run([...H("default-src 'self'"), ...MRO('upgrade-insecure-requests')], mixed), 'uir');
    });
  });
});

// ---------------------------------------------------------------------------
// form-action: 強制の CSP があり form-action がない（default-src にフォールバックしない）（low）
// ---------------------------------------------------------------------------

describe('v1.8.0 T07: SEC-CSPX-FORM-01 — 強制の CSP に form-action がない', () => {
  describe('単一ポリシー', () => {
    it.each(["default-src 'self'", "default-src 'none'", "default-src 'self'; navigate-to 'self'"])(
      '陽性: %j のとき warning / low で出る（default-src にフォールバックしない）',
      (csp) => {
        const c = expectFires(run(H(csp)), 'form');
        expect(isRequiresAttention(c)).toBe(true);
      }
    );

    it.each([
      "default-src 'self'; form-action 'self'",
      "default-src 'self'; form-action 'none'",
      "default-src 'self'; form-action https://forms.example.test",
      "default-src 'self'; Form-Action 'self'",
    ])('陰性: %j のとき出ない', (csp) => {
      expectSilent(run(H(csp)), 'form');
    });

    it('陰性: 強制の CSP がない（ポリシーなし / Report-Only だけ）ときは出ない', () => {
      expectSilent(run([]), 'form');
      expectSilent(run(RO("default-src 'self'")), 'form');
    });
  });

  describe('複数ポリシー', () => {
    it('陽性: 2 つの強制ポリシーのどちらにもないとき 1 件だけ出る', () => {
      expectFires(run([...H("default-src 'self'"), ...H("frame-ancestors 'none'")]), 'form');
    });

    it('陰性: 片方の強制ポリシーだけが指定しているとき出ない', () => {
      expectSilent(run([...H("default-src 'self'"), ...H("form-action 'self'")]), 'form');
    });

    it('陽性: Report-Only のポリシーだけが指定しているときは「ない」扱いで出る', () => {
      expectFires(run([...H("default-src 'self'"), ...RO("form-action 'self'")]), 'form');
    });
  });

  describe('meta の CSP', () => {
    it('陽性: meta の強制ポリシーに指定がないとき出る', () => {
      expectFires(run(M("default-src 'self'")), 'form');
    });

    it('陰性: meta の強制ポリシーが指定しているとき出ない（ヘッダー側に無くても）', () => {
      expectSilent(run(M("default-src 'self'; form-action 'self'")), 'form');
      expectSilent(run([...H("default-src 'self'"), ...M("form-action 'self'")]), 'form');
    });

    it('陽性: meta の Report-Only だけが指定しているときは「ない」扱いで出る', () => {
      expectFires(run([...H("default-src 'self'"), ...MRO("form-action 'self'")]), 'form');
    });
  });
});

// ---------------------------------------------------------------------------
// レポート先: report-to のグループが Reporting-Endpoints に定義されていない（info）
// ---------------------------------------------------------------------------

describe('v1.8.0 T07: SEC-CSPX-REPORT-01 — report-to のグループが Reporting-Endpoints に定義されていない', () => {
  const CSP_WITH_REPORT_TO = "default-src 'self'; report-to csp-endpoint";

  describe('単一ポリシー', () => {
    it('陽性: Reporting-Endpoints ヘッダーがないとき info / info で出て、根拠にグループ名がある', () => {
      const c = expectFires(run(H(CSP_WITH_REPORT_TO), ctx({ reportingEndpoints: [] })), 'report');
      expect(`${c.observed} ${c.description}`).toContain('csp-endpoint');
    });

    it('陽性: 文脈に Reporting-Endpoints が渡されない（undefined）ときも「定義されていない」として出る', () => {
      expectFires(run(H(CSP_WITH_REPORT_TO), { mixedContentDetected: false }), 'report');
    });

    it('陽性: Reporting-Endpoints に別の名前しかないとき出る', () => {
      expectFires(
        run(H(CSP_WITH_REPORT_TO), ctx({ reportingEndpoints: ['other-endpoint="https://reports.example.test/x"'] })),
        'report'
      );
    });

    it('陽性: Report-Only のヘッダーのポリシーでも、グループが定義されていなければ出る', () => {
      expectFires(run(RO(CSP_WITH_REPORT_TO)), 'report');
    });

    it.each([
      [RE_DEFINES_CSP_ENDPOINT],
      [`main="https://reports.example.test/main", ${RE_DEFINES_CSP_ENDPOINT}`],
      ['main="https://reports.example.test/main"', RE_DEFINES_CSP_ENDPOINT],
      [` ${RE_DEFINES_CSP_ENDPOINT} `],
    ])('陰性: Reporting-Endpoints %j がグループを定義しているとき出ない', (...lines) => {
      expectSilent(run(H(CSP_WITH_REPORT_TO), ctx({ reportingEndpoints: lines })), 'report');
      expectSilent(run(RO(CSP_WITH_REPORT_TO), ctx({ reportingEndpoints: lines })), 'report');
    });

    it('陰性: report-to を使っていないとき（report-uri だけ / どちらもない）は、Reporting-Endpoints がなくても出ない', () => {
      expectSilent(run(H("default-src 'self'; report-uri /csp-report")), 'report');
      expectSilent(run(H("default-src 'self'")), 'report');
      expectSilent(run([]), 'report');
    });
  });

  describe('複数ポリシー', () => {
    it('陰性: 2 つのポリシーが同じ定義済みのグループを使うとき出ない', () => {
      const policies = [...H(CSP_WITH_REPORT_TO), ...RO("script-src 'self'; report-to csp-endpoint")];
      expectSilent(run(policies, ctx({ reportingEndpoints: [RE_DEFINES_CSP_ENDPOINT] })), 'report');
    });

    it('陽性: 片方のポリシーのグループだけが未定義のとき 1 件にまとまり、根拠に未定義のグループ名がある', () => {
      const policies = [...H(CSP_WITH_REPORT_TO), ...H("script-src 'self'; report-to missing-group")];
      const c = expectFires(run(policies, ctx({ reportingEndpoints: [RE_DEFINES_CSP_ENDPOINT] })), 'report');
      expect(`${c.observed} ${c.description}`).toContain('missing-group');
    });

    it('陽性: 2 つのポリシーのグループがどちらも未定義のとき 1 件にまとまり、根拠に両方のグループ名がある', () => {
      const policies = [...H("default-src 'self'; report-to group-a"), ...RO("default-src 'self'; report-to group-b")];
      const c = expectFires(run(policies), 'report');
      expect(`${c.observed} ${c.description}`).toContain('group-a');
      expect(`${c.observed} ${c.description}`).toContain('group-b');
    });
  });

  describe('meta の CSP（report-to は無効という既存の扱いを崩さない）', () => {
    it('陰性: meta の CSP の report-to は、グループが未定義でもこの項目の対象にしない', () => {
      expectSilent(run(M("default-src 'self'; report-to meta-group")), 'report');
      expectSilent(run(MRO("default-src 'self'; report-to meta-group")), 'report');
    });

    it('陽性: ヘッダーのポリシーのグループだけを根拠にする（meta 側のグループ名は出さない）', () => {
      const policies = [...H("default-src 'self'; report-to header-group"), ...M("default-src 'self'; report-to meta-group")];
      const c = expectFires(run(policies), 'report');
      expect(`${c.observed} ${c.description}`).toContain('header-group');
      expect(`${c.observed} ${c.description}`).not.toContain('meta-group');
    });

    it('既存の扱い: meta の report-to は従来どおり CSP-META-INVALID-REPORT-TO（medium）として指摘される', () => {
      const { issues } = analyzeCSPPolicies(M("default-src 'self'; report-to meta-group"), URL_HTTPS);
      const invalid = issues.filter((i) => i.id === 'CSP-META-INVALID-REPORT-TO');
      expect(invalid).toHaveLength(1);
      expect(invalid[0].severity).toBe('medium');
    });
  });
});

// ---------------------------------------------------------------------------
// 共通: 推奨どおりの CSP では何も出ない / 重複しない / G4
// ---------------------------------------------------------------------------

describe('v1.8.0 T07: 共通の確認', () => {
  const FULL = "default-src 'self'; form-action 'self'; require-trusted-types-for 'script'; upgrade-insecure-requests; report-to csp-endpoint";

  it('陰性の総合: 4 項目をすべて満たす CSP では、混在コンテンツがあっても新しい ID は 1 件も出ない', () => {
    const checks = run(H(FULL), ctx({ mixedContentDetected: true, reportingEndpoints: [RE_DEFINES_CSP_ENDPOINT] }));
    expect(checks.filter((c) => NEW_CHECK_IDS.includes(c.checkId))).toEqual([]);
  });

  it('陽性の総合: 4 項目がすべて発火する入力で、それぞれ 1 件ずつ表のとおりに出る', () => {
    const checks = run(H("default-src 'self'; report-to csp-endpoint"), ctx({ mixedContentDetected: true }));
    for (const key of ITEM_KEYS) expectFires(checks, key);
  });

  it('G4: 新しい指摘の重大度は low 以下', () => {
    const inputs: Array<[CSPPolicy[], CspExtrasContext]> = [
      [H("default-src 'self'; report-to csp-endpoint"), ctx({ mixedContentDetected: true })],
      [[...H("default-src 'self'; report-to a"), ...H('script-src *; report-to b')], ctx({ mixedContentDetected: true })],
      [M("default-src 'self'"), ctx({ mixedContentDetected: true })],
      [[], ctx({ mixedContentDetected: true })],
    ];
    for (const [policies, c] of inputs) {
      for (const r of run(policies, c)) {
        expect(['info', 'low'], `${r.checkId} の重大度 ${r.severity}`).toContain(r.severity);
      }
    }
  });

  it('checkCspExtras は新しい ID 以外を返さない（既存の SEC-CSP-* は analyzeCSPPolicies が作る）', () => {
    const checks = run(H("default-src 'self'; report-to csp-endpoint"), ctx({ mixedContentDetected: true }));
    for (const c of checks) {
      expect(NEW_CHECK_IDS, c.checkId).toContain(c.checkId);
    }
  });
});

// ---------------------------------------------------------------------------
// CSP の問題点の表（v1.7.1 T10）にも同じ表現で出す
// ---------------------------------------------------------------------------

describe('v1.8.0 T07: CSP の問題点の表（ポリシーごとの指摘）に同じ表現で出る', () => {
  const ALL_MISSING = "default-src 'self'; report-to csp-endpoint";
  const c0 = ctx({ mixedContentDetected: true });

  it('単一ポリシー: 4 項目が問題点の表の指摘として出て、重大度・内容がセキュリティ診断の項目と同じ', () => {
    const policies = H(ALL_MISSING);
    const checks = run(policies, c0);
    const issues = evaluatePolicyIssuesWithIntersection(policies[0], policies, false, c0);
    for (const key of ITEM_KEYS) {
      const item = ITEMS[key];
      const matched = issues.filter((i) => i.id === item.issueId);
      expect(matched.length, `${item.issueId} が問題点の表にありません`).toBe(1);
      expect(matched[0].directive).toContain(item.directive);
      const check = byId(checks, item.checkId)[0];
      expect(matched[0].severity).toBe(check.severity);
      expect(matched[0].description, `${item.issueId} の内容が ${item.checkId} と違います`).toBe(check.description);
      expect(matched[0].recommendation.length).toBeGreaterThan(0);
    }
  });

  it('evaluateCspExtraIssues は、evaluatePolicyIssuesWithIntersection に足される指摘と同じものを返す', () => {
    const policies = H(ALL_MISSING);
    const extras = evaluateCspExtraIssues(policies[0], policies, c0);
    expect(issueIds(extras).sort()).toEqual([...NEW_ISSUE_IDS].sort());
    const withCtx = evaluatePolicyIssuesWithIntersection(policies[0], policies, false, c0);
    const withoutCtx = evaluatePolicyIssuesWithIntersection(policies[0], policies, false);
    expect(issueIds(withCtx).filter((id) => NEW_ISSUE_IDS.includes(id)).sort()).toEqual(issueIds(extras).sort());
    expect(issueIds(withCtx).filter((id) => !NEW_ISSUE_IDS.includes(id))).toEqual(issueIds(withoutCtx));
  });

  it('後方互換: 文脈を渡さないときは、問題点の表に新しい指摘を足さない', () => {
    const policies = H(ALL_MISSING);
    const issues = evaluatePolicyIssuesWithIntersection(policies[0], policies, false);
    expect(issueIds(issues).filter((id) => NEW_ISSUE_IDS.includes(id))).toEqual([]);
  });

  it('複数ポリシー: 片方の強制ポリシーが form-action を指定していれば、どちらの表にも form-action の指摘は出ない', () => {
    const policies = [...H("default-src 'self'"), ...H("form-action 'self'")];
    for (const p of policies) {
      const ids = issueIds(evaluatePolicyIssuesWithIntersection(p, policies, false, c0));
      expect(ids).not.toContain(ITEMS.form.issueId);
    }
  });

  it('複数ポリシー: どちらの強制ポリシーにもないとき、両方の表に出る', () => {
    const policies = [...H("default-src 'self'"), ...H("frame-ancestors 'none'")];
    for (const p of policies) {
      const ids = issueIds(evaluatePolicyIssuesWithIntersection(p, policies, false, c0));
      expect(ids).toContain(ITEMS.form.issueId);
      expect(ids).toContain(ITEMS.tt.issueId);
      expect(ids).toContain(ITEMS.uir.issueId);
    }
  });

  it('複数ポリシー: report-to の指摘は、未定義のグループを使うポリシーの表にだけ出る', () => {
    const policies = [...H("default-src 'self'; report-to csp-endpoint"), ...H("script-src 'self'; report-to missing-group")];
    const c = ctx({ reportingEndpoints: [RE_DEFINES_CSP_ENDPOINT] });
    const first = evaluatePolicyIssuesWithIntersection(policies[0], policies, false, c);
    const second = evaluatePolicyIssuesWithIntersection(policies[1], policies, false, c);
    expect(issueIds(first)).not.toContain(ITEMS.report.issueId);
    const reportIssues = second.filter((i) => i.id === ITEMS.report.issueId);
    expect(reportIssues).toHaveLength(1);
    expect(reportIssues[0].severity).toBe('info');
    expect(reportIssues[0].description).toContain('missing-group');
  });

  it('Report-Only のポリシー: TT・UIR・form-action の指摘は出ないが、report-to の指摘は出る', () => {
    const policies = [...H("default-src 'self'"), ...RO("default-src 'self'; report-to ro-group")];
    const ids = issueIds(evaluatePolicyIssuesWithIntersection(policies[1], policies, false, c0));
    expect(ids).not.toContain(ITEMS.tt.issueId);
    expect(ids).not.toContain(ITEMS.uir.issueId);
    expect(ids).not.toContain(ITEMS.form.issueId);
    expect(ids).toContain(ITEMS.report.issueId);
  });

  it('meta のポリシー: TT・UIR・form-action の指摘は出るが、report-to は既存の CSP-META-INVALID-REPORT-TO だけ', () => {
    const policies = M("default-src 'self'; report-to meta-group");
    const ids = issueIds(evaluatePolicyIssuesWithIntersection(policies[0], policies, false, c0));
    expect(ids).toContain(ITEMS.tt.issueId);
    expect(ids).toContain(ITEMS.uir.issueId);
    expect(ids).toContain(ITEMS.form.issueId);
    expect(ids).not.toContain(ITEMS.report.issueId);
    expect(ids.filter((id) => id === 'CSP-META-INVALID-REPORT-TO')).toHaveLength(1);
  });

  it('meta の Report-Only のポリシー: 新しい指摘は出ない', () => {
    const policies = [...H("default-src 'self'"), ...MRO("default-src 'self'; report-to meta-group")];
    const ids = issueIds(evaluatePolicyIssuesWithIntersection(policies[1], policies, false, c0));
    expect(ids.filter((id) => NEW_ISSUE_IDS.includes(id))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 既存の CSP の評価を変えない（SEC-CSP-00 / SEC-CSP-03 の集計に入れない）
// ---------------------------------------------------------------------------

describe('v1.8.0 T07: 既存の CSP の評価を変えない', () => {
  const STRONG =
    "default-src 'self'; script-src 'self' 'nonce-rAnd0m'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

  it('analyzeCSPPolicies の結果と指摘には、新しい ID が入らない', () => {
    const { issues, results } = analyzeCSPPolicies(H(STRONG), URL_HTTPS, true);
    expect(results.map((r) => r.checkId)).toEqual(['SEC-CSP-00']);
    expect(issueIds(issues).filter((id) => NEW_ISSUE_IDS.includes(id))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// executeInspection（調査の統括）での結果・SPEC-01・G5
// ---------------------------------------------------------------------------

function dom(o: { metaCsp?: string[]; metaCspReportOnly?: string[]; mixedContent?: MixedContentItem[] } = {}): DomSignals {
  return {
    url: URL_HTTPS,
    title: 'CSP extras test',
    metaTags: [],
    scriptUrls: [],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: o.mixedContent || [],
    cookiesFromDocument: [],
    cssAssets: [],
    metaCsp: o.metaCsp || [],
    metaCspReportOnly: o.metaCspReportOnly || [],
  } as unknown as DomSignals;
}

const MIXED: MixedContentItem[] = [{ resourceType: 'image', url: 'http://img.example.test/a.png' }];

interface InspectOpts {
  headers?: Record<string, string[]>;
  cache?: 'observed' | 'none' | 'other-origin';
  metaCsp?: string[];
  metaCspReportOnly?: string[];
  mixedContent?: MixedContentItem[];
}

async function inspect(opts: InspectOpts): Promise<InspectionReport> {
  const cache = opts.cache ?? 'observed';
  return executeInspection({
    tab: { id: 701, url: URL_HTTPS },
    fetchDomSignals: vi.fn().mockResolvedValue(dom(opts)),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue(
      cache === 'none'
        ? undefined
        : {
            url: cache === 'other-origin' ? 'https://other.example.test/' : URL_HTTPS,
            headers: opts.headers || {},
            observed: true,
          }
    ),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
  });
}

const STRONG_HEADER_CSP =
  "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; report-to csp-endpoint";

describe('v1.8.0 T07: executeInspection での結果', () => {
  it('ヘッダーを観測したとき: 4 項目が表のとおりに出て、SEC-CSP-00（合格）は従来どおり', async () => {
    const report = await inspect({
      headers: { 'content-security-policy': [STRONG_HEADER_CSP] },
      mixedContent: MIXED,
    });
    for (const key of ITEM_KEYS) expectFires(report.securityChecks, key);
    const main = report.securityChecks.filter((c) => /^SEC-CSP-0[0-3]$/.test(c.checkId));
    expect(main.map((c) => c.checkId)).toEqual(['SEC-CSP-00']);
    expect(main[0].status).toBe('pass');
  });

  it('要確認件数: form-action（low）だけが要確認に入り、info の 3 項目は入らない', async () => {
    const report = await inspect({
      headers: { 'content-security-policy': [STRONG_HEADER_CSP] },
      mixedContent: MIXED,
    });
    const attention = report.securityChecks.filter((c) => NEW_CHECK_IDS.includes(c.checkId) && isRequiresAttention(c));
    expect(attention.map((c) => c.checkId)).toEqual([ITEMS.form.checkId]);
  });

  it('Reporting-Endpoints ヘッダーがグループを定義していれば、report-to の項目は出ない', async () => {
    const report = await inspect({
      headers: {
        'content-security-policy': [STRONG_HEADER_CSP],
        'reporting-endpoints': [RE_DEFINES_CSP_ENDPOINT],
      },
      mixedContent: MIXED,
    });
    expectSilent(report.securityChecks, 'report');
    expectFires(report.securityChecks, 'tt');
  });

  it('混在コンテンツが無ければ upgrade-insecure-requests の項目は出ない', async () => {
    const report = await inspect({ headers: { 'content-security-policy': [STRONG_HEADER_CSP] } });
    expectSilent(report.securityChecks, 'uir');
  });

  it('meta の CSP だけのページ（ヘッダーは観測、CSP ヘッダーなし）: TT と form-action が出て、meta の report-to では report-to の項目が出ない', async () => {
    const report = await inspect({
      headers: { 'strict-transport-security': ['max-age=31536000'] },
      metaCsp: ["default-src 'self'; report-to meta-group"],
    });
    expectFires(report.securityChecks, 'tt');
    expectFires(report.securityChecks, 'form');
    expectSilent(report.securityChecks, 'report');
  });

  it('meta の CSP が指定していれば、ヘッダーの CSP に無くても出ない（積集合）', async () => {
    const report = await inspect({
      headers: { 'content-security-policy': ["frame-ancestors 'none'"] },
      metaCsp: ["default-src 'self'; form-action 'self'; require-trusted-types-for 'script'; upgrade-insecure-requests"],
      mixedContent: MIXED,
    });
    expectSilent(report.securityChecks, 'tt');
    expectSilent(report.securityChecks, 'form');
    expectSilent(report.securityChecks, 'uir');
  });

  it('同じ新しい ID は 1 回の調査で 2 件以上出ない', async () => {
    const report = await inspect({
      headers: { 'content-security-policy': [STRONG_HEADER_CSP, "script-src 'self'; report-to other-group"] },
      metaCsp: ["default-src 'self'"],
      mixedContent: MIXED,
    });
    for (const id of NEW_CHECK_IDS) {
      expect(byId(report.securityChecks, id).length, `${id} が重複しています`).toBeLessThanOrEqual(1);
    }
  });
});

describe('v1.8.0 T07: SPEC-01 — ヘッダー未観測なら新しい項目は unknown', () => {
  it.each(NEW_CHECK_IDS.map((id) => [id]))('%s の接頭辞が HEADER_DEPENDENT_CHECK_PREFIXES にある', (id) => {
    expect(HEADER_DEPENDENT_CHECK_PREFIXES.some((p) => id.startsWith(p))).toBe(true);
  });

  it.each([
    { label: 'キャッシュなし', cache: 'none' as const },
    { label: 'キャッシュの origin が違う', cache: 'other-origin' as const },
  ])('$label: meta の CSP と混在コンテンツがあっても、新しい項目は unknown / info で要確認に入らない', async ({ cache }) => {
    const report = await inspect({
      cache,
      headers: { 'content-security-policy': ["default-src 'self'; report-to csp-endpoint"] },
      metaCsp: ["default-src 'self'"],
      mixedContent: MIXED,
    });
    const fresh = report.securityChecks.filter((c) => NEW_CHECK_IDS.includes(c.checkId));
    for (const c of fresh) {
      expect(c.status, `${c.checkId} が unknown になっていません`).toBe('unknown');
      expect(c.severity).toBe('info');
      expect(isRequiresAttention(c)).toBe(false);
    }
  });
});

describe('v1.8.0 T07: 評価に使うヘッダーが取得される（G5: reporting-endpoints）', () => {
  it('reporting-endpoints が ALLOWED_RESPONSE_HEADERS にあり、filterAndSanitizeHeaders が残す', () => {
    expect(ALLOWED_RESPONSE_HEADERS.has('reporting-endpoints')).toBe(true);
    const out = filterAndSanitizeHeaders([
      { name: 'Reporting-Endpoints', value: RE_DEFINES_CSP_ENDPOINT },
      { name: 'Content-Security-Policy', value: "default-src 'self'; report-to csp-endpoint" },
      { name: 'Set-Cookie', value: 'sid=secret' },
    ] as chrome.webRequest.HttpHeader[]);
    expect(out['reporting-endpoints']).toEqual([RE_DEFINES_CSP_ENDPOINT]);
    expect(out['set-cookie']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Markdown レポート（第 8 節: CSP の問題点の表）と整合性チェッカー
// ---------------------------------------------------------------------------

const section8 = (md: string): string =>
  md.split('## 8. CSP（Content Security Policy）診断')[1]?.split('## 9.')[0] || '';

const tableRows = (text: string): string[] =>
  text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('|') && l.endsWith('|'));

describe('v1.8.0 T07: Markdown の CSP の問題点の表', () => {
  it('ヘッダーを観測したとき: 第 8 節の表に、診断の項目と同じ重大度・内容の行が出る', async () => {
    const report = await inspect({
      headers: { 'content-security-policy': [STRONG_HEADER_CSP] },
      mixedContent: MIXED,
    });
    const rows = tableRows(section8(generateMarkdownReport(report)));
    for (const key of ITEM_KEYS) {
      const item = ITEMS[key];
      const check = byId(report.securityChecks, item.checkId)[0];
      expect(check, `${item.checkId} がありません`).toBeDefined();
      const cell = escapeMarkdownTableCell(check.description);
      const row = rows.find((r) => r.includes(cell));
      expect(row, `${item.checkId} の行が第 8 節の表にありません`).toBeDefined();
      expect(row).toContain(item.directive);
      expect(row).toContain(`| ${check.severity.toUpperCase()} |`);
    }
  });

  it('ヘッダー未観測のとき: 第 8 節の表に新しい行を足さない（断定しない）', async () => {
    const report = await inspect({
      cache: 'none',
      metaCsp: ["default-src 'self'"],
      mixedContent: MIXED,
    });
    const rows = tableRows(section8(generateMarkdownReport(report)));
    for (const directive of ['require-trusted-types-for', 'upgrade-insecure-requests', 'form-action']) {
      expect(rows.some((r) => r.includes(directive)), `${directive} の行があります`).toBe(false);
    }
  });

  it('新しい項目を含むレポートと Markdown が整合性チェッカーを通り、項目名が Markdown にある', async () => {
    const report = await inspect({
      headers: { 'content-security-policy': [STRONG_HEADER_CSP] },
      metaCsp: ["default-src 'self'"],
      mixedContent: MIXED,
    });
    const md = generateMarkdownReport(report);
    for (const c of report.securityChecks.filter((x) => NEW_CHECK_IDS.includes(x.checkId))) {
      expect(md, `${c.checkId} の項目が Markdown にありません`).toContain(c.name);
    }
    const lint = lintReportPair(report, md, { includePending: true });
    expect(lint.violations).toEqual([]);
    expect(lint.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 仕様書・変更範囲（受け入れ条件 2・3）
// ---------------------------------------------------------------------------

/** v1.8.0 の起点（AGENTS.md「現在の作業」） */
const BASE_COMMIT = 'a5bd583';

function git(args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return null;
  }
}

/** 起点からの差分の行数（追加＋削除）。起点のコミットが無い（浅い clone など）ときは null */
function diffLinesFromBase(file: string): number | null {
  if (git(['cat-file', '-e', `${BASE_COMMIT}^{commit}`]) === null) return null;
  const out = git(['diff', '--numstat', BASE_COMMIT, '--', file]);
  if (out === null) return null;
  return out
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .reduce((sum, line) => {
      const [added, deleted] = line.split(/\s+/);
      return sum + Number(added) + Number(deleted);
    }, 0);
}

describe('v1.8.0 T07: 仕様書と変更範囲', () => {
  it('仕様書（docs/DETECTION_SPECIFICATION.md）に新しい ID がすべて載っている', () => {
    const spec = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'DETECTION_SPECIFICATION.md'), 'utf-8');
    for (const id of NEW_CHECK_IDS) {
      expect(spec.includes(id), `${id} が仕様書にありません`).toBe(true);
    }
  });

  it('新しい評価は src/security/csp-extras.ts にある', () => {
    expect(fs.existsSync(path.join(REPO_ROOT, 'src', 'security', 'csp-extras.ts'))).toBe(true);
  });

  it('csp-parser.ts の差分が起点から 30 行以内（追加＋削除）', () => {
    const file = 'src/security/csp-parser.ts';
    const lines = diffLinesFromBase(file);
    if (lines !== null) {
      expect(lines, `${file} の差分が ${lines} 行あります`).toBeLessThanOrEqual(30);
    } else {
      // 起点のコミットが無い環境（浅い clone）では、起点の行数（1113 行）からの増加で確かめる
      const current = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n').length - 1;
      expect(current).toBeLessThanOrEqual(1113 + 30);
    }
  });

  it('tests/csp-parser.test.ts は起点から変わっていない（既存の期待値を変えない）', () => {
    const file = 'tests/csp-parser.test.ts';
    const lines = diffLinesFromBase(file);
    if (lines !== null) {
      expect(lines, `${file} が変更されています`).toBe(0);
    } else {
      // 起点のコミットが無い環境では、既存の代表的な期待値が残っていることだけ確かめる
      const text = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');
      expect(text).toContain("\"'unsafe-inline' あり / object-src 未指定 / frame-ancestors 未指定 / base-uri 未指定\"");
    }
  });
});
