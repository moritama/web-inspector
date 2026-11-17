/**
 * v1.8.1 T06: CVE ごとのディストリの判定を engine・調査（executeInspection）・表示・エクスポートに組み込んだ結果の受け入れテスト
 *
 * - engine が、推定したリリースのディストリのデータで、上流の照合で出た CVE ごとに distroStatus を付ける（§4.1・§4.2）
 * - 要確認件数とバッジは §4.2 の表のとおり（H4a）: fixed・not-affected は数えず、それ以外は数える
 * - 判定はすべて Needs Review（H4）。「該当なし」「安全」の語を使わない
 * - 第三者リポジトリ・バックポートではディストリのデータを使わない（H5・H9）
 * - ポップアップ・ダッシュボード・Markdown / JSON / CSV に区分と修正版、JSON には OSV ID と出典も出す
 * - reports:lint（scripts/report-lint.mjs）が通る
 *
 * 照合は固定 DB（tests/fixtures/advisory-db.fixture.json）を複製し、distro 節に合成の advisories と _source を足して使う。
 * 固定 DB で、PHP 7.4.3 の上流の照合は CVE-2024-4577 と CVE-2022-31628、Apache 2.4.41 は CVE-2021-44790 になる。
 */
import { describe, expect, it, vi } from 'vitest';
import { executeInspection, HEADER_DEPENDENT_CHECK_PREFIXES, InspectionDependencies } from '../src/background/service-worker';
import { AdvisoryDatabase, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { DetectionEngine } from '../src/detection/engine';
import { exportReportToCsv } from '../src/export/csv';
import { exportReportToJson } from '../src/export/json';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderFullTechnologiesHtml, renderLibrarySecurityTableHtml } from '../src/dashboard/render';
import { renderTechModalHtml } from '../src/popup/render';
import type {
  AdvisoryDistroSection,
  DetectedTechnology,
  DistroAdvisoryEntry,
  DistroSourceRecord,
  DomSignals,
  InspectionReport,
} from '../src/shared/types';
// @ts-expect-error scripts/report-lint.mjs は型定義を持たない .mjs モジュール
import { lintReportPair } from '../scripts/report-lint.mjs';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

type DbWithDistro = AdvisoryDatabase & { distro?: AdvisoryDistroSection };
type Status = 'not-fixed' | 'open' | 'unknown-revision' | 'no-data' | 'fixed' | 'not-affected';

const fixture = rawFixtureDb as unknown as DbWithDistro;
const FORBIDDEN_WORDS = ['該当なし', '安全', 'Not Affected', '影響はありません'];
const HOST = 'https://www.example.test/';

const PHP_UBUNTU = { 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] };
const APACHE_UBUNTU = { server: ['Apache/2.4.41 (Ubuntu)'] };
const PHP_CVES = ['CVE-2024-4577', 'CVE-2022-31628'];
const APACHE_CVE = 'CVE-2021-44790';
const OLDER_FIX = '7.4.3-4ubuntu2.10';
const NEWER_FIX = '7.4.3-4ubuntu2.24';
const APACHE_FIX = '2.4.41-4ubuntu3.10';

const SOURCES: DistroSourceRecord[] = [
  { name: 'OSV.dev (Debian Security Tracker)', url: 'https://osv.dev/list?ecosystem=Debian', ecosystem: 'Debian', license: null, licenseNote: '確認中', retrievedAt: null, recordCount: 0 },
  { name: 'OSV.dev (Ubuntu Security Notices)', url: 'https://github.com/canonical/ubuntu-security-notices', ecosystem: 'Ubuntu', license: 'CC-BY-SA-4.0', retrievedAt: null, recordCount: 0 },
  { name: 'endoflife.date', url: 'https://endoflife.date/', ecosystem: null, license: 'MIT', retrievedAt: null, recordCount: 0 },
];

function fixedEntry(cve: string, fixedVersions: string[], osvIds = [`UBUNTU-${cve}`]): DistroAdvisoryEntry {
  return { cve, status: 'fixed', fixedVersions, osvIds };
}
function openEntry(cve: string): DistroAdvisoryEntry {
  return { cve, status: 'open', fixedVersions: [], osvIds: [`UBUNTU-${cve}`] };
}
function notAffectedEntry(cve: string): DistroAdvisoryEntry {
  return { cve, status: 'not-affected', fixedVersions: [], osvIds: [`UBUNTU-${cve}`] };
}

/** 固定 DB の複製に、合成の distro.advisories と _source を足す */
function dbWithAdvisories(advisories: Record<string, Record<string, DistroAdvisoryEntry[]>>, mutate?: (db: DbWithDistro) => void): DbWithDistro {
  const db = structuredClone(fixture);
  db.distro!.advisories = advisories;
  db.distro!._source = structuredClone(SOURCES);
  mutate?.(db);
  return db;
}

const emptyDom = (): DomSignals => ({
  url: HOST,
  title: 'Distro advisory test',
  metaTags: [],
  scriptUrls: [],
  linkUrls: [],
  domMarkers: [],
  htmlSnippets: [],
  mixedContent: [],
  cookiesFromDocument: [],
  cssAssets: [],
});

const engine = new DetectionEngine();

function detect(headers: Record<string, string[]>): DetectedTechnology[] {
  return engine.detect({ url: HOST, dom: emptyDom(), network: { url: HOST, responseHeaders: headers, cookies: [] } });
}

function tech(techs: DetectedTechnology[], name: string): DetectedTechnology {
  const t = techs.find((x) => x.technology === name);
  if (!t) throw new Error(`${name} が検出されていません`);
  return t;
}

function deps(headers: Record<string, string[]>): InspectionDependencies {
  return {
    tab: { id: 7, url: HOST },
    fetchDomSignals: vi.fn().mockResolvedValue({ ...emptyDom(), scriptUrls: ['https://www.example.test/assets/app.js'] }),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue({ url: HOST, headers }),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  };
}

function distroCveChecks(report: InspectionReport, techName: string) {
  const prefix = `SEC-DISTRO-CVE-${techName.toUpperCase()}`;
  return report.securityChecks.filter((c) => c.checkId === prefix || c.checkId.startsWith(`${prefix}-`));
}

function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectStrings(v, out));
  return out;
}

/** 区分ごとの入力: 見出し（ヘッダー）と、その区分になる advisories、技術名、判定される CVE */
interface Scenario {
  headers: Record<string, string[]>;
  techName: string;
  cves: string[];
  advisories: Record<string, Record<string, DistroAdvisoryEntry[]>>;
}
const SCENARIOS: Record<Status, Scenario> = {
  'not-fixed': { headers: PHP_UBUNTU, techName: 'PHP', cves: PHP_CVES, advisories: { 'ubuntu:20.04': { 'php7.4': PHP_CVES.map((c) => fixedEntry(c, [NEWER_FIX])) } } },
  open: { headers: PHP_UBUNTU, techName: 'PHP', cves: PHP_CVES, advisories: { 'ubuntu:20.04': { 'php7.4': PHP_CVES.map((c) => openEntry(c)) } } },
  'unknown-revision': { headers: APACHE_UBUNTU, techName: 'Apache', cves: [APACHE_CVE], advisories: { 'ubuntu:20.04': { apache2: [fixedEntry(APACHE_CVE, [APACHE_FIX])] } } },
  'no-data': { headers: PHP_UBUNTU, techName: 'PHP', cves: PHP_CVES, advisories: { 'ubuntu:20.04': { 'php7.4': [] } } },
  fixed: { headers: PHP_UBUNTU, techName: 'PHP', cves: PHP_CVES, advisories: { 'ubuntu:20.04': { 'php7.4': PHP_CVES.map((c) => fixedEntry(c, [OLDER_FIX])) } } },
  'not-affected': { headers: PHP_UBUNTU, techName: 'PHP', cves: PHP_CVES, advisories: { 'ubuntu:20.04': { 'php7.4': PHP_CVES.map((c) => notAffectedEntry(c)) } } },
};
const COUNTED: Record<Status, boolean> = { 'not-fixed': true, open: true, 'unknown-revision': true, 'no-data': true, fixed: false, 'not-affected': false };

/** 比べるための基準: 同じヘッダーで、判定される CVE がすべて not-affected（数えない） */
function baselineAdvisories(s: Scenario): Record<string, Record<string, DistroAdvisoryEntry[]>> {
  const pkg = s.techName === 'Apache' ? 'apache2' : 'php7.4';
  return { 'ubuntu:20.04': { [pkg]: s.cves.map((c) => notAffectedEntry(c)) } };
}

describe('T06: engine が CVE ごとに distroStatus を付ける', () => {
  it('前提: 固定 DB（advisories の無い distro 節）では distroAdvisories を付けない（第2段階の出力のまま）', () => {
    for (const headers of [PHP_UBUNTU, APACHE_UBUNTU]) {
      for (const t of detect(headers)) expect(t.distroAdvisories).toBeUndefined();
    }
  });

  it('PHP/7.4.3-4ubuntu2.19: 上流の照合で出た CVE（固定 DB の 2 件）すべてに distroStatus が付き、件数は upstreamAdvisoriesCount と同じ', () => {
    setTestAdvisoryDatabase(dbWithAdvisories(SCENARIOS['not-fixed'].advisories));
    const php = tech(detect(PHP_UBUNTU), 'PHP');
    expect(php.distroAdvisories).toBeDefined();
    const upstream = php.distroAdvisories!.cves.filter((c) => c.origin === 'upstream');
    expect(upstream.map((c) => c.cve).sort()).toEqual([...PHP_CVES].sort());
    expect(upstream).toHaveLength(php.upstreamAdvisoriesCount!);
    expect(php.distroAdvisories!.packageVersion).toBe('7.4.3-4ubuntu2.19');
    expect(php.distroAdvisories!.releases).toEqual(['ubuntu:20.04']);
  });

  it.each(Object.keys(SCENARIOS) as Status[])('%s: engine の結果の各 CVE がその区分になり、照合は Needs Review のまま（H4）', (status) => {
    const s = SCENARIOS[status];
    setTestAdvisoryDatabase(dbWithAdvisories(s.advisories));
    const t = tech(detect(s.headers), s.techName);
    for (const cve of s.cves) {
      const c = t.distroAdvisories?.cves.find((x) => x.cve === cve);
      expect(c?.distroStatus, cve).toBe(status);
      expect(c?.counted, cve).toBe(COUNTED[status]);
    }
    expect(t.advisoryMatchStatus).toBe('Needs Review');
    expect(t.supportStatus).not.toBe('Supported');
  });
});

describe('T06 H4a: 要確認件数とバッジの数え方が §4.2 の表のとおり（受け入れ条件 1）', () => {
  it.each(Object.keys(SCENARIOS) as Status[])('%s: 数える区分なら SEC-DISTRO-CVE の指摘が 1 件出て要確認件数とバッジが 1 増え、数えない区分なら増えない', async (status) => {
    const s = SCENARIOS[status];
    setTestAdvisoryDatabase(dbWithAdvisories(baselineAdvisories(s)));
    const baseline = await executeInspection(deps(s.headers));
    expect(distroCveChecks(baseline, s.techName)).toHaveLength(0);

    setTestAdvisoryDatabase(dbWithAdvisories(s.advisories));
    const d = deps(s.headers);
    const report = await executeInspection(d);
    const checks = distroCveChecks(report, s.techName);
    expect(checks).toHaveLength(COUNTED[status] ? 1 : 0);
    expect(report.summary.requiresAttentionCount - baseline.summary.requiresAttentionCount).toBe(COUNTED[status] ? 1 : 0);

    // バッジ（拡張のアイコンの数字）は要確認件数と同じ値で更新される
    const badgeCalls = (d.updateBadge as ReturnType<typeof vi.fn>).mock.calls;
    expect(badgeCalls.length).toBeGreaterThan(0);
    const [count, isWarning] = badgeCalls[badgeCalls.length - 1];
    if (report.summary.requiresAttentionCount > 0) {
      expect(count).toBe(report.summary.requiresAttentionCount);
      expect(isWarning).toBe(true);
    }

    const t = tech(report.technologies, s.techName);
    expect(t.distroAdvisories!.reviewCount).toBe(COUNTED[status] ? s.cves.length : 0);
  });

  it('SEC-DISTRO-CVE は新しいチェックなので重大度は最大 LOW、status は warning、カテゴリは library-security', async () => {
    setTestAdvisoryDatabase(dbWithAdvisories(SCENARIOS['not-fixed'].advisories));
    const [c] = distroCveChecks(await executeInspection(deps(PHP_UBUNTU)), 'PHP');
    expect(c).toBeDefined();
    expect(c.status).toBe('warning');
    expect(['low', 'info']).toContain(c.severity);
    expect(c.category).toBe('library-security');
  });

  it('数える CVE が複数でも、指摘は技術ごとに 1 件（CVE ごとに指摘を増やさない）', async () => {
    setTestAdvisoryDatabase(dbWithAdvisories(SCENARIOS.open.advisories));
    const report = await executeInspection(deps(PHP_UBUNTU));
    expect(tech(report.technologies, 'PHP').distroAdvisories!.reviewCount).toBe(PHP_CVES.length);
    expect(distroCveChecks(report, 'PHP')).toHaveLength(1);
  });

  it('fixed と not-fixed が混ざれば、数えるのは not-fixed だけ（reviewCount 1、指摘 1 件）', async () => {
    setTestAdvisoryDatabase(
      dbWithAdvisories({ 'ubuntu:20.04': { 'php7.4': [fixedEntry(PHP_CVES[0], [OLDER_FIX]), fixedEntry(PHP_CVES[1], [NEWER_FIX])] } })
    );
    const report = await executeInspection(deps(PHP_UBUNTU));
    expect(tech(report.technologies, 'PHP').distroAdvisories!.reviewCount).toBe(1);
    expect(distroCveChecks(report, 'PHP')).toHaveLength(1);
  });

  it('要確認件数は summarizeSecurityChecks の規則のまま（CRITICAL〜LOW の合計と一致する）', async () => {
    setTestAdvisoryDatabase(dbWithAdvisories(SCENARIOS['not-fixed'].advisories));
    const report = await executeInspection(deps(PHP_UBUNTU));
    const f = report.summary.securityFindings;
    expect((f.critical ?? 0) + f.high + f.medium + f.low).toBe(report.summary.requiresAttentionCount);
  });

  it('固定 DB（advisories の無い distro 節）では SEC-DISTRO-CVE の指摘を出さない（陰性）', async () => {
    for (const headers of [PHP_UBUNTU, APACHE_UBUNTU]) {
      const report = await executeInspection(deps(headers));
      expect(report.securityChecks.filter((c) => c.checkId.startsWith('SEC-DISTRO-CVE-'))).toHaveLength(0);
    }
  });

  it('SEC-DISTRO-CVE- の接頭辞が HEADER_DEPENDENT_CHECK_PREFIXES にある（Server・X-Powered-By に依存するチェック）', () => {
    expect(HEADER_DEPENDENT_CHECK_PREFIXES).toContain('SEC-DISTRO-CVE-');
  });
});

describe('T06 §4.1: 候補のリリースが 2 件で結果が分かれる入力（受け入れ条件 2）', () => {
  /** PHP 7.4.3 が ubuntu:20.04 と ubuntu:22.04 の両方にある合成の対応表（確信度 low・候補 2 件） */
  function splitDb(): DbWithDistro {
    return dbWithAdvisories(
      {
        'ubuntu:20.04': { 'php7.4': [fixedEntry(PHP_CVES[1], [OLDER_FIX]), notAffectedEntry(PHP_CVES[0])] },
        'ubuntu:22.04': { 'php7.4': [fixedEntry(PHP_CVES[1], [NEWER_FIX])] },
      },
      (db) => {
        const base = db.distro!.map.find((e) => e.release === 'ubuntu:20.04' && e.product === 'php')!;
        db.distro!.map.push({ ...base, release: 'ubuntu:22.04', codename: 'jammy' });
      }
    );
  }

  it('前提: 合成の対応表で PHP 7.4.3 の候補は 2 件', () => {
    setTestAdvisoryDatabase(splitDb());
    const php = tech(detect(PHP_UBUNTU), 'PHP');
    expect(php.distroInference?.candidates).toEqual(['ubuntu:20.04', 'ubuntu:22.04']);
  });

  it('悪いほう（not-fixed・no-data）が採られ、数えられる。分かれたことを注記する', async () => {
    setTestAdvisoryDatabase(splitDb());
    const report = await executeInspection(deps(PHP_UBUNTU));
    const da = tech(report.technologies, 'PHP').distroAdvisories!;
    const fixedOrNot = da.cves.find((c) => c.cve === PHP_CVES[1])!;
    expect(fixedOrNot.distroStatus).toBe('not-fixed');
    expect(fixedOrNot.split).toBe(true);
    const affectedOrNoData = da.cves.find((c) => c.cve === PHP_CVES[0])!;
    expect(affectedOrNoData.distroStatus).toBe('no-data');
    expect(da.reviewCount).toBe(2);
    expect(da.splitNote).toMatch(/分かれ/);
    expect(distroCveChecks(report, 'PHP')).toHaveLength(1);
  });

  it('分かれた注記が、ポップアップ・ダッシュボード・Markdown に出る', async () => {
    setTestAdvisoryDatabase(splitDb());
    const report = await executeInspection(deps(PHP_UBUNTU));
    const php = tech(report.technologies, 'PHP');
    expect(renderTechModalHtml(php)).toMatch(/分かれ/);
    expect(renderFullTechnologiesHtml([php])).toMatch(/分かれ/);
    expect(generateMarkdownReport(report)).toMatch(/分かれ/);
  });
});

describe('T06 H5・H9: 第三者リポジトリ・バックポートの入力では、ディストリのデータを使わない（受け入れ条件 3）', () => {
  /** どのリリース・ソースパッケージにもデータがある DB（使ってしまえば distroStatus が付く） */
  const everywhere = (): DbWithDistro => {
    const adv: Record<string, Record<string, DistroAdvisoryEntry[]>> = {};
    for (const e of fixture.distro!.map) {
      if (e.family !== 'ubuntu' && e.family !== 'debian') continue;
      (adv[e.release] ??= {})[e.sourcePackage] = [...PHP_CVES, APACHE_CVE].map((c) => fixedEntry(c, ['1:99.0-1']));
    }
    return dbWithAdvisories(adv);
  };

  it.each([
    ['deb.sury.org', { 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }],
    ['+ubuntuNN.NN', { 'x-powered-by': ['PHP/7.4.3-1+ubuntu20.04.1'] }],
    ['~bpo', { 'x-powered-by': ['PHP/7.4.33-1~bpo10+1'] }],
  ])('%s: distroAdvisories を付けず、SEC-DISTRO-CVE も出さず、照合は第1段階（advisories の無い DB）と同じ', async (_label, headers) => {
    const reference = await executeInspection(deps(headers));
    const refPhp = tech(reference.technologies, 'PHP');

    setTestAdvisoryDatabase(everywhere());
    const report = await executeInspection(deps(headers));
    const php = tech(report.technologies, 'PHP');
    expect(php.distroInference?.thirdParty).toBeDefined();
    expect(php.distroAdvisories).toBeUndefined();
    expect(JSON.stringify(php)).not.toContain('distroStatus');
    expect(distroCveChecks(report, 'PHP')).toHaveLength(0);
    expect(php.advisoryMatchStatus).toBe(refPhp.advisoryMatchStatus);
    expect(php.upstreamAdvisoriesCount).toBe(refPhp.upstreamAdvisoriesCount);
    expect(php.advisories).toEqual(refPhp.advisories);
    expect(report.summary.requiresAttentionCount).toBe(reference.summary.requiresAttentionCount);
  });

  it('リリースを推定できない（確信度 none）入力でもディストリのデータを使わない', async () => {
    setTestAdvisoryDatabase(everywhere());
    const report = await executeInspection(deps({ server: ['Apache/2.4.99 (Ubuntu)'] }));
    const apache = tech(report.technologies, 'Apache');
    expect(apache.distroInference?.confidence).toBe('none');
    expect(apache.distroAdvisories).toBeUndefined();
    expect(distroCveChecks(report, 'Apache')).toHaveLength(0);
  });

  it('RHEL 系（.el9）はディストリのデータで判定しない（H1）', async () => {
    setTestAdvisoryDatabase(
      dbWithAdvisories({ 'rhel:9': { httpd: [fixedEntry(APACHE_CVE, ['2.4.62-1.el9'])] } })
    );
    const report = await executeInspection(deps({ server: ['Apache/2.4.62 (Red Hat Enterprise Linux) OpenSSL/3.0.7'] }));
    for (const t of report.technologies) expect(t.distroAdvisories).toBeUndefined();
  });
});

describe('T06: ポップアップ・ダッシュボード・Markdown / JSON / CSV に区分と修正版を出す', () => {
  async function notFixedReport(): Promise<InspectionReport> {
    setTestAdvisoryDatabase(
      dbWithAdvisories({
        'ubuntu:20.04': {
          'php7.4': [
            fixedEntry(PHP_CVES[0], [NEWER_FIX], [`UBUNTU-${PHP_CVES[0]}`, 'USN-6757-1']),
            fixedEntry(PHP_CVES[1], [OLDER_FIX]),
            fixedEntry('CVE-2021-21702', [OLDER_FIX]),
            fixedEntry('CVE-2021-21703', [OLDER_FIX]),
          ],
        },
      })
    );
    return executeInspection(deps(PHP_UBUNTU));
  }

  const outputsOf = (report: InspectionReport) => {
    const php = tech(report.technologies, 'PHP');
    return {
      popup: renderTechModalHtml(php),
      dashboard: renderFullTechnologiesHtml([php]),
      markdown: generateMarkdownReport(report),
      csv: exportReportToCsv(report),
    };
  };

  it.each(['popup', 'dashboard', 'markdown', 'csv'] as const)('%s: CVE ごとの区分（not-fixed・fixed）と修正版が出る', async (where) => {
    const out = outputsOf(await notFixedReport())[where];
    expect(out).toContain(PHP_CVES[0]);
    expect(out).toContain('not-fixed');
    expect(out).toContain(NEWER_FIX);
    expect(out).toContain(PHP_CVES[1]);
    expect(out).toMatch(/(^|[^-])fixed/);
  });

  it.each(['popup', 'dashboard', 'markdown'] as const)('%s: ディストリにだけある fixed の CVE は並べず「ほかにディストリで修正済み N 件」と出す', async (where) => {
    const report = await notFixedReport();
    const n = tech(report.technologies, 'PHP').distroAdvisories!.otherFixedCount;
    expect(n).toBe(2);
    const out = outputsOf(report)[where];
    expect(out).toContain(`ほかにディストリで修正済み ${n} 件`);
    expect(out).not.toContain('CVE-2021-21702');
    expect(out).not.toContain('CVE-2021-21703');
  });

  it('JSON: CVE ごとの distroStatus・修正版・OSV ID と、出典（_source の要素）が出る', async () => {
    const parsed = JSON.parse(exportReportToJson(await notFixedReport())) as InspectionReport;
    const php = parsed.technologies.find((t) => t.technology === 'PHP')!;
    const c = php.distroAdvisories!.cves.find((x) => x.cve === PHP_CVES[0])!;
    expect(c.distroStatus).toBe('not-fixed');
    expect(c.fixedVersions).toEqual([NEWER_FIX]);
    expect([...c.osvIds].sort()).toEqual([`UBUNTU-${PHP_CVES[0]}`, 'USN-6757-1'].sort());
    const ubuntu = php.distroAdvisories!.sources.find((s) => s.ecosystem === 'Ubuntu');
    expect(ubuntu).toMatchObject({ name: SOURCES[1].name, url: SOURCES[1].url, license: SOURCES[1].license });
  });

  it('ESM だけの修正は、ポップアップと Markdown で「ESM で修正」と区別して出る', async () => {
    setTestAdvisoryDatabase(
      dbWithAdvisories({
        'ubuntu:20.04': { 'php7.4': [{ cve: PHP_CVES[0], status: 'fixed', fixedVersions: ['7.4.3-4ubuntu2.19+esm1'], esm: true, osvIds: [`UBUNTU-${PHP_CVES[0]}`] }] },
      })
    );
    const report = await executeInspection(deps(PHP_UBUNTU));
    expect(renderTechModalHtml(tech(report.technologies, 'PHP'))).toContain('ESM で修正');
    expect(generateMarkdownReport(report)).toContain('ESM で修正');
  });

  it('distroAdvisories の無い技術（固定 DB・旧い履歴）では、区分の表示を出さない（陰性）', async () => {
    const report = await executeInspection(deps(PHP_UBUNTU));
    const out = outputsOf(report);
    for (const text of Object.values(out)) {
      expect(text).not.toContain('not-fixed');
      expect(text).not.toContain('unknown-revision');
      expect(text).not.toContain('ほかにディストリで修正済み');
    }
  });

  it.each(Object.keys(SCENARIOS) as Status[])('%s: 判定・指摘・画面表示・エクスポートに禁止語が無い（H4）', async (status) => {
    const s = SCENARIOS[status];
    setTestAdvisoryDatabase(dbWithAdvisories(s.advisories));
    const report = await executeInspection(deps(s.headers));
    const t = tech(report.technologies, s.techName);
    const texts: string[] = [];
    collectStrings(t.distroAdvisories, texts);
    for (const c of distroCveChecks(report, s.techName)) collectStrings([c.name, c.observed, c.description, c.recommendation], texts);
    texts.push(renderTechModalHtml(t), renderFullTechnologiesHtml([t]), renderLibrarySecurityTableHtml([t]));
    for (const text of texts) {
      for (const w of FORBIDDEN_WORDS) expect(text, `「${w}」を含む`).not.toContain(w);
    }
  });
});

describe('T06: reports:lint が通る（受け入れ条件 4）', () => {
  it.each([
    ['数える区分と数えない区分が混ざる PHP と、unknown-revision の Apache', {
      server: ['Apache/2.4.41 (Ubuntu)'],
      'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'],
    }],
    ['分かれない PHP だけ', PHP_UBUNTU],
  ])('%s: CVE ごとの判定を含むレポートの JSON と Markdown の組が lintReportPair を通る', async (_label, headers) => {
    setTestAdvisoryDatabase(
      dbWithAdvisories({
        'ubuntu:20.04': {
          'php7.4': [fixedEntry(PHP_CVES[0], [NEWER_FIX]), fixedEntry(PHP_CVES[1], [OLDER_FIX]), fixedEntry('CVE-2021-21702', [OLDER_FIX])],
          apache2: [fixedEntry(APACHE_CVE, [APACHE_FIX])],
        },
      })
    );
    const report = await executeInspection(deps(headers));
    // 前提: CVE ごとの判定を含むレポートであること
    expect(report.technologies.some((t) => t.distroAdvisories)).toBe(true);
    const json = JSON.parse(exportReportToJson(report));
    const md = generateMarkdownReport(report);
    const result = lintReportPair(json, md);
    expect(result.violations, JSON.stringify(result.violations, null, 2)).toEqual([]);
    expect(result.ok).toBe(true);
  });
});
