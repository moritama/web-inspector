/**
 * v1.8.1 T03: OS リリースの推定を engine・調査（executeInspection）・表示・エクスポートに組み込んだ結果の受け入れテスト
 *
 * - engine が製品ごとに distroInference を付け、EOL を OS のライフサイクルで判定する（§3.2）
 * - 上流の EOL は参考表示（upstreamEolInfo）にして、要確認件数・EOL 件数に数えない（二重に数えない）
 * - distro 節が無い DB では第1段階と同じ出力（§5.3）
 * - ポップアップ・ダッシュボード・Markdown / JSON / CSV に、推定したリリース・確信度・根拠を出す
 * - reports:lint（scripts/report-lint.mjs）が通る
 *
 * 照合は固定 DB（tests/fixtures/advisory-db.fixture.json）を使う。日付は直接書かず、
 * 合成 DB のライフサイクルの日付は「今日」からの相対で作る。
 */
import * as fs from 'fs';
import * as path from 'path';
import { describe, expect, it, vi } from 'vitest';
import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { AdvisoryDatabase, matchOfflineAdvisories, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { DetectionEngine } from '../src/detection/engine';
import { exportReportToCsv } from '../src/export/csv';
import { exportReportToJson } from '../src/export/json';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderFullTechnologiesHtml, renderLibrarySecurityTableHtml } from '../src/dashboard/render';
import { renderTechModalHtml } from '../src/popup/render';
import type { AdvisoryDistroSection, DetectedTechnology, DomSignals, InspectionReport } from '../src/shared/types';
// @ts-expect-error scripts/report-lint.mjs は型定義を持たない .mjs モジュール
import { lintReportPair } from '../scripts/report-lint.mjs';
import { REPO_ROOT } from './helpers/release-version';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

type DbWithDistro = AdvisoryDatabase & { distro?: AdvisoryDistroSection; integrity?: Record<string, unknown> };

const fixture = rawFixtureDb as unknown as DbWithDistro;
const FORBIDDEN_WORDS = ['該当なし', '安全', 'Not Affected'];
const HOST = 'https://www.example.test/';

/** 今日（UTC）から shiftDays 日ずらした YYYY-MM-DD */
function isoFromToday(shiftDays: number): string {
  return new Date(Date.now() + shiftDays * 86_400_000).toISOString().slice(0, 10);
}

/** 固定 DB の複製。distro 節のライフサイクルの標準サポート終了日を書き換える */
function dbWithStandardEnds(ends: Record<string, string>): DbWithDistro {
  const db = structuredClone(fixture);
  for (const r of db.distro!.releases) {
    if (r.release in ends) r.standardSupportEnd = ends[r.release];
  }
  return db;
}

/** distro 節を外し schema を 2.2 に戻した旧 DB（v1.8.0 以前の同梱 DB と同じ形） */
function legacyDb(): DbWithDistro {
  const db = structuredClone(fixture);
  delete db.distro;
  db.schemaVersion = '2.2';
  if (db.integrity) delete db.integrity.distroDigest;
  return db;
}

const emptyDom = (): DomSignals => ({
  url: HOST,
  title: 'Distro inference test',
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
    fetchDomSignals: vi.fn().mockResolvedValue({
      ...emptyDom(),
      scriptUrls: ['https://www.example.test/assets/app.js'],
    }),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue({ url: HOST, headers }),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  };
}

function eolChecksOf(report: InspectionReport, techName: string) {
  const prefix = `SEC-EOL-${techName.toUpperCase()}`;
  return report.securityChecks.filter((c) => c.checkId === prefix || c.checkId.startsWith(`${prefix}-`));
}

function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectStrings(v, out));
  return out;
}

function eolText(eol: { label?: string; note?: string; recommendation?: string } | undefined): string {
  return eol ? [eol.label, eol.note, eol.recommendation].filter(Boolean).join('\n') : '';
}

describe('T03: engine が製品ごとに distroInference を付ける', () => {
  it('Server: Apache/2.4.41 (Ubuntu) の Apache に distroInference（family・release・candidates・confidence・evidence）が付き、照合は Needs Review のまま', () => {
    const apache = tech(detect({ server: ['Apache/2.4.41 (Ubuntu)'] }), 'Apache');
    expect(apache.distroInference).toBeDefined();
    expect(apache.distroInference).toMatchObject({
      family: 'ubuntu',
      release: 'ubuntu:20.04',
      candidates: ['ubuntu:20.04'],
      confidence: 'medium',
    });
    expect(apache.distroInference!.evidence.length).toBeGreaterThan(0);
    expect(apache.advisoryMatchStatus).toBe('Needs Review');
    expect(apache.distroHint).toBe('Ubuntu');
  });

  it('同じ応答の nginx と PHP（X-Powered-By）の候補の積集合を、それぞれの製品に付ける（high）', () => {
    const techs = detect({ server: ['nginx/1.18.0 (Ubuntu)'], 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] });
    expect(tech(techs, 'Nginx').distroInference).toMatchObject({ release: 'ubuntu:20.04', confidence: 'high' });
    expect(tech(techs, 'PHP').distroInference).toMatchObject({ release: 'ubuntu:20.04', confidence: 'high' });
  });

  it('ディストリの印が無い製品には distroInference を付けない（陰性）', () => {
    const techs = detect({ server: ['Apache/2.4.58 (Unix)'], 'x-powered-by': ['PHP/8.2.10'] });
    expect(tech(techs, 'Apache').distroInference).toBeUndefined();
    expect(tech(techs, 'PHP').distroInference).toBeUndefined();
  });

  it('受け入れ条件 2: deb.sury.org を含む PHP の版はリリースを推定せず thirdParty が付き、EOL は第1段階の表示のまま', () => {
    const php = tech(detect({ 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }), 'PHP');
    expect(php.distroInference?.thirdParty).toBeDefined();
    expect(php.distroInference?.release).toBeNull();
    expect(php.distroInference?.candidates).toEqual([]);
    expect(php.distroInference?.note).toContain('第三者リポジトリ');
    const firstStage = matchOfflineAdvisories('PHP', php.version, fixture, { distroHint: php.distroHint });
    expect(php.supportStatus).toBe(firstStage.eolInfo.status);
    expect(php.eolDate ?? null).toBe(firstStage.eolInfo.eolDate);
  });

  it('受け入れ条件 2: ~bpo を含む版はリリースを推定せず thirdParty が付く', () => {
    const php = tech(detect({ 'x-powered-by': ['PHP/7.4.33-1~bpo10+1'] }), 'PHP');
    expect(php.distroInference?.thirdParty).toBeDefined();
    expect(php.distroInference?.release).toBeNull();
    expect(php.distroInference?.candidates).toEqual([]);
  });

  it('候補が無いときは EOL を第1段階の表示のまま残し、注記に「リリースを推定できない」旨を付ける', () => {
    const apache = tech(detect({ server: ['Apache/2.4.99 (Ubuntu)'] }), 'Apache');
    expect(apache.distroInference?.confidence).toBe('none');
    expect(apache.distroInference?.note).toMatch(/リリースを推定でき/);
    const firstStage = matchOfflineAdvisories('Apache', apache.version, fixture, { distroHint: apache.distroHint });
    expect(apache.supportStatus).toBe(firstStage.eolInfo.status);
  });
});

describe('T03 §3.2: EOL を OS のライフサイクルで判定し、上流の EOL は参考にして数えない（受け入れ条件 4）', () => {
  const PHP_DEB11 = { 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] };

  it('前提: 固定 DB で PHP 7.4 の上流の EOL は EOL（参考表示の対象）', () => {
    expect(matchOfflineAdvisories('PHP', '7.4.33', fixture).eolInfo.status).toBe('EOL');
  });

  it('OS の標準サポートが終わっていれば EOL。日付は OS のライフサイクル、上流の EOL は upstreamEolInfo に参考として残す', () => {
    const end = isoFromToday(-30);
    setTestAdvisoryDatabase(dbWithStandardEnds({ 'debian:11': end }));
    const php = tech(detect(PHP_DEB11), 'PHP');
    expect(php.supportStatus).toBe('EOL');
    expect(php.eolDate).toBe(end);
    expect(eolText(php.eolInfo)).toContain('Debian 11');
    expect(eolText(php.eolInfo)).toContain('推定');
    expect(php.upstreamEolInfo).toBeDefined();
    expect(php.upstreamEolInfo?.status).toBe('EOL');
    expect(eolText(php.upstreamEolInfo)).toContain('参考');
  });

  it('OS の標準サポート中なら、上流が EOL でも EOL にせず数えない（SEC-EOL も EOL 件数も 0）。Supported とも断定しない', async () => {
    setTestAdvisoryDatabase(dbWithStandardEnds({ 'debian:11': isoFromToday(365) }));
    const report = await executeInspection(deps(PHP_DEB11));
    const php = tech(report.technologies, 'PHP');
    expect(php.supportStatus).not.toBe('EOL');
    expect(php.supportStatus).not.toBe('Supported');
    expect(php.upstreamEolInfo?.status).toBe('EOL');
    expect(eolChecksOf(report, 'PHP')).toHaveLength(0);
    expect(report.summary.librarySecurity.eolCount).toBe(0);
  });

  it('OS と上流の両方が EOL でも、PHP の EOL は 1 件だけ数える（二重に数えない）。指摘の文言に推定である旨がある', async () => {
    setTestAdvisoryDatabase(dbWithStandardEnds({ 'debian:11': isoFromToday(-30) }));
    const report = await executeInspection(deps(PHP_DEB11));
    const checks = eolChecksOf(report, 'PHP');
    expect(checks).toHaveLength(1);
    const allEolChecks = report.securityChecks.filter((c) => c.checkId.startsWith('SEC-EOL-'));
    expect(report.summary.librarySecurity.eolCount).toBe(allEolChecks.length);
    const c = checks[0];
    expect([c.name, c.observed, c.description, c.recommendation].join('\n')).toContain('推定');
  });

  it('重大度の区分は既存の EOL 判定（SPEC-04）に合わせる: 推定の EOL も上流の EOL の指摘と同じ重大度', async () => {
    setTestAdvisoryDatabase(dbWithStandardEnds({ 'debian:11': isoFromToday(-30) }));
    const inferred = eolChecksOf(await executeInspection(deps(PHP_DEB11)), 'PHP')[0];
    setTestAdvisoryDatabase(fixture);
    const upstream = eolChecksOf(await executeInspection(deps({ 'x-powered-by': ['PHP/7.4.33'] })), 'PHP')[0];
    expect(upstream).toBeDefined();
    expect(inferred.severity).toBe(upstream.severity);
    expect(inferred.status).toBe(upstream.status);
  });

  it('候補が 2 件以上: いちばん早く終わる候補で判定する（nginx 1.18.0 の 20.04 と 22.04）', () => {
    const early = isoFromToday(-10);
    setTestAdvisoryDatabase(dbWithStandardEnds({ 'ubuntu:20.04': isoFromToday(400), 'ubuntu:22.04': early }));
    const nginx = tech(detect({ server: ['nginx/1.18.0 (Ubuntu)'] }), 'Nginx');
    expect(nginx.distroInference?.confidence).toBe('low');
    expect(nginx.supportStatus).toBe('EOL');
    expect(nginx.eolDate).toBe(early);
    const text = eolText(nginx.eolInfo);
    expect(text).toContain('Ubuntu 20.04');
    expect(text).toContain('Ubuntu 22.04');
  });

  it('インスタンス（バージョン別）の EOL も OS のライフサイクルの判定と一致する', () => {
    setTestAdvisoryDatabase(dbWithStandardEnds({ 'debian:11': isoFromToday(-30) }));
    const php = tech(detect(PHP_DEB11), 'PHP');
    expect(php.supportStatus).toBe('EOL');
    for (const inst of php.instances ?? []) {
      expect(inst.supportStatus ?? inst.eol.status).toBe(php.supportStatus);
    }
  });
});

describe('T03 §5.3: distro 節が無い DB では第1段階と同じ出力（受け入れ条件 5）', () => {
  const HEADERS = {
    server: ['Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f'],
    'x-powered-by': ['PHP/7.4.33-1+deb11u5'],
  };

  it('旧 DB では distroInference・upstreamEolInfo を付けず、EOL は第1段階の照合結果と同じ', () => {
    const db = legacyDb();
    setTestAdvisoryDatabase(db);
    const techs = detect(HEADERS);
    for (const name of ['Apache', 'PHP']) {
      const t = tech(techs, name);
      expect(t.distroInference).toBeUndefined();
      expect(t.upstreamEolInfo).toBeUndefined();
      const firstStage = matchOfflineAdvisories(name, t.version, db, { distroHint: t.distroHint });
      expect(t.eolInfo).toEqual(firstStage.eolInfo);
      expect(t.supportStatus).toBe(firstStage.eolInfo.status);
      expect(t.advisoryMatchStatus).toBe(firstStage.matchStatus);
    }
  });

  it('旧 DB では、同梱 DB の distro 節で補わない（差し替えた DB に distro 節が無ければ推定しない）', () => {
    setTestAdvisoryDatabase(legacyDb());
    for (const t of detect({ server: ['nginx/1.18.0 (Ubuntu)'], 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] })) {
      expect(t.distroInference).toBeUndefined();
    }
  });

  it('旧 DB の調査では、ディストリ版の製品の EOL の指摘は出ない（第1段階どおり）', async () => {
    setTestAdvisoryDatabase(legacyDb());
    const report = await executeInspection(deps(HEADERS));
    expect(eolChecksOf(report, 'Apache')).toHaveLength(0);
    expect(eolChecksOf(report, 'PHP')).toHaveLength(0);
  });

  it('ライフサイクルの取得結果が無い（releases が空）DB では、推定は付けるが EOL は第1段階のまま（失敗しない）', async () => {
    const db = structuredClone(fixture);
    db.distro!.releases = [];
    setTestAdvisoryDatabase(db);
    const report = await executeInspection(deps({ server: ['Apache/2.4.41 (Ubuntu)'] }));
    const apache = tech(report.technologies, 'Apache');
    expect(apache.distroInference?.release).toBe('ubuntu:20.04');
    const firstStage = matchOfflineAdvisories('Apache', apache.version, db, { distroHint: apache.distroHint });
    expect(apache.supportStatus).toBe(firstStage.eolInfo.status);
    expect(eolChecksOf(report, 'Apache')).toHaveLength(0);
  });
});

describe('T03 H4: 推定した結果はどれも Needs Review で、「該当なし」「安全」の文言が出ない（受け入れ条件 3）', () => {
  const SCENARIOS: Array<[string, Record<string, string[]>]> = [
    ['high（印）', { 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] }],
    ['high（積集合）', { server: ['nginx/1.18.0 (Ubuntu)'], 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] }],
    ['medium', { server: ['Apache/2.4.41 (Ubuntu)'] }],
    ['low', { server: ['nginx/1.18.0 (Ubuntu)'] }],
    ['none', { server: ['Apache/2.4.99 (Ubuntu)'] }],
    ['第三者リポジトリ', { 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }],
    ['バックポート', { 'x-powered-by': ['PHP/7.4.33-1~bpo10+1'] }],
  ];

  // ~bpo の版は第1段階でディストリ版の印（distroHint）が付かず、上流の版で照合される。T03 は第三者・バックポートを
  // 「第1段階の表示のまま」にする（§3.2）ので、照合の区分はこの検査の対象にしない（thirdParty が付くことは別のテストで確かめる）
  const NEEDS_REVIEW_SCENARIOS = SCENARIOS.filter(([label]) => label !== 'バックポート');

  it.each(NEEDS_REVIEW_SCENARIOS)('%s: 照合は Needs Review、サポート状況は Supported と断定しない', (_label, headers) => {
    for (const ends of [isoFromToday(-30), isoFromToday(365)]) {
      setTestAdvisoryDatabase(
        dbWithStandardEnds({ 'ubuntu:20.04': ends, 'ubuntu:22.04': ends, 'debian:11': ends })
      );
      const inferred = detect(headers).filter((t) => t.distroInference);
      expect(inferred.length).toBeGreaterThan(0);
      for (const t of inferred) {
        expect(t.advisoryMatchStatus).toBe('Needs Review');
        expect(t.supportStatus).not.toBe('Supported');
      }
    }
  });

  it.each(SCENARIOS)('%s: 推定・判定の文言と、EOL の指摘・画面表示に禁止語が無い', async (_label, headers) => {
    for (const ends of [isoFromToday(-30), isoFromToday(365)]) {
      setTestAdvisoryDatabase(
        dbWithStandardEnds({ 'ubuntu:20.04': ends, 'ubuntu:22.04': ends, 'debian:11': ends })
      );
      const report = await executeInspection(deps(headers));
      const inferred = report.technologies.filter((t) => t.distroInference);
      expect(inferred.length).toBeGreaterThan(0);
      const texts: string[] = [];
      for (const t of inferred) {
        collectStrings(t.distroInference, texts);
        collectStrings(t.eolInfo, texts);
        collectStrings(t.upstreamEolInfo, texts);
        for (const c of eolChecksOf(report, t.technology)) collectStrings([c.name, c.observed, c.description, c.recommendation], texts);
        texts.push(renderTechModalHtml(t), renderFullTechnologiesHtml([t]), renderLibrarySecurityTableHtml([t]));
      }
      for (const text of texts) {
        for (const w of FORBIDDEN_WORDS) expect(text, `「${w}」を含む`).not.toContain(w);
      }
    }
  });
});

describe('T03 §3.2: ポップアップ・ダッシュボード・Markdown / JSON / CSV に推定したリリース・確信度・根拠を出す', () => {
  const SERVER = 'Apache/2.4.41 (Ubuntu)';

  async function inferredReport(): Promise<InspectionReport> {
    return executeInspection(deps({ server: [SERVER], 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }));
  }

  it('ポップアップの技術の詳細に、推定したリリース・確信度・根拠（ヘッダーの値）が出る', async () => {
    const apache = tech((await inferredReport()).technologies, 'Apache');
    const html = renderTechModalHtml(apache);
    expect(html).toContain('Ubuntu 20.04');
    expect(html).toContain('推定');
    expect(html).toMatch(/確信度/);
    expect(html).toContain(SERVER);
  });

  it('ポップアップの技術の詳細に、第三者リポジトリの注記が出る', async () => {
    const php = tech((await inferredReport()).technologies, 'PHP');
    expect(renderTechModalHtml(php)).toContain('第三者リポジトリ');
  });

  it('ダッシュボードの技術一覧に、推定したリリース・確信度・根拠が出て、ライブラリのセキュリティ表にリリースが出る', async () => {
    const report = await inferredReport();
    const apache = tech(report.technologies, 'Apache');
    const full = renderFullTechnologiesHtml([apache]);
    expect(full).toContain('Ubuntu 20.04');
    expect(full).toContain('推定');
    expect(full).toMatch(/確信度/);
    expect(full).toContain(SERVER);
    expect(renderLibrarySecurityTableHtml([apache])).toContain('Ubuntu 20.04');
    expect(renderFullTechnologiesHtml([tech(report.technologies, 'PHP')])).toContain('第三者リポジトリ');
  });

  it('Markdown レポートに、推定したリリース・確信度・根拠と第三者リポジトリの注記が出る', async () => {
    const md = generateMarkdownReport(await inferredReport());
    expect(md).toContain('Ubuntu 20.04');
    expect(md).toMatch(/確信度/);
    expect(md).toContain('推定');
    expect(md).toContain(SERVER);
    expect(md).toContain('第三者リポジトリ');
  });

  it('Markdown レポートに、候補が無いときの「リリースを推定できない」旨が出る', async () => {
    const md = generateMarkdownReport(await executeInspection(deps({ server: ['Apache/2.4.99 (Ubuntu)'] })));
    expect(md).toMatch(/リリースを推定でき/);
  });

  it('JSON エクスポートに distroInference（family・release・candidates・confidence・evidence・thirdParty）が出る', async () => {
    const parsed = JSON.parse(exportReportToJson(await inferredReport())) as InspectionReport;
    const apache = parsed.technologies.find((t) => t.technology === 'Apache')!;
    expect(apache.distroInference).toMatchObject({ family: 'ubuntu', release: 'ubuntu:20.04', candidates: ['ubuntu:20.04'], confidence: 'medium' });
    expect(apache.distroInference!.evidence.some((e) => e.value === SERVER)).toBe(true);
    const php = parsed.technologies.find((t) => t.technology === 'PHP')!;
    expect(php.distroInference?.thirdParty).toBeDefined();
  });

  it('CSV エクスポートに、推定したリリースと確信度、第三者リポジトリの注記が出る', async () => {
    const csv = exportReportToCsv(await inferredReport());
    expect(csv).toContain('Ubuntu 20.04');
    expect(csv).toMatch(/確信度/);
    expect(csv).toContain('第三者リポジトリ');
  });

  it('根拠のヘッダーの値は、ポップアップとダッシュボードで HTML としてエスケープされる', async () => {
    const evil = 'Apache/2.4.41 (Ubuntu) <img src=x onerror=alert(1)>';
    const apache = tech((await executeInspection(deps({ server: [evil] }))).technologies, 'Apache');
    expect(apache.distroInference).toBeDefined();
    for (const html of [renderTechModalHtml(apache), renderFullTechnologiesHtml([apache])]) {
      expect(html).not.toContain('<img src=x');
      expect(html).toContain('&lt;img');
    }
  });
});

describe('T03: reports:lint が通る（受け入れ条件 6）', () => {
  it.each([
    ['OS の EOL あり（固定 DB の日付）', {}, null],
    ['OS の EOL あり（終了日を過去にした合成 DB）', { 'ubuntu:20.04': isoFromToday(-30), 'debian:11': isoFromToday(-30) }, true],
    ['OS の EOL なし（終了日を未来にした合成 DB）', { 'ubuntu:20.04': isoFromToday(365), 'debian:11': isoFromToday(365) }, false],
  ] as Array<[string, Record<string, string>, boolean | null]>)('%s: 推定を含むレポートの JSON と Markdown の組が lintReportPair を通る', async (_label, ends, expectOsEol) => {
    setTestAdvisoryDatabase(dbWithStandardEnds(ends));
    const report = await executeInspection(
      deps({
        server: ['Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f'],
        'x-powered-by': ['PHP/7.4.33-1+deb11u5'],
      })
    );
    // 前提: 推定の結果を含むレポートであること（推定が無いレポートでは検査の意味が無い）
    expect(tech(report.technologies, 'Apache').distroInference).toBeDefined();
    expect(tech(report.technologies, 'PHP').distroInference).toBeDefined();
    if (expectOsEol !== null) {
      expect(eolChecksOf(report, 'Apache')).toHaveLength(expectOsEol ? 1 : 0);
      expect(eolChecksOf(report, 'PHP')).toHaveLength(expectOsEol ? 1 : 0);
    }
    const json = JSON.parse(exportReportToJson(report));
    const md = generateMarkdownReport(report);
    const result = lintReportPair(json, md);
    expect(result.violations, JSON.stringify(result.violations, null, 2)).toEqual([]);
    expect(result.ok).toBe(true);
  });
});

describe('T03: docs/DETECTION_SPECIFICATION.md に推定の規則と確信度の表がある', () => {
  const spec = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'DETECTION_SPECIFICATION.md'), 'utf-8');

  it('distroInference と、第三者リポジトリ・バックポートの印（deb.sury.org・+ubuntuNN.NN・~bpo）が書かれている', () => {
    expect(spec).toContain('distroInference');
    expect(spec).toContain('deb.sury.org');
    expect(spec).toContain('~bpo');
    expect(spec).toMatch(/\+ubuntu/);
  });

  it('確信度の表に high・medium・low・none の行がある', () => {
    for (const level of ['high', 'medium', 'low', 'none']) {
      expect(spec).toMatch(new RegExp(`^\\|\\s*\`?${level}\`?\\s*\\|`, 'm'));
    }
  });
});
