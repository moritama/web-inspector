// @vitest-environment happy-dom
/**
 * T01: 表示用の文言の整理とポップアップのレイアウト（C）の受け入れテスト
 *
 * 設計メモ: 今回の版の作業フォルダ（docs/dev/ の下）の design/T01.md
 *
 * - H4: 判定側（judgeDistroEol）の eolInfo.label はリリース名だけ（「確信度」「推定・」を含まない）。eolInfo.note は確信度入りのまま
 * - §3.2-2: formatDistroReleaseDisplay の分岐 (2)（OS のライフサイクルの label を使う）を削除する
 * - §3.2-3: formatDistroReleaseWithConfidence(tech) を足し、指摘文（SEC-EOL-* の観測値・説明、SEC-DISTRO-CVE-* の観測値）に使う
 * - §3.3: 候補 1 件・2 件以上のそれぞれで、ポップアップの一覧・モーダル・ダッシュボード・CSV・Markdown・指摘文に、
 *   OS の推定の確信度（高・中・低）がちょうど 1 回（ポップアップの一覧は 0 回。既存の検出の確信度バッジだけ）
 *   eolInfo.note（説明の全文。§3.2-1 で確信度入りのまま）は数えない
 * - H5・§3.2-5: ポップアップの一覧の「ディストリ版」は .item-meta に短縮形で出し、全文は title
 * - §3.2-4: ポップアップの CSS（.item-main・.item-side）
 * - 第三者・none・対応表に無い版は従来どおり「推定なし」で、断定しない
 *
 * 照合は固定 DB（tests/fixtures/advisory-db.fixture.json）を複製して使う。日付は「今日」からの相対で作る。
 * 固定 DB で、PHP 7.4.3 の上流の照合には CVE-2024-4577 が含まれる（tests/distro-advisory-report.test.ts と同じ前提）。
 */
import * as fs from 'fs';
import * as path from 'path';
import { describe, expect, it, vi } from 'vitest';
import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { AdvisoryDatabase, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { inferDistroFromHeaders, judgeDistroEol } from '../src/detection/distro-inference';
import { exportReportToCsv } from '../src/export/csv';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderFullTechnologiesHtml, renderLibrarySecurityTableHtml } from '../src/dashboard/render';
import * as popupRender from '../src/popup/render';
import { renderTechModalHtml } from '../src/popup/render';
import * as distroDisplay from '../src/shared/distro-display';
import { formatDistroConfidenceJp, formatDistroReleaseDisplay, formatDistroReleaseName } from '../src/shared/distro-display';
import type {
  AdvisoryDistroSection,
  DetectedTechnology,
  DistroAdvisoryEntry,
  DistroInference,
  DomSignals,
  EolInfo,
  InspectionReport,
  SecurityCheckResult,
} from '../src/shared/types';
import { REPO_ROOT } from './helpers/release-version';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

type DbWithDistro = AdvisoryDatabase & { distro?: AdvisoryDistroSection };

const fixture = rawFixtureDb as unknown as DbWithDistro;
const HOST = 'https://www.example.test/';
const OS_LIFECYCLE_SOURCE = 'endoflife.date（OS のライフサイクル）';
const FORBIDDEN_WORDS = ['該当なし', '安全', 'Not Affected'];

/** OS の推定の確信度の表記（「確信度 高」「確信度: 中」「推定・確信度 低」など）。検出の確信度（数値・英語）は数えない */
const DISTRO_CONF_RE = /確信度[\s:：]*[高中低]/g;

function countDistroConf(text: string): number {
  return (text.match(DISTRO_CONF_RE) || []).length;
}

/** 説明の全文（eolInfo.note・distroInference.note）は確信度入りのままでよい（§3.2-1）ので、数える前に取り除く */
function withoutNotes(text: string, t: DetectedTechnology): string {
  const notes = new Set<string>();
  const add = (s: string | undefined) => {
    if (s) notes.add(s);
  };
  add(t.eolInfo?.note);
  add(t.distroInference?.note);
  for (const inst of t.instances || []) {
    add(inst.eol?.note);
    add(inst.eolInfo?.note);
  }
  let out = text;
  for (const n of notes) out = out.split(n).join('');
  return out;
}

function htmlText(html: string): string {
  return new DOMParser().parseFromString(`<!doctype html><body>${html}</body>`, 'text/html').body.textContent || '';
}

/** 今日（UTC）から shiftDays 日ずらした YYYY-MM-DD */
function isoFromToday(shiftDays: number): string {
  return new Date(Date.now() + shiftDays * 86_400_000).toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------
// 入力（候補 1 件・2 件以上）
// ---------------------------------------------------------------------------

const PHP_UBUNTU = { 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] };
const APACHE_UBUNTU = { server: ['Apache/2.4.41 (Ubuntu)'] };
const PHP_CVE = 'CVE-2024-4577';
const R20 = 'ubuntu:20.04';
const R22 = 'ubuntu:22.04';

function openEntry(cve: string): DistroAdvisoryEntry {
  return { cve, status: 'open', fixedVersions: [], osvIds: [`UBUNTU-${cve}`] };
}

/**
 * 固定 DB の複製。
 * - ubuntu:20.04・22.04 の標準サポート終了日を過去にする（OS のライフサイクルで EOL になる）
 * - 両方のリリースの php7.4 に open の CVE を足す（SEC-DISTRO-CVE-PHP が出る）
 * - multi が真なら、PHP 7.4.3 を ubuntu:22.04 の対応表にも足す（候補 2 件・確信度 low）
 */
function scenarioDb(multi: boolean, eol = true): DbWithDistro {
  const db = structuredClone(fixture);
  for (const r of db.distro!.releases) {
    if (r.release === R20) r.standardSupportEnd = isoFromToday(eol ? -30 : 300);
    if (r.release === R22) r.standardSupportEnd = isoFromToday(eol ? -20 : 400);
  }
  db.distro!.advisories = {
    [R20]: { 'php7.4': [openEntry(PHP_CVE)] },
    [R22]: { 'php7.4': [openEntry(PHP_CVE)] },
  };
  if (multi) {
    const base = db.distro!.map.find((e) => e.release === R20 && e.product === 'php')!;
    db.distro!.map.push({ ...base, release: R22, codename: 'jammy' });
  }
  return db;
}

const emptyDom = (): DomSignals => ({
  url: HOST,
  title: 'Distro confidence display test',
  metaTags: [],
  scriptUrls: ['https://www.example.test/assets/app.js'],
  linkUrls: [],
  domMarkers: [],
  htmlSnippets: [],
  mixedContent: [],
  cookiesFromDocument: [],
  cssAssets: [],
});

function deps(headers: Record<string, string[]>): InspectionDependencies {
  return {
    tab: { id: 7, url: HOST },
    fetchDomSignals: vi.fn().mockResolvedValue(emptyDom()),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue({ url: HOST, headers }),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  };
}

function techOf(report: InspectionReport, name: string): DetectedTechnology {
  const t = report.technologies.find((x) => x.technology === name);
  if (!t) throw new Error(`${name} が検出されていません`);
  return t;
}

interface Scenario {
  label: string;
  multi: boolean;
  expectedCandidates: string[];
}

const SCENARIOS: Scenario[] = [
  { label: '候補 1 件', multi: false, expectedCandidates: [R20] },
  { label: '候補 2 件以上', multi: true, expectedCandidates: [R20, R22] },
];

async function scenarioReport(s: Scenario): Promise<{ report: InspectionReport; php: DetectedTechnology }> {
  setTestAdvisoryDatabase(scenarioDb(s.multi));
  const report = await executeInspection(deps(PHP_UBUNTU));
  const php = techOf(report, 'PHP');
  // 前提が崩れていたら、テストの誤りとして落とす
  if (!php.distroInference) throw new Error('前提: PHP に distroInference が付いていない');
  expect(php.distroInference.candidates).toEqual(s.expectedCandidates);
  expect(php.eolInfo?.source).toBe(OS_LIFECYCLE_SOURCE);
  expect(php.supportStatus).toBe('EOL');
  return { report, php };
}

function releaseNames(candidates: string[]): string[] {
  return candidates.map((c) => formatDistroReleaseName(c));
}

// ---------------------------------------------------------------------------
// CSV と Markdown の表を読む
// ---------------------------------------------------------------------------

function parseCsv(text: string): string[][] {
  const src = text.replace(/^﻿/, '');
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          cell += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cell += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && src[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += ch;
    }
  }
  if (cell !== '' || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

/** CSV の「検出技術」の表から、技術名が name の行を、見出し → 値の形で返す */
function csvTechRows(csv: string, name: string): Array<Record<string, string>> {
  const rows = parseCsv(csv);
  const headerIdx = rows.findIndex((r) => r.includes('OSの推定') && r.includes('サポート状態 (EOL)'));
  if (headerIdx < 0) throw new Error('CSV に検出技術の表の見出しがありません');
  const header = rows[headerIdx];
  const out: Array<Record<string, string>> = [];
  for (let i = headerIdx + 1; i < rows.length; i++) {
    const r = rows[i];
    if (r.length < header.length) break;
    if (r[0] !== name) continue;
    const rec: Record<string, string> = {};
    header.forEach((h, j) => (rec[h] = r[j] ?? ''));
    out.push(rec);
  }
  return out;
}

function splitMdRow(line: string): string[] {
  // 先頭と末尾の | を外し、エスケープされていない | で分ける
  const inner = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return inner.split(/(?<!\\)\|/).map((c) => c.trim());
}

/** Markdown の見出し heading の直後の表から、1 列目に name を含む行を、見出し → 値の形で返す */
function mdTableRows(md: string, heading: RegExp, name: string): Array<Record<string, string>> {
  const lines = md.split('\n');
  const start = lines.findIndex((l) => heading.test(l));
  if (start < 0) throw new Error(`Markdown に ${heading} がありません`);
  const headerIdx = lines.findIndex((l, i) => i > start && l.trim().startsWith('|'));
  const header = splitMdRow(lines[headerIdx]);
  const out: Array<Record<string, string>> = [];
  for (let i = headerIdx + 2; i < lines.length && lines[i].trim().startsWith('|'); i++) {
    const cells = splitMdRow(lines[i]);
    if (!cells[0].includes(name)) continue;
    const rec: Record<string, string> = {};
    header.forEach((h, j) => (rec[h] = cells[j] ?? ''));
    out.push(rec);
  }
  return out;
}

function findColumn(rec: Record<string, string>, pred: (h: string) => boolean): string {
  const key = Object.keys(rec).find(pred);
  if (key === undefined) throw new Error(`列が見つかりません: ${Object.keys(rec).join(', ')}`);
  return rec[key];
}

// ---------------------------------------------------------------------------
// ポップアップの一覧の 1 行（設計メモ: src/popup/render.ts の renderTechRowHtml）
// ---------------------------------------------------------------------------

type RowRenderer = (tech: DetectedTechnology) => string;

function rowRenderer(): RowRenderer {
  const fn = (popupRender as unknown as { renderTechRowHtml?: RowRenderer }).renderTechRowHtml;
  if (typeof fn !== 'function') throw new Error('src/popup/render.ts に renderTechRowHtml(tech) がありません（設計メモ「実装の方針」）');
  return fn;
}

function renderRow(t: DetectedTechnology): HTMLElement {
  const html = rowRenderer()(t);
  const doc = new DOMParser().parseFromString(`<!doctype html><body><div class="item-row">${html}</div></body>`, 'text/html');
  return doc.querySelector('.item-row') as HTMLElement;
}

type WithConfidence = (tech: Pick<DetectedTechnology, 'distroInference' | 'eolInfo'>) => string;

function withConfidenceFn(): WithConfidence {
  const fn = (distroDisplay as unknown as { formatDistroReleaseWithConfidence?: WithConfidence }).formatDistroReleaseWithConfidence;
  if (typeof fn !== 'function') throw new Error('src/shared/distro-display.ts に formatDistroReleaseWithConfidence(tech) がありません（§3.2-3）');
  return fn;
}

// ===========================================================================
// H4・§3.2-1: eolInfo.label はリリース名だけ
// ===========================================================================

describe('T01 H4・§3.2-1: 判定側（judgeDistroEol）の eolInfo.label はリリース名だけ', () => {
  const distro = fixture.distro!;
  const now = (release: string, shift: number) => {
    const r = distro.releases.find((x) => x.release === release)!;
    return new Date(Date.parse(`${r.standardSupportEnd}T12:00:00Z`) + shift * 86_400_000);
  };
  const apacheMedium = () => inferDistroFromHeaders(APACHE_UBUNTU, distro).apache!;
  const nginxLow = () => inferDistroFromHeaders({ server: ['nginx/1.18.0 (Ubuntu)'] }, distro).nginx!;
  const phpHigh = () => inferDistroFromHeaders({ 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] }, distro).php!;

  const cases: Array<[string, () => DistroInference, string]> = [
    ['候補 1 件（medium）', apacheMedium, R20],
    ['候補 1 件（high）', phpHigh, 'debian:11'],
    ['候補 2 件以上（low）', nginxLow, R20],
  ];

  it.each(cases)('%s: EOL の前後どちらでも、label に「確信度」「推定・」が含まれない（陰性）', (_l, inf, basis) => {
    expect(inf().candidates.length).toBeGreaterThan(0);
    for (const shift of [-1, 1]) {
      const res = judgeDistroEol(inf(), distro, now(basis, shift));
      expect(res).not.toBeNull();
      const label = res!.eolInfo.label ?? '';
      expect(label).not.toContain('確信度');
      expect(label).not.toContain('推定・');
    }
  });

  it.each(cases)('%s: label には候補のリリース名がすべて入る（陽性）', (_l, inf, basis) => {
    const i = inf();
    const res = judgeDistroEol(i, distro, now(basis, 1));
    for (const name of releaseNames(i.candidates)) expect(res!.eolInfo.label).toContain(name);
  });

  it('候補 2 件以上の label は、候補の名前を併記する（「Ubuntu 20.04 … / Ubuntu 22.04 …」）', () => {
    const i = nginxLow();
    expect(i.candidates).toEqual([R20, R22]);
    const label = judgeDistroEol(i, distro, now(R20, 1))!.eolInfo.label!;
    expect(label.indexOf('Ubuntu 20.04')).toBeGreaterThanOrEqual(0);
    expect(label.indexOf('Ubuntu 22.04')).toBeGreaterThan(label.indexOf('Ubuntu 20.04'));
  });

  it.each(cases)('%s: eolInfo.note は説明の全文で、確信度入りのまま（陽性。§3.2-1）', (_l, inf, basis) => {
    const i = inf();
    const res = judgeDistroEol(i, distro, now(basis, 1));
    const jp = formatDistroConfidenceJp(i.confidence);
    expect(res!.eolInfo.note).toMatch(new RegExp(`確信度\\s*${jp}`));
  });

  it.each(SCENARIOS)('$label: 調査（executeInspection）の結果でも tech.eolInfo.label に「確信度」が含まれない', async (s) => {
    const { php } = await scenarioReport(s);
    expect(php.eolInfo!.label ?? '').not.toContain('確信度');
    for (const inst of php.instances || []) {
      expect((inst.eol ?? inst.eolInfo)?.label ?? '').not.toContain('確信度');
    }
  });
});

// ===========================================================================
// §3.2-2: formatDistroReleaseDisplay の分岐 (2) の削除
// ===========================================================================

describe('T01 §3.2-2: formatDistroReleaseDisplay は eolInfo.label を使わない（分岐 (2) の削除）', () => {
  const inf = (o: Partial<DistroInference>): DistroInference => ({
    family: 'ubuntu',
    release: null,
    candidates: [],
    confidence: 'none',
    evidence: [],
    ...o,
  });
  const osEol = (label: string): EolInfo => ({
    status: 'EOL',
    eolDate: null,
    source: OS_LIFECYCLE_SOURCE,
    recommendation: '確認してください。',
    label,
  });

  it('候補 2 件以上で、OS のライフサイクルの label（v1.8.1 以前の保存データの確信度入りの形）があっても、確信度を出さない', () => {
    const distroInference = inf({ candidates: [R20, R22], confidence: 'low' });
    const display = formatDistroReleaseDisplay({
      distroInference,
      eolInfo: osEol('Ubuntu 20.04 LTS / Ubuntu 22.04 LTS（推定・確信度 低）'),
    });
    expect(display).not.toContain('確信度');
    expect(display).toContain('Ubuntu 20.04');
    expect(display).toContain('Ubuntu 22.04');
  });

  it('候補 2 件以上の結果は、eolInfo が無いとき（分岐 (3)）と同じ', () => {
    const distroInference = inf({ candidates: [R20, R22], confidence: 'low' });
    const withLabel = formatDistroReleaseDisplay({ distroInference, eolInfo: osEol('OsLifecycleLabelMarker') });
    expect(withLabel).toBe(formatDistroReleaseDisplay({ distroInference }));
    expect(withLabel).not.toContain('OsLifecycleLabelMarker');
  });

  it('候補 1 件（inf.release あり）は従来どおりリリース名（確信度を含まない）', () => {
    const display = formatDistroReleaseDisplay({
      distroInference: inf({ release: R20, candidates: [R20], confidence: 'medium' }),
      eolInfo: osEol('Ubuntu 20.04 LTS（推定・確信度 中）'),
    });
    expect(display).toContain('Ubuntu 20.04');
    expect(display).not.toContain('確信度');
  });
});

// ===========================================================================
// §3.2-3: formatDistroReleaseWithConfidence
// ===========================================================================

describe('T01 §3.2-3: formatDistroReleaseWithConfidence(tech)（リリース名＋「（推定・確信度 X）」）', () => {
  const inf = (o: Partial<DistroInference>): DistroInference => ({
    family: 'ubuntu',
    release: null,
    candidates: [],
    confidence: 'none',
    evidence: [],
    ...o,
  });

  it('src/shared/distro-display から export されている', () => {
    expect(typeof withConfidenceFn()).toBe('function');
  });

  it.each([
    ['候補 1 件（medium）', inf({ release: R20, candidates: [R20], confidence: 'medium' })],
    ['候補 1 件（high）', inf({ family: 'debian', release: 'debian:11', candidates: ['debian:11'], confidence: 'high' })],
    ['候補 2 件以上（low）', inf({ candidates: [R20, R22], confidence: 'low' })],
  ])('%s: 候補のリリース名がすべて入り、「（推定・確信度 X）」がちょうど 1 回', (_l, distroInference) => {
    const out = withConfidenceFn()({ distroInference });
    for (const name of releaseNames(distroInference.candidates)) expect(out).toContain(name);
    const jp = formatDistroConfidenceJp(distroInference.confidence);
    expect(out).toContain(`（推定・確信度 ${jp}）`);
    expect(countDistroConf(out)).toBe(1);
  });

  it.each([
    ['候補 1 件', inf({ release: R20, candidates: [R20], confidence: 'medium' }), 'Ubuntu 20.04 LTS（推定・確信度 中）'],
    ['候補 2 件以上', inf({ candidates: [R20, R22], confidence: 'low' }), 'Ubuntu 20.04 LTS / Ubuntu 22.04 LTS（推定・確信度 低）'],
  ])('%s: v1.8.1 以前の確信度入りの eolInfo.label が付いていても、確信度は 1 回だけ', (_l, distroInference, legacyLabel) => {
    const out = withConfidenceFn()({
      distroInference,
      eolInfo: { status: 'EOL', eolDate: null, source: OS_LIFECYCLE_SOURCE, recommendation: '確認してください。', label: legacyLabel },
    });
    expect(countDistroConf(out)).toBe(1);
  });

  it.each([
    ['第三者リポジトリ（deb.sury.org）', inf({ thirdParty: { kind: 'third-party', marker: 'deb.sury.org' }, note: '第三者リポジトリの版です（deb.sury.org）。' })],
    ['バックポート（~bpo）', inf({ family: 'debian', thirdParty: { kind: 'backport', marker: '~bpo10+1' } })],
    ['確信度 none（対応表に無い版）', inf({ note: 'リリースを推定できません（対応表に無い版です。）' })],
  ])('%s: 従来どおり「推定なし」で、確信度（高・中・低）を付けず、断定しない（陰性）', (_l, distroInference) => {
    const out = withConfidenceFn()({ distroInference });
    expect(out).toContain('推定なし');
    expect(countDistroConf(out)).toBe(0);
    for (const w of FORBIDDEN_WORDS) expect(out).not.toContain(w);
  });

  it('distroInference が無ければ空文字', () => {
    expect(withConfidenceFn()({})).toBe('');
  });
});

// ===========================================================================
// §3.3: 出力先ごとに確信度がちょうど 1 回（候補 1 件・2 件以上を別々に）
// ===========================================================================

describe.each(SCENARIOS)('T01 §3.3: $label のとき、出力先ごとに OS の推定の確信度がちょうど 1 回', (s) => {
  it('ポップアップのモーダル（renderTechModalHtml）: 説明の全文を除いて 1 回。「推定リリース」に候補の名前', async () => {
    const { php } = await scenarioReport(s);
    const text = htmlText(renderTechModalHtml(php));
    expect(countDistroConf(withoutNotes(text, php))).toBe(1);
    expect(text).toContain('推定リリース');
    for (const name of releaseNames(s.expectedCandidates)) expect(text).toContain(name);
  });

  it('ダッシュボードの技術一覧（renderFullTechnologiesHtml）: 説明の全文を除いて 1 回', async () => {
    const { php } = await scenarioReport(s);
    const text = htmlText(renderFullTechnologiesHtml([php]));
    expect(countDistroConf(withoutNotes(text, php))).toBe(1);
    for (const name of releaseNames(s.expectedCandidates)) expect(text).toContain(name);
  });

  it('ダッシュボードのライブラリのセキュリティ表（renderLibrarySecurityTableHtml）: 説明の全文を除いて 1 回以下（二重にならない）', async () => {
    const { php } = await scenarioReport(s);
    const text = htmlText(renderLibrarySecurityTableHtml([php]));
    expect(countDistroConf(withoutNotes(text, php))).toBeLessThanOrEqual(1);
  });

  it('CSV: 「OSの推定」の列に「（推定・確信度 X）」が 1 回。「サポート状態 (EOL)」の列には確信度が無い', async () => {
    const { report, php } = await scenarioReport(s);
    const rows = csvTechRows(exportReportToCsv(report), 'PHP');
    expect(rows.length).toBeGreaterThan(0);
    const jp = formatDistroConfidenceJp(php.distroInference!.confidence);
    for (const r of rows) {
      const os = r['OSの推定'];
      expect(countDistroConf(os)).toBe(1);
      expect(os).toContain(`確信度 ${jp}`);
      for (const name of releaseNames(s.expectedCandidates)) expect(os).toContain(name);
      expect(r['サポート状態 (EOL)']).not.toContain('確信度');
    }
  });

  it('Markdown: OS リリースの推定の表で、リリースの列は名前だけ、確信度は別の列に 1 回', async () => {
    const { report, php } = await scenarioReport(s);
    const md = generateMarkdownReport(report);
    const rows = mdTableRows(md, /OS リリースの推定/, 'PHP');
    expect(rows).toHaveLength(1);
    const release = findColumn(rows[0], (h) => h.includes('推定リリース'));
    const conf = findColumn(rows[0], (h) => h === '確信度');
    expect(release).not.toContain('確信度');
    for (const name of releaseNames(s.expectedCandidates)) expect(release).toContain(name);
    expect(conf).toBe(formatDistroConfidenceJp(php.distroInference!.confidence));
  });

  it('Markdown: EOL・既知脆弱性の表の「サポート状況 (EOL)」の列に確信度が無い', async () => {
    const { report } = await scenarioReport(s);
    const rows = mdTableRows(generateMarkdownReport(report), /^## 6\. /, 'PHP');
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      expect(findColumn(r, (h) => h.startsWith('サポート状況'))).not.toContain('確信度');
    }
  });

  it('指摘文: OS のライフサイクルの EOL（SEC-EOL-PHP）の観測値と説明に、候補の名前と確信度が 1 回ずつ', async () => {
    const { report, php } = await scenarioReport(s);
    const checks = report.securityChecks.filter((c) => c.checkId === 'SEC-EOL-PHP' || c.checkId.startsWith('SEC-EOL-PHP-'));
    expect(checks.length).toBeGreaterThan(0);
    const jp = formatDistroConfidenceJp(php.distroInference!.confidence);
    for (const c of checks) {
      for (const field of [c.observed, c.description] as string[]) {
        expect(countDistroConf(field), field).toBe(1);
        expect(field).toContain(`確信度 ${jp}`);
        for (const name of releaseNames(s.expectedCandidates)) expect(field).toContain(name);
      }
    }
  });

  it('指摘文: ディストリの修正状況（SEC-DISTRO-CVE-PHP）の観測値に、候補の名前と確信度が 1 回', async () => {
    const { report, php } = await scenarioReport(s);
    const check = report.securityChecks.find((c) => c.checkId === 'SEC-DISTRO-CVE-PHP') as SecurityCheckResult | undefined;
    expect(check).toBeDefined();
    const jp = formatDistroConfidenceJp(php.distroInference!.confidence);
    expect(countDistroConf(check!.observed)).toBe(1);
    expect(check!.observed).toContain(`確信度 ${jp}`);
    for (const name of releaseNames(s.expectedCandidates)) expect(check!.observed).toContain(name);
  });

  it('ポップアップの一覧（renderTechRowHtml）: OS の推定の確信度は出さない（既存の検出の確信度バッジだけ）', async () => {
    const { php } = await scenarioReport(s);
    const row = renderRow(php);
    expect(countDistroConf(row.textContent || '')).toBe(0);
    expect(row.textContent).not.toContain('確信度');
    // EOL バッジには推定したリリースの名前が出る
    const side = row.querySelector('.item-side')!;
    expect(side.textContent).toContain('Ubuntu 20.04');
    // 既存の検出の確信度バッジ（数値）は残る
    expect(side.textContent).toContain(String(php.confidence));
  });
});

describe('T01 §3.3: EOL でない（標準サポート中と推定）ときも、確信度は 1 回', () => {
  it.each(SCENARIOS)('$label: ポップアップのモーダルと SEC-DISTRO-CVE の観測値', async (s) => {
    setTestAdvisoryDatabase(scenarioDb(s.multi, false));
    const report = await executeInspection(deps(PHP_UBUNTU));
    const php = techOf(report, 'PHP');
    expect(php.distroInference?.candidates).toEqual(s.expectedCandidates);
    expect(php.supportStatus).not.toBe('EOL');
    expect(php.eolInfo?.label ?? '').not.toContain('確信度');
    expect(countDistroConf(withoutNotes(htmlText(renderTechModalHtml(php)), php))).toBe(1);
    const check = report.securityChecks.find((c) => c.checkId === 'SEC-DISTRO-CVE-PHP');
    expect(check).toBeDefined();
    expect(countDistroConf(check!.observed)).toBe(1);
  });
});

// ===========================================================================
// 第三者・none・対応表に無い版は従来どおり
// ===========================================================================

describe('T01: 第三者リポジトリ・バックポート・対応表に無い版は従来どおり（「推定なし」、断定しない）', () => {
  const NO_ESTIMATE: Array<[string, Record<string, string[]>, string]> = [
    ['第三者リポジトリ（deb.sury.org）', { 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }, 'PHP'],
    ['バックポート（~bpo）', { 'x-powered-by': ['PHP/7.4.33-1~bpo10+1'] }, 'PHP'],
    ['対応表に無い版', { server: ['Apache/2.4.99 (Ubuntu)'] }, 'Apache'],
  ];

  it.each(NO_ESTIMATE)('%s: リリース欄は「推定なし」で、確信度（高・中・低）を出さない', async (_l, headers, name) => {
    const report = await executeInspection(deps(headers));
    const t = techOf(report, name);
    expect(t.distroInference?.confidence).toBe('none');
    expect(formatDistroReleaseDisplay(t)).toContain('推定なし');
    expect(withConfidenceFn()(t)).toContain('推定なし');
    for (const text of [
      htmlText(renderTechModalHtml(t)),
      htmlText(renderFullTechnologiesHtml([t])),
      htmlText(rowRenderer()(t)),
    ]) {
      expect(countDistroConf(text)).toBe(0);
    }
    for (const r of csvTechRows(exportReportToCsv(report), name)) {
      expect(countDistroConf(r['OSの推定'])).toBe(0);
      for (const w of FORBIDDEN_WORDS) expect(r['OSの推定']).not.toContain(w);
    }
  });

  it.each(NO_ESTIMATE)('%s: OS のライフサイクルの EOL の指摘を出さない（推定なしで EOL と断定しない）', async (_l, headers, name) => {
    const report = await executeInspection(deps(headers));
    const t = techOf(report, name);
    expect(t.eolInfo?.source).not.toBe(OS_LIFECYCLE_SOURCE);
    const prefix = `SEC-EOL-${name.toUpperCase()}`;
    for (const c of report.securityChecks.filter((x) => x.checkId === prefix || x.checkId.startsWith(`${prefix}-`))) {
      expect(c.observed).not.toContain('推定した OS');
    }
  });
});

// ===========================================================================
// H5・§3.2-5: ポップアップの一覧の「ディストリ版」
// ===========================================================================

describe('T01 H5・§3.2-5: ポップアップの一覧の行（renderTechRowHtml）', () => {
  async function apacheUbuntu(): Promise<DetectedTechnology> {
    const t = techOf(await executeInspection(deps(APACHE_UBUNTU)), 'Apache');
    if (!t.distroHint) throw new Error('前提: Apache に distroHint が付いていない');
    return t;
  }

  it('src/popup/render.ts から renderTechRowHtml が export されている', () => {
    expect(typeof rowRenderer()).toBe('function');
  });

  it('.item-main にアイコンと技術名があり、.item-side に右のバッジ群がある', async () => {
    const t = await apacheUbuntu();
    const row = renderRow(t);
    const main = row.querySelector('.item-main');
    expect(main).not.toBeNull();
    expect(main!.querySelector('.tech-icon-badge')?.textContent?.trim().length).toBeGreaterThan(0);
    expect(main!.querySelector('.item-name')?.textContent).toContain('Apache');
    expect(row.querySelector('.item-side')).not.toBeNull();
  });

  it('distroHint があると、.item-meta に短縮形「ディストリ版」が出て、全文は title にある（陽性）', async () => {
    const t = await apacheUbuntu();
    const row = renderRow(t);
    const meta = row.querySelector('.item-meta')!;
    const badge = Array.from(meta.querySelectorAll('*')).find((el) => (el.textContent || '').trim() === 'ディストリ版');
    expect(badge, '.item-meta に「ディストリ版」の要素がありません').toBeDefined();
    const title = badge!.getAttribute('title') || '';
    expect(title).toContain('バックポートの可能性');
  });

  it('「ディストリ版」は .item-side に出ない。長い文言「ディストリ版（バックポートの可能性）」は画面の文字に出ない（title だけ）', async () => {
    const t = await apacheUbuntu();
    const row = renderRow(t);
    expect(row.querySelector('.item-side')!.textContent).not.toContain('ディストリ版');
    expect(row.textContent).not.toContain('ディストリ版（バックポートの可能性）');
  });

  it('distroHint が無い技術には「ディストリ版」を出さない（陰性）', async () => {
    const t = techOf(await executeInspection(deps({ server: ['Apache/2.4.58 (Unix)'] })), 'Apache');
    expect(t.distroHint).toBeFalsy();
    const row = renderRow(t);
    expect(row.textContent).not.toContain('ディストリ版');
    expect(row.querySelector('[title*="バックポート"]')).toBeNull();
  });

  it('title の値は HTML としてエスケープされる', async () => {
    const t = await apacheUbuntu();
    const evil = { ...t, distroHint: 'Ubuntu"><img src=x onerror=alert(1)>' } as DetectedTechnology;
    const html = rowRenderer()(evil);
    expect(html).not.toContain('<img src=x');
    const row = renderRow(evil);
    expect(row.querySelector('img')).toBeNull();
  });

  it('src/popup/popup.ts は一覧の行を renderTechRowHtml で作る', () => {
    const src = fs.readFileSync(path.join(REPO_ROOT, 'src', 'popup', 'popup.ts'), 'utf-8');
    expect(src).toMatch(/\brenderTechRowHtml\s*\(/);
    expect(src).not.toContain('ディストリ版（バックポートの可能性）');
  });
});

// ===========================================================================
// §3.2-4: ポップアップの CSS
// ===========================================================================

describe('T01 §3.2-4: ポップアップの CSS（.item-main が潰れない・.item-side が折り返す）', () => {
  const css = fs.readFileSync(path.join(REPO_ROOT, 'src', 'popup', 'popup.css'), 'utf-8');

  /** メディアクエリの外にある、セレクタがちょうど selector の規則の宣言をまとめる（後のものが勝つ） */
  function declarations(selector: string): Record<string, string> {
    const noComments = css.replace(/\/\*[\s\S]*?\*\//g, '');
    const out: Record<string, string> = {};
    const re = /([^{}@]+)\{([^{}]*)\}/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(noComments)) !== null) {
      const selectors = m[1].split(',').map((x) => x.trim());
      if (!selectors.includes(selector)) continue;
      for (const decl of m[2].split(';')) {
        const idx = decl.indexOf(':');
        if (idx < 0) continue;
        out[decl.slice(0, idx).trim().toLowerCase()] = decl.slice(idx + 1).trim().replace(/\s+/g, ' ').replace(/\s*!important$/, '');
      }
    }
    return out;
  }

  it('.item-main は flex: 1 1 auto と min-width: 0', () => {
    const d = declarations('.item-main');
    expect(d['flex']).toBe('1 1 auto');
    expect(['0', '0px']).toContain(d['min-width']);
  });

  it('.item-side は flex-shrink: 1・flex-wrap: wrap・justify-content: flex-end（flex-shrink: 0 ではない）', () => {
    const d = declarations('.item-side');
    expect(d['flex-shrink']).toBe('1');
    expect(d['flex-wrap']).toBe('wrap');
    expect(d['justify-content']).toBe('flex-end');
  });

  it('ポップアップの幅は 450px のまま', () => {
    expect(declarations('body')['width']).toBe('450px');
  });
});
