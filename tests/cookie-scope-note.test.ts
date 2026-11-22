/**
 * 根拠の注記（v1.8.2 T04 / A、指示書 §4.2・§6 T04）
 *
 * 親ドメイン（host-only でない）の Cookie 名だけで検出し、T03 で確信度を下げた技術（cookieScopeDowngraded）に、
 * 「同一ドメインの別サイトで発行された可能性がある。このホスト単体での利用は確認できていない」の趣旨の注記を
 * Markdown の §4・§14 とダッシュボードの根拠に出す。host-only の Cookie だけのとき、他の根拠があるときは出さない。
 *
 * 公開 API（設計メモ「実装の方針」）:
 * - src/shared/cookie-scope-note.ts の formatCookieScopeNote(tech, cookies?) → string | null
 * - renderFullTechnologiesHtml(techs, coverage?, cookies?)（第 3 引数を任意で足す）
 *
 * 再現データは *.example.test の合成データ。文言は「別サイト」と「このホスト単体での利用は確認できていません」だけを確かめる。
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { DetectionEngine, type DetectionInput } from '../src/detection/engine';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderFullTechnologiesHtml } from '../src/dashboard/render';
import { sanitizeReportUrls } from '../src/storage/history';
import type {
  DetectedTechnology,
  DomSignals,
  InspectedCookieInfo,
  InspectionReport,
} from '../src/shared/types';

const PAGE_URL = 'https://app.example.test/';
const PAGE_HOST = 'app.example.test';
const PARENT_DOMAIN = '.example.test';
const OTHER_PARENT_DOMAIN = '.app.example.test';
const GA_SCRIPT = 'https://www.googletagmanager.com/gtag/js?id=G-TEST000001';
const GA = 'Google Analytics';
const AI = 'Application Insights';
const PHP = 'PHP';

/** 注記の趣旨（指示書 §4.2）。実装はこの 2 つの語句を含める */
const NOTE_SITE = '別サイト';
const NOTE_TAIL = 'このホスト単体での利用は確認できていません';

type NoteFn = (tech: DetectedTechnology, cookies?: readonly InspectedCookieInfo[]) => string | null;
let formatCookieScopeNote: NoteFn = () => {
  throw new Error('src/shared/cookie-scope-note.ts の formatCookieScopeNote がありません');
};

beforeAll(async () => {
  // モジュールが無いとき（実装の前）も、ほかのケースが自分の理由で失敗するよう動的に読む
  try {
    const mod = (await import('../src/shared/cookie-scope-note')) as unknown as { formatCookieScopeNote?: NoteFn };
    if (typeof mod.formatCookieScopeNote === 'function') formatCookieScopeNote = mod.formatCookieScopeNote;
  } catch {
    // 実装の前は上の既定（例外）のまま
  }
});

type RenderTechs = (techs: DetectedTechnology[], coverage?: unknown, cookies?: InspectedCookieInfo[]) => string;
const renderTechs = renderFullTechnologiesHtml as unknown as RenderTechs;

const emptyDom = (overrides: Partial<DomSignals> = {}): DomSignals => ({
  url: PAGE_URL,
  title: 'Cookie scope note fixture',
  metaTags: [],
  scriptUrls: [],
  linkUrls: [],
  domMarkers: [],
  htmlSnippets: [],
  mixedContent: [],
  cookiesFromDocument: [],
  cssAssets: [],
  ...overrides,
});

const hostCookie = (name: string): InspectedCookieInfo => ({
  name,
  domain: PAGE_HOST,
  path: '/',
  secure: true,
  httpOnly: false,
  sameSite: 'lax',
  session: false,
  hostOnly: true,
});

const domainCookie = (name: string, domain = PARENT_DOMAIN): InspectedCookieInfo => ({
  name,
  domain,
  path: '/',
  secure: true,
  httpOnly: false,
  sameSite: 'lax',
  session: false,
  hostOnly: false,
});

interface Fixture {
  cookies?: InspectedCookieInfo[];
  documentCookies?: string[];
  scriptUrls?: string[];
}

const detect = (f: Fixture): DetectedTechnology[] => {
  const input: DetectionInput = {
    url: PAGE_URL,
    dom: emptyDom({ cookiesFromDocument: f.documentCookies ?? [], scriptUrls: f.scriptUrls ?? [] }),
    network: { url: PAGE_URL, responseHeaders: {}, cookies: f.cookies ?? [] },
  };
  return new DetectionEngine().detect(input);
};

const find = (techs: DetectedTechnology[], name: string): DetectedTechnology => {
  const t = techs.find((x) => x.technology === name);
  if (!t) throw new Error(`${name} が検出されていません: ${techs.map((x) => x.technology).join(', ')}`);
  return t;
};

const buildReport = (techs: DetectedTechnology[], cookies: InspectedCookieInfo[]): InspectionReport => ({
  id: 'report-cookie-scope-note',
  url: PAGE_URL,
  hostname: PAGE_HOST,
  inspectedAt: new Date().toISOString(),
  extensionVersion: '0.0.0-test',
  rulesVersion: 'test',
  summary: {
    totalTechnologies: techs.length,
    requiresAttentionCount: 0,
    securityFindings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    librarySecurity: { eolCount: 0, vulnerableLibraryCount: 0, mismatchCount: 0 },
    isHttps: true,
    mixedContentCount: 0,
  },
  technologies: techs,
  securityChecks: [],
  cookies,
  mixedContent: [],
});

/** Markdown のエスケープ（\_ など）とコードスパンの ` を除いた本文 */
const plain = (s: string): string => s.replace(/\\/g, '').replace(/`/g, '');

/** "## N." から次の "## " までの節 */
const mdSection = (md: string, num: number): string => {
  const start = md.indexOf(`## ${num}.`);
  expect(start, `§${num} がありません`).toBeGreaterThanOrEqual(0);
  const next = md.indexOf('\n## ', start + 1);
  return md.slice(start, next < 0 ? undefined : next);
};

/** §14 の中の、技術ごとの小見出し（### 技術名）の節 */
const evidenceBlock = (md: string, techName: string): string => {
  const sec14 = mdSection(md, 14);
  const blocks = sec14.split('\n### ').slice(1);
  const block = blocks.find((b) => b.startsWith(`${techName} `) || b.startsWith(`${techName}(`));
  expect(block, `§14 に ${techName} の節がありません`).toBeDefined();
  return block!;
};

const countOf = (text: string, needle: string): number => text.split(needle).length - 1;

// ---------------------------------------------------------------------------

describe('T04 前提: T03 の判定（親ドメインの _ga だけなら下げる）', () => {
  it('親ドメインの _ga だけ → GA に cookieScopeDowngraded が付く（T04 の注記の前提）', () => {
    const ga = find(detect({ cookies: [domainCookie('_ga')] }), GA);
    expect(ga.confidenceLevel).toBe('low');
    expect(ga.cookieScopeDowngraded).toBe(true);
  });
});

describe('T04: formatCookieScopeNote（注記の組み立て）', () => {
  it('export されている', async () => {
    const mod = (await import('../src/shared/cookie-scope-note')) as unknown as Record<string, unknown>;
    expect(typeof mod.formatCookieScopeNote).toBe('function');
  });

  it('陽性: 親ドメインの _ga だけ → 注記に Cookie 名・スコープのドメイン・趣旨の語句がある', () => {
    const cookies = [domainCookie('_ga')];
    const ga = find(detect({ cookies }), GA);
    const note = formatCookieScopeNote(ga, cookies);
    expect(note).toBeTruthy();
    expect(note).toContain('_ga');
    expect(note).toContain(PARENT_DOMAIN);
    expect(note).toContain(NOTE_SITE);
    expect(note).toContain(NOTE_TAIL);
    expect(countOf(note!, NOTE_TAIL)).toBe(1);
  });

  it('陰性: host-only の _ga だけ → 注記なし（null）', () => {
    const cookies = [hostCookie('_ga')];
    const ga = find(detect({ cookies }), GA);
    expect(formatCookieScopeNote(ga, cookies)).toBeNull();
  });

  it('陰性: 親ドメインの _ga ＋ GA の script-url → 下げないので注記なし', () => {
    const cookies = [domainCookie('_ga')];
    const ga = find(detect({ cookies, scriptUrls: [GA_SCRIPT] }), GA);
    expect(ga.confidenceLevel).toBe('high');
    expect(formatCookieScopeNote(ga, cookies)).toBeNull();
  });

  it('陰性: 同じ名前に host-only と親ドメインが混在 → 下げないので注記なし', () => {
    const cookies = [domainCookie('_ga'), hostCookie('_ga')];
    const ga = find(detect({ cookies }), GA);
    expect(formatCookieScopeNote(ga, cookies)).toBeNull();
  });

  it('陽性: document.cookie だけにある _ga（スコープ不明）→ 注記あり。ドメインは書かない', () => {
    const ga = find(detect({ documentCookies: ['_ga'] }), GA);
    const note = formatCookieScopeNote(ga, []);
    expect(note).toBeTruthy();
    expect(note).toContain('_ga');
    expect(note).toContain(NOTE_TAIL);
    expect(note).not.toContain(PARENT_DOMAIN);
  });

  it('陽性: cookies を渡さなくても注記は出る（ドメインが分からないだけ）', () => {
    const ga = find(detect({ cookies: [domainCookie('_ga')] }), GA);
    const note = formatCookieScopeNote(ga);
    expect(note).toBeTruthy();
    expect(note).toContain('_ga');
    expect(note).toContain(NOTE_TAIL);
  });

  it('複数: 同じ名前の _ga が 2 つの親ドメインにある → 両方のドメインを書き、趣旨の語句は 1 回', () => {
    const cookies = [domainCookie('_ga', PARENT_DOMAIN), domainCookie('_ga', OTHER_PARENT_DOMAIN)];
    const ga = find(detect({ cookies }), GA);
    const note = formatCookieScopeNote(ga, cookies)!;
    expect(note).toBeTruthy();
    expect(note).toContain(PARENT_DOMAIN);
    expect(note).toContain(OTHER_PARENT_DOMAIN);
    expect(countOf(note, NOTE_TAIL)).toBe(1);
  });

  it('複数: 別々の Cookie 名 2 つ（ai_user・ai_session）が親ドメイン → 両方の名前を書き、趣旨の語句は 1 回', () => {
    const cookies = [domainCookie('ai_user'), domainCookie('ai_session')];
    const ai = find(detect({ cookies }), AI);
    const note = formatCookieScopeNote(ai, cookies)!;
    expect(note).toBeTruthy();
    expect(note).toContain('ai_user');
    expect(note).toContain('ai_session');
    expect(countOf(note, NOTE_TAIL)).toBe(1);
  });

  it('陰性: 注記に、根拠でない別の Cookie の名前は入らない', () => {
    const cookies = [domainCookie('_ga'), domainCookie('unrelated_pref')];
    const ga = find(detect({ cookies }), GA);
    const note = formatCookieScopeNote(ga, cookies)!;
    expect(note).not.toContain('unrelated_pref');
  });

  it('互換: cookieScopeDowngraded の無い技術（v1.8.1 以前の履歴）は、cookie-name の根拠だけでも注記なし', () => {
    const legacy: DetectedTechnology = {
      technology: GA,
      category: 'analytics-tracking',
      version: null,
      confidence: 85,
      confidenceLevel: 'high',
      evidence: [{ type: 'cookie-name', name: '_ga', value: '_ga', source: PAGE_URL, detail: 'legacy', weight: 85 }],
    } as unknown as DetectedTechnology;
    expect(() => formatCookieScopeNote(legacy, [domainCookie('_ga')])).not.toThrow();
    expect(formatCookieScopeNote(legacy, [domainCookie('_ga')])).toBeNull();
  });

  it('陰性: 印があっても、後から cookie-name 以外の根拠（連動検出など）が足された技術には注記なし', () => {
    const cookies = [domainCookie('PHPSESSID')];
    const php = find(detect({ cookies }), PHP);
    expect(php.cookieScopeDowngraded).toBe(true);
    const raised: DetectedTechnology = {
      ...php,
      evidence: [
        ...php.evidence,
        {
          type: 'pattern',
          name: '連動検出 (Implication)',
          value: 'WordPress',
          source: 'WordPress',
          detail: 'WordPress の検出に基づく連動判定',
          weight: 80,
        },
      ],
    } as DetectedTechnology;
    expect(formatCookieScopeNote(php, cookies)).toBeTruthy();
    expect(formatCookieScopeNote(raised, cookies)).toBeNull();
  });
});

describe('T04: Markdown の §4・§14 に注記を出す', () => {
  it('陽性: 親ドメインの _ga だけ → §4 と §14 の GA の節に注記', () => {
    const cookies = [domainCookie('_ga')];
    const md = generateMarkdownReport(buildReport(detect({ cookies }), cookies));
    const sec4 = plain(mdSection(md, 4));
    expect(sec4).toContain('_ga');
    expect(sec4).toContain(NOTE_TAIL);
    const ev = plain(evidenceBlock(md, GA));
    expect(ev).toContain('_ga');
    expect(ev).toContain(PARENT_DOMAIN);
    expect(ev).toContain(NOTE_SITE);
    expect(ev).toContain(NOTE_TAIL);
  });

  it('陰性: host-only の _ga だけ → レポートのどこにも注記の語句が無い', () => {
    const cookies = [hostCookie('_ga')];
    const md = plain(generateMarkdownReport(buildReport(detect({ cookies }), cookies)));
    expect(md).not.toContain(NOTE_TAIL);
  });

  it('陰性: 親ドメインの _ga ＋ script-url（high）→ §4・§14 に注記なし', () => {
    const cookies = [domainCookie('_ga')];
    const md = generateMarkdownReport(buildReport(detect({ cookies, scriptUrls: [GA_SCRIPT] }), cookies));
    expect(plain(mdSection(md, 4))).not.toContain(NOTE_TAIL);
    expect(plain(mdSection(md, 14))).not.toContain(NOTE_TAIL);
  });

  it('混在: 下げた GA と host-only の PHPSESSID の PHP → GA の節にだけ注記', () => {
    const cookies = [domainCookie('_ga'), hostCookie('PHPSESSID')];
    const md = generateMarkdownReport(buildReport(detect({ cookies }), cookies));
    expect(plain(evidenceBlock(md, GA))).toContain(NOTE_TAIL);
    expect(plain(evidenceBlock(md, PHP))).not.toContain(NOTE_TAIL);
  });

  it('複数: 下げた技術が 2 つ（GA と Application Insights）→ §14 の各節に 1 回ずつ、§4 にも両方', () => {
    const cookies = [domainCookie('_ga'), domainCookie('ai_user'), domainCookie('ai_session')];
    const md = generateMarkdownReport(buildReport(detect({ cookies }), cookies));
    expect(countOf(plain(evidenceBlock(md, GA)), NOTE_TAIL)).toBe(1);
    expect(countOf(plain(evidenceBlock(md, AI)), NOTE_TAIL)).toBe(1);
    expect(countOf(plain(mdSection(md, 14)), NOTE_TAIL)).toBe(2);
    const sec4 = plain(mdSection(md, 4));
    expect(sec4).toContain('_ga');
    expect(sec4).toContain('ai_user');
    expect(countOf(sec4, NOTE_TAIL)).toBeGreaterThanOrEqual(1);
  });

  it('履歴に保存した後（sanitizeReportUrls）も注記が出る', () => {
    const cookies = [domainCookie('_ga')];
    const saved = sanitizeReportUrls(buildReport(detect({ cookies }), cookies));
    const md = generateMarkdownReport(saved);
    expect(plain(evidenceBlock(md, GA))).toContain(NOTE_TAIL);
  });

  it('既存の §7 の親ドメインの注記は残る', () => {
    const cookies = [domainCookie('_ga')];
    const md = generateMarkdownReport(buildReport(detect({ cookies }), cookies));
    expect(mdSection(md, 7)).toContain('親ドメインのCookieに関する注記');
  });
});

describe('T04: ダッシュボードの根拠に注記を出す', () => {
  it('陽性: 親ドメインの _ga だけ → 「判定根拠」の後に注記（Cookie 名・ドメイン・趣旨）', () => {
    const cookies = [domainCookie('_ga')];
    const ga = find(detect({ cookies }), GA);
    const html = renderTechs([ga], undefined, cookies);
    const evIdx = html.indexOf('判定根拠');
    expect(evIdx).toBeGreaterThanOrEqual(0);
    const after = html.slice(evIdx);
    expect(after).toContain(NOTE_TAIL);
    expect(after).toContain(NOTE_SITE);
    expect(after).toContain('_ga');
    expect(after).toContain(PARENT_DOMAIN);
  });

  it('陰性: host-only の _ga だけ → 注記なし', () => {
    const cookies = [hostCookie('_ga')];
    const ga = find(detect({ cookies }), GA);
    expect(renderTechs([ga], undefined, cookies)).not.toContain(NOTE_TAIL);
  });

  it('陰性: 親ドメインの _ga ＋ script-url → 注記なし', () => {
    const cookies = [domainCookie('_ga')];
    const ga = find(detect({ cookies, scriptUrls: [GA_SCRIPT] }), GA);
    expect(renderTechs([ga], undefined, cookies)).not.toContain(NOTE_TAIL);
  });

  it('cookies を渡さない呼び出し（従来の 2 引数）でも壊れず、注記は出る', () => {
    const ga = find(detect({ cookies: [domainCookie('_ga')] }), GA);
    expect(() => renderFullTechnologiesHtml([ga])).not.toThrow();
    expect(renderFullTechnologiesHtml([ga])).toContain(NOTE_TAIL);
  });

  it('複数: 下げた技術 2 つ → 注記が 2 回、host-only の技術には付かない', () => {
    const cookies = [domainCookie('_ga'), domainCookie('ai_user'), hostCookie('PHPSESSID')];
    const techs = detect({ cookies });
    const html = renderTechs(techs, undefined, cookies);
    expect(countOf(html, NOTE_TAIL)).toBe(2);
    expect(renderTechs([find(techs, PHP)], undefined, cookies)).not.toContain(NOTE_TAIL);
  });

  it('Cookie 名・ドメインはエスケープされる（HTML を注入できない）', () => {
    const evil = '.example.test"><img src=x onerror=alert(1)>';
    const cookies = [domainCookie('_ga', evil)];
    const ga = find(detect({ cookies }), GA);
    const html = renderTechs([ga], undefined, cookies);
    expect(html).not.toContain('<img src=x');
  });
});
