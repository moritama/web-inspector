// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * v1.8.2 T07: 同梱データの出典とライセンスの表示（指示書 §5.2・§5.4、H9・H11・H12）
 *
 * - src/shared/data-sources.ts の出典の一覧（§5.2 の表の 7 種類）と NVD の表示文
 * - ダッシュボードの「データの出典とライセンス」欄（NVD の表示文はここ）と、URL のハッシュでその欄を開くこと
 * - ポップアップはその欄へのリンクだけ（NVD の表示文や出典の一覧を載せない）
 * - Markdown のレポートの末尾の出典の節
 *
 * 件数・日付・版は書かない。出典の名前・URL は定数から取り、同梱 DB との一致は
 * tests/advisory-db-invariants.test.ts（同梱 DB を読んでよいテスト）で確かめる。
 */

import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BUNDLED_DATA_SOURCES,
  DATA_SOURCES_VIEW_ID,
  NVD_NOTICE,
  NVD_TERMS_URL,
} from '../src/shared/data-sources';
import { generateMarkdownReport } from '../src/export/markdown';
import type { InspectionReport } from '../src/shared/types';

const ROOT = path.resolve(__dirname, '..');
const read = (rel: string): string => fs.readFileSync(path.join(ROOT, rel), 'utf-8');

/** 指示書 §5.2 の NVD の表示文（一字一句。設計メモの「外部の事実」） */
const EXPECTED_NVD_NOTICE = 'This product uses the NVD API but is not endorsed or certified by the NVD.';

const EXPECTED_IDS = ['nvd', 'ghsa', 'ubuntu', 'debian', 'endoflife', 'kev', 'psl'];

const byId = (id: string) => {
  const s = BUNDLED_DATA_SOURCES.find((x) => x.id === id);
  if (!s) throw new Error(`BUNDLED_DATA_SOURCES に ${id} がありません`);
  return s;
};

/** HTML の body を DOM に入れる（<script> は外す。tests/dashboard-history.test.ts と同じ方法） */
function loadBody(htmlFile: string): void {
  const full = read(htmlFile);
  const m = full.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  const body = m ? m[1] : full;
  document.body.innerHTML = body.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
}

const createReport = (): InspectionReport => ({
  id: 'rep-t07',
  url: 'https://www.example.test/',
  hostname: 'www.example.test',
  inspectedAt: '2026-01-01T00:00:00.000Z',
  extensionVersion: '0.0.1',
  rulesVersion: '0.0.1',
  technologies: [],
  securityChecks: [],
  cookies: [],
  mixedContent: [],
  summary: {
    totalTechnologies: 0,
    requiresAttentionCount: 0,
    securityFindings: { high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    librarySecurity: { eolCount: 0, vulnerableLibraryCount: 0, mismatchCount: 0 },
    isHttps: true,
    mixedContentCount: 0,
  },
  coverage: {
    overallStatus: 'complete',
    dom: 'complete',
    headers: 'complete',
    cookies: 'complete',
    iframes: 'complete',
    network: 'complete',
  },
});

describe('T07: 出典の一覧（src/shared/data-sources.ts）', () => {
  it('NVD の表示文が指示書 §5.2 の文と一字一句同じで、利用規約の URL を持つこと', () => {
    expect(NVD_NOTICE).toBe(EXPECTED_NVD_NOTICE);
    expect(NVD_TERMS_URL).toBe('https://nvd.nist.gov/developers/terms-of-use');
  });

  it('§5.2 の表の 7 種類がちょうど 1 つずつあること（id の重複なし）', () => {
    const ids = BUNDLED_DATA_SOURCES.map((s) => s.id);
    expect([...ids].sort()).toEqual([...EXPECTED_IDS].sort());
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('陰性: 表示不要のもの（Launchpad・sources.debian.org・curated.json）を載せないこと', () => {
    const text = JSON.stringify(BUNDLED_DATA_SOURCES);
    expect(text).not.toMatch(/launchpad/i);
    expect(text).not.toMatch(/sources\.debian\.org/i);
    expect(text).not.toMatch(/curated/i);
  });

  it('すべての出典に、空でない名前・https の URL・ライセンスの表記・加工の有無があること', () => {
    for (const s of BUNDLED_DATA_SOURCES) {
      expect(s.name.trim().length, s.id).toBeGreaterThan(0);
      expect(s.url, s.id).toMatch(/^https:\/\//);
      expect(s.licenseLabel.trim().length, s.id).toBeGreaterThan(0);
      expect(s.contents.trim().length, s.id).toBeGreaterThan(0);
      expect(s.modification.trim().length, s.id).toBeGreaterThan(0);
      if (s.licenseUrl !== null) expect(s.licenseUrl, s.id).toMatch(/^https:\/\//);
    }
  });

  it('ライセンスが §5.2 の表のとおりであること（SPDX と表記と URL）', () => {
    expect(byId('ghsa').license).toBe('CC-BY-4.0');
    expect(byId('ghsa').licenseLabel).toContain('CC BY 4.0');
    expect(byId('ghsa').licenseUrl).toBe('https://creativecommons.org/licenses/by/4.0/');

    expect(byId('ubuntu').license).toBe('CC-BY-SA-4.0');
    expect(byId('ubuntu').licenseLabel).toContain('CC BY-SA 4.0');
    expect(byId('ubuntu').licenseUrl).toBe('https://creativecommons.org/licenses/by-sa/4.0/');

    expect(byId('endoflife').license).toBe('MIT');
    expect(byId('endoflife').licenseLabel).toContain('MIT');

    expect(byId('kev').license).toBe('CC0-1.0');
    expect(byId('kev').licenseLabel).toContain('CC0');
    expect(byId('kev').licenseUrl).toBe('https://creativecommons.org/publicdomain/zero/1.0/');

    expect(byId('psl').license).toBe('MPL-2.0');
    expect(byId('psl').licenseLabel).toContain('MPL 2.0');
    expect(byId('psl').licenseUrl).toBe('https://mozilla.org/MPL/2.0/');

    expect(byId('nvd').license).toBeNull();
    expect(byId('nvd').licenseUrl).toBe(NVD_TERMS_URL);
  });

  it('陰性: Debian にライセンスを割り当てず、「ライセンスの明記なし」と書くこと（H9）', () => {
    const debian = byId('debian');
    expect(debian.license).toBeNull();
    expect(debian.licenseUrl).toBeNull();
    expect(debian.licenseLabel).toContain('ライセンスの明記なし');
    expect(debian.licenseLabel).not.toMatch(/CC|MIT|MPL|GPL|パブリックドメイン/);
  });

  it('NVD の加工の有無に「加工した内容は NVD の提供ではない」趣旨があること（利用規約）', () => {
    expect(byId('nvd').modification).toContain('NVD');
    expect(byId('nvd').modification).toMatch(/加工/);
  });
});

describe('T07: ダッシュボードの「データの出典とライセンス」欄（H11）', () => {
  beforeEach(() => {
    loadBody('dashboard.html');
    window.location.hash = '';
    (globalThis as any).chrome = {
      runtime: {
        getManifest: () => ({ version: '0.0.1' }),
        sendMessage: vi.fn().mockResolvedValue({ success: true, reports: [] }),
      },
    };
  });

  afterEach(() => {
    window.location.hash = '';
    vi.resetModules();
  });

  async function init(): Promise<void> {
    vi.resetModules();
    const mod = await import('../src/dashboard/dashboard');
    await mod.initDashboard();
  }

  const panel = (): HTMLElement => {
    const el = document.getElementById(DATA_SOURCES_VIEW_ID);
    if (!el) throw new Error(`#${DATA_SOURCES_VIEW_ID} がありません`);
    return el;
  };

  it('欄の id が dataSourcesView で、view-panel として dashboard.html にあること', () => {
    expect(DATA_SOURCES_VIEW_ID).toBe('dataSourcesView');
    expect(panel().classList.contains('view-panel')).toBe(true);
    expect(panel().textContent).toContain('データの出典とライセンス');
  });

  it('サイドバーに欄を開くナビの項目があり、クリックで欄が表示されること', async () => {
    await init();
    const nav = document.querySelector(`.nav-item[data-view="${DATA_SOURCES_VIEW_ID}"]`) as HTMLElement | null;
    expect(nav).not.toBeNull();
    expect(nav!.textContent).toContain('出典');
    nav!.dispatchEvent(new Event('click'));
    expect(panel().classList.contains('active')).toBe(true);
    expect(document.getElementById('overviewView')!.classList.contains('active')).toBe(false);
  });

  it('欄に NVD の表示文（一字一句）と利用規約へのリンクがあること', async () => {
    await init();
    expect(panel().textContent).toContain(EXPECTED_NVD_NOTICE);
    const hrefs = Array.from(panel().querySelectorAll('a[href]')).map((a) => a.getAttribute('href'));
    expect(hrefs).toContain(NVD_TERMS_URL);
  });

  it('欄に 7 種類すべての名前・ライセンスの表記と、出典の URL へのリンクがあること', async () => {
    await init();
    const text = panel().textContent ?? '';
    const hrefs = Array.from(panel().querySelectorAll('a[href]')).map((a) => a.getAttribute('href'));
    for (const s of BUNDLED_DATA_SOURCES) {
      expect(text, s.id).toContain(s.name);
      expect(text, s.id).toContain(s.licenseLabel);
      expect(hrefs, s.id).toContain(s.url);
      if (s.licenseUrl !== null) expect(hrefs, s.id).toContain(s.licenseUrl);
    }
  });

  it('調査結果が 1 件も無くても欄の中身が出ること（調査結果に依存しない）', async () => {
    await init();
    expect(panel().textContent).toContain(EXPECTED_NVD_NOTICE);
    expect(panel().textContent).toContain(byId('debian').name);
  });

  it('欄のリンクはすべて https で、インラインイベントハンドラを含まないこと', async () => {
    await init();
    const anchors = Array.from(panel().querySelectorAll('a'));
    expect(anchors.length).toBeGreaterThan(0);
    for (const a of anchors) {
      expect(a.getAttribute('href') ?? '').toMatch(/^https:\/\//);
    }
    expect(panel().innerHTML).not.toMatch(/\bon[a-z]+\s*=/i);
  });

  it('URL のハッシュが #dataSourcesView なら、初期表示でその欄が開くこと', async () => {
    window.location.hash = `#${DATA_SOURCES_VIEW_ID}`;
    expect(window.location.hash).toBe(`#${DATA_SOURCES_VIEW_ID}`);
    await init();
    expect(panel().classList.contains('active')).toBe(true);
    expect(document.getElementById('overviewView')!.classList.contains('active')).toBe(false);
    const nav = document.querySelector(`.nav-item[data-view="${DATA_SOURCES_VIEW_ID}"]`);
    expect(nav?.classList.contains('active')).toBe(true);
    const activePanels = document.querySelectorAll('.view-panel.active');
    expect(activePanels.length).toBe(1);
  });

  it('陰性: ハッシュが無いときは従来どおり概要サマリーが開くこと', async () => {
    await init();
    expect(document.getElementById('overviewView')!.classList.contains('active')).toBe(true);
    expect(panel().classList.contains('active')).toBe(false);
  });

  it.each([
    ['存在しない id', '#noSuchView'],
    ['view-panel でない要素の id', '#currentHostname'],
    ['HTML を含む値', '#%3Cimg%20src%3Dx%3E'],
    ['セレクタとして不正な値', '#a"]),b[x'],
  ])('陰性: ハッシュが %s なら概要サマリーのままで、例外を投げないこと', async (_label, hash) => {
    window.location.hash = hash;
    await expect(init()).resolves.toBeUndefined();
    expect(document.getElementById('overviewView')!.classList.contains('active')).toBe(true);
    expect(panel().classList.contains('active')).toBe(false);
    expect(document.querySelectorAll('.view-panel.active').length).toBe(1);
  });
});

describe('T07: ポップアップは欄へのリンクだけ（H11・H12）', () => {
  const tabsCreate = vi.fn();

  beforeEach(() => {
    loadBody('popup.html');
    tabsCreate.mockReset();
    (globalThis as any).chrome = {
      runtime: {
        getManifest: () => ({ version: '0.0.1' }),
        getURL: (p: string) => `chrome-extension://abcdefghijklmnop/${p}`,
        sendMessage: vi.fn().mockResolvedValue({ success: false, error: 'テスト' }),
      },
      tabs: { create: tabsCreate },
    };
  });

  async function initPopup(): Promise<void> {
    vi.resetModules();
    await import('../src/popup/popup');
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await Promise.resolve();
  }

  it('popup.html に #dataSourcesLink があり、短い文言（「出典」を含む）であること（450px で崩さない）', () => {
    const link = document.getElementById('dataSourcesLink');
    expect(link).not.toBeNull();
    const text = (link!.textContent ?? '').trim();
    expect(text).toContain('出典');
    expect(text.length).toBeLessThanOrEqual(20);
    expect(link!.outerHTML).not.toMatch(/\bon[a-z]+\s*=/i);
  });

  it('リンクをクリックすると、ダッシュボードの欄（dashboard.html#dataSourcesView）を新しいタブで開くこと', async () => {
    await initPopup();
    const link = document.getElementById('dataSourcesLink') as HTMLElement;
    link.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    // テストごとにモジュールを読み直すため、前のテストの読み込みが document に残した処理が呼ぶこともある。回数ではなく中身を比べる
    expect(tabsCreate).toHaveBeenCalled();
    for (const call of tabsCreate.mock.calls) {
      expect(call[0]).toEqual({
        url: `chrome-extension://abcdefghijklmnop/dashboard.html#${DATA_SOURCES_VIEW_ID}`,
      });
    }
  });

  it('陰性: 既存のダッシュボードを開くボタンはハッシュ無しのまま（従来どおり）', async () => {
    await initPopup();
    (document.getElementById('openDashboardBtn') as HTMLElement).dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(tabsCreate).toHaveBeenCalled();
    for (const call of tabsCreate.mock.calls) {
      expect(call[0]).toEqual({ url: 'chrome-extension://abcdefghijklmnop/dashboard.html' });
    }
  });

  it('陰性: ポップアップに NVD の表示文や出典の一覧を載せないこと（リンクだけ）', () => {
    const sources = [read('popup.html'), read('src/popup/popup.ts'), read('src/popup/render.ts')];
    for (const src of sources) {
      expect(src).not.toContain('not endorsed or certified by the NVD');
      expect(src).not.toContain('CC BY-SA 4.0');
      expect(src).not.toContain('BUNDLED_DATA_SOURCES');
    }
  });
});

describe('T07: Markdown のレポートの末尾の出典の節（§5.4）', () => {
  const md = generateMarkdownReport(createReport());
  const headings = md.split('\n').filter((l) => /^##\s/.test(l));
  const lastHeading = headings[headings.length - 1] ?? '';
  const lastSection = md.slice(md.lastIndexOf(lastHeading));

  it('最後の ## の節が出典の節（見出しに「出典」）であること', () => {
    expect(lastHeading).toContain('出典');
    expect(headings.filter((h) => h.includes('出典')).length).toBe(1);
  });

  it('陰性: 既存の §15（制限事項・免責事項）は残り、出典の節より前にあること', () => {
    const i15 = md.indexOf('## 15. 調査上の制限事項・免責事項');
    expect(i15).toBeGreaterThanOrEqual(0);
    expect(i15).toBeLessThan(md.lastIndexOf(lastHeading));
  });

  it('出典の節に NVD の表示文と 7 種類の名前・ライセンスの表記・URL があること', () => {
    expect(lastSection).toContain(EXPECTED_NVD_NOTICE);
    for (const s of BUNDLED_DATA_SOURCES) {
      expect(lastSection, s.id).toContain(s.name);
      expect(lastSection, s.id).toContain(s.licenseLabel);
      expect(lastSection, s.id).toContain(s.url);
    }
  });

  it('調査結果の中身によらず出ること（技術や指摘が無いレポートでも）', () => {
    expect(createReport().technologies.length).toBe(0);
    expect(lastSection).toContain(byId('ubuntu').licenseLabel);
  });
});
