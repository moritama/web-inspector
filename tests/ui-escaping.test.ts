// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * UI エスケープおよびリンク無害化の単体テスト (tests/ui-escaping.test.ts) - IMPL-03
 */

import { describe, expect, it } from 'vitest';
import {
  renderFullSecurityHtml,
  renderFullTechnologiesHtml,
  renderLibrarySecurityTableHtml,
} from '../src/dashboard/render';
import {
  renderCookieModalHtml,
  renderSecurityModalHtml,
  renderTechModalHtml,
} from '../src/popup/render';
import { escapeHtml, renderSafeExternalLink, safeHref } from '../src/shared/html';
import { DetectedTechnology, SecurityCheckResult } from '../src/shared/types';

describe('IMPL-03: escapeHtml 単体テスト', () => {
  it('危険なHTMLタグや属性文字を正しく実体参照へエスケープする', () => {
    const payload = '<img src=x onerror=alert(1)>';
    const escaped = escapeHtml(payload);
    expect(escaped).toBe('&lt;img src=x onerror=alert(1)&gt;');
    expect(escaped).not.toContain('<img');
    expect(escaped).not.toContain('>');

    const payloadWithQuotes = '<img src="x" onerror=alert(1)>';
    expect(escapeHtml(payloadWithQuotes)).toBe('&lt;img src=&quot;x&quot; onerror=alert(1)&gt;');
  });

  it('&, <, >, ", \' の5つの特殊文字を網羅してエスケープする', () => {
    const raw = `& < > " '`;
    expect(escapeHtml(raw)).toBe('&amp; &lt; &gt; &quot; &#039;');
  });

  it('null / undefined に対して空文字を返す', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });

  it('文字列以外のプリミティブ（数値・boolean）を安全に文字列化してエスケープする', () => {
    expect(escapeHtml(123)).toBe('123');
    expect(escapeHtml(0)).toBe('0');
    expect(escapeHtml(true)).toBe('true');
    expect(escapeHtml(false)).toBe('false');
  });
});

describe('IMPL-03: safeHref 単体テスト', () => {
  it('https: URL のみを許可し、正規化されたURLを返す', () => {
    expect(safeHref('https://nvd.nist.gov/vuln/detail/CVE-2023-1234')).toBe(
      'https://nvd.nist.gov/vuln/detail/CVE-2023-1234'
    );
    expect(safeHref('https://example.com/path?query=1#frag')).toBe(
      'https://example.com/path?query=1#frag'
    );
  });

  it('javascript: や data: など悪意あるスキームを拒否して null を返す', () => {
    expect(safeHref('javascript:alert(1)')).toBeNull();
    expect(safeHref('JAVASCRIPT:alert(document.cookie)')).toBeNull();
    expect(safeHref('javascript:void(0)')).toBeNull();
    expect(safeHref('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(safeHref('vbscript:msgbox(1)')).toBeNull();
  });

  it('非暗号化 http: スキームを拒否して null を返す', () => {
    expect(safeHref('http://example.com/')).toBeNull();
  });

  it('スキームなしの相対パスやプロトコル相対URL、解析不能な文字列を拒否して null を返す', () => {
    expect(safeHref('//evil.com/xss')).toBeNull();
    expect(safeHref('/local/path')).toBeNull();
    expect(safeHref('not-a-valid-url')).toBeNull();
    expect(safeHref('<img src=x onerror=alert(1)>')).toBeNull();
    expect(safeHref('')).toBeNull();
    expect(safeHref('   ')).toBeNull();
  });

  it('null, undefined, 非文字列に対して null を返す', () => {
    expect(safeHref(null)).toBeNull();
    expect(safeHref(undefined)).toBeNull();
    expect(safeHref(12345)).toBeNull();
    expect(safeHref({})).toBeNull();
  });
});

describe('IMPL-03: renderSafeExternalLink 単体テスト', () => {
  it('有効な https URL の場合、target="_blank" と rel="noopener noreferrer" を持つリンクを生成する', () => {
    const html = renderSafeExternalLink('https://example.com/', '公式サイト', {
      className: 'my-link',
    });
    expect(html).toContain('href="https://example.com/"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain('class="my-link"');
    expect(html).toContain('公式サイト');
  });

  it('javascript: などの安全でないURLの場合、リンクではなくエスケープされたテキストとして表示する', () => {
    const html = renderSafeExternalLink('javascript:alert(1)', '危険なリンク');
    expect(html).not.toContain('<a');
    expect(html).not.toContain('href');
    expect(html).toContain('<span>危険なリンク</span>');
  });
});

describe('IMPL-03: 悪意のある値を含むレポート描画時の XSS / 不正リンク防止検証', () => {
  const createMaliciousTech = (): DetectedTechnology => ({
    technology: '<script>alert("tech")</script>',
    category: 'js-framework',
    detected: true,
    version: '"><svg onload=alert(1)>',
    confidence: 100,
    confidenceLevel: 'high',
    evidence: [
      {
        type: 'html',
        name: '<b>bad-name</b>',
        value: '<iframe src="javascript:alert(1)"></iframe>',
        source: 'html-signal',
        detail: '<img src=x onerror=alert("evidence")>',
      },
    ],
    detectionMethod: 'direct',
    website: 'javascript:alert("website")',
    eolInfo: {
      status: 'EOL',
      source: 'endoflife.date',
      eolDate: '"><img src=x onerror=alert("eolDate")>',
      recommendation: '<img src=x onerror=alert("eolRec")>',
      sourceUrl: 'javascript:alert("eolSource")',
    },
    advisories: [
      {
        id: 'CVE-2026-XSS',
        title: '<img src=x onerror=alert("advTitle")>',
        summary: '<script>alert("advSummary")</script>',
        severity: 'HIGH',
        affectedRange: '<img src=x onerror=alert("range")>',
        fixedVersion: '"><img src=x onerror=alert("fixed")>',
        referenceUrls: ['javascript:alert("advRef")', 'https://nvd.nist.gov/vuln/detail/CVE-2026-XSS'],
      },
    ],
  });

  const createMaliciousCheck = (): SecurityCheckResult => ({
    checkId: 'SEC-XSS-01',
    name: '<img src=x onerror=alert("checkName")>',
    category: 'http-headers',
    status: 'fail',
    severity: 'high',
    scope: '<img src=x onerror=alert("scope")>',
    observed: '<img src=x onerror=alert("observed")>',
    description: '<script>alert("desc")</script>',
    recommendation: '<img src=x onerror=alert("rec")>',
    exceptionReason: '<img src=x onerror=alert("reason")>',
    referenceUrls: ['javascript:alert("checkRef")', 'https://cheatsheetseries.owasp.org/'],
  });

  it('ポップアップ: 技術詳細モーダルに悪意ある値を描画しても img / script タグや javascript: リンクが生成されない', () => {
    const tech = createMaliciousTech();
    const html = renderTechModalHtml(tech);

    const container = document.createElement('div');
    container.innerHTML = html;

    // img, script, svg, iframe などの実行可能要素が DOM 上に存在しないこと
    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect(container.querySelectorAll('script')).toHaveLength(0);
    expect(container.querySelectorAll('svg')).toHaveLength(0);
    expect(container.querySelectorAll('iframe')).toHaveLength(0);

    // javascript: スキームの a タグが存在しないこと
    expect(container.querySelectorAll('a[href^="javascript:"]')).toHaveLength(0);

    // 有効な https URL（referenceUrls の 2 番目）のみ a タグになり、noopener が付与されていること
    const links = Array.from(container.querySelectorAll('a'));
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.getAttribute('href')).toMatch(/^https:\/\//);
      expect(link.getAttribute('rel')).toBe('noopener noreferrer');
      expect(link.getAttribute('target')).toBe('_blank');
    }
  });

  it('ポップアップ: セキュリティ詳細モーダルに悪意ある値を描画しても img / script タグや javascript: リンクが生成されない', () => {
    const check = createMaliciousCheck();
    const html = renderSecurityModalHtml(check);

    const container = document.createElement('div');
    container.innerHTML = html;

    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect(container.querySelectorAll('script')).toHaveLength(0);
    expect(container.querySelectorAll('a[href^="javascript:"]')).toHaveLength(0);

    const links = Array.from(container.querySelectorAll('a'));
    expect(links).toHaveLength(1);
    expect(links[0].getAttribute('href')).toBe('https://cheatsheetseries.owasp.org/');
    expect(links[0].getAttribute('rel')).toBe('noopener noreferrer');
  });

  it('ダッシュボード: renderFullTechnologiesHtml で adv.title や website がエスケープされ安全である', () => {
    const tech = createMaliciousTech();
    const html = renderFullTechnologiesHtml([tech]);

    const container = document.createElement('div');
    container.innerHTML = html;

    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect(container.querySelectorAll('script')).toHaveLength(0);
    expect(container.querySelectorAll('a[href^="javascript:"]')).toHaveLength(0);
  });

  it('ダッシュボード: renderFullSecurityHtml で referenceUrls が安全に処理され、javascript: リンクが生成されない', () => {
    const check = createMaliciousCheck();
    const html = renderFullSecurityHtml([check]);

    const container = document.createElement('div');
    container.innerHTML = html;

    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect(container.querySelectorAll('script')).toHaveLength(0);
    expect(container.querySelectorAll('a[href^="javascript:"]')).toHaveLength(0);

    const links = Array.from(container.querySelectorAll('a'));
    expect(links).toHaveLength(1);
    expect(links[0].getAttribute('href')).toBe('https://cheatsheetseries.owasp.org/');
    expect(links[0].getAttribute('rel')).toBe('noopener noreferrer');
  });

  it('ダッシュボード: renderLibrarySecurityTableHtml で悪意ある値がエスケープされ安全である', () => {
    const tech = createMaliciousTech();
    const html = renderLibrarySecurityTableHtml([tech]);

    const container = document.createElement('div');
    container.innerHTML = html;

    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect(container.querySelectorAll('script')).toHaveLength(0);
  });

  it('ポップアップ: Cookie詳細モーダルに悪意ある値を描画してもタグが実行されずエスケープされる', () => {
    const html = renderCookieModalHtml({
      name: '<script>alert(1)</script>',
      domain: '<img src=x onerror=alert(2)>',
      path: '"><svg onload=alert(3)>',
      secure: false,
      httpOnly: false,
      sameSite: 'lax',
      session: true,
      issues: ['<b onmouseover=alert(4)>issue</b>', '<img src=x onerror=alert(5)>'],
    });

    const container = document.createElement('div');
    container.innerHTML = html;

    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect(container.querySelectorAll('script')).toHaveLength(0);
    expect(container.querySelectorAll('svg')).toHaveLength(0);
    expect(container.querySelectorAll('b')).toHaveLength(0);
  });

  it('T03 (SPEC-13): 新しいバッジ (fixStatus・KEV・重大度) に悪意ある文字列を入れたときにエスケープされること', () => {
    const tech = createMaliciousTech();
    tech.advisories = [
      {
        id: 'CVE-2020-11023',
        title: 'Test Adv',
        severity: '<img src=x onerror=alert("sev")>' as unknown as 'critical',
        cvssScore: 9.8,
        affectedRange: '< 3.5.0',
        fixedVersion: '3.5.0',
        fixStatus: '<img src=x onerror=alert("fix")>' as unknown as 'fixed',
        kev: true,
        kevDateAdded: '<img src=x onerror=alert("kev")>',
        summary: 'Summary',
        referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2020-11023'],
      },
    ];

    const popupHtml = renderTechModalHtml(tech);
    const dashboardFullHtml = renderFullTechnologiesHtml([tech]);
    const dashboardLibTableHtml = renderLibrarySecurityTableHtml([tech]);

    for (const html of [popupHtml, dashboardFullHtml, dashboardLibTableHtml]) {
      const container = document.createElement('div');
      container.innerHTML = html;
      expect(container.querySelectorAll('img')).toHaveLength(0);
      expect(container.querySelectorAll('script')).toHaveLength(0);
      expect(html).toContain('悪用確認済み（CISA KEV）');
    }
  });

  // --- T04 (SPEC-03): 「収録 DB 上は該当なし」・収録範囲・多件数の折りたたみ・ディストリ版上流参考件数 ---
  describe('T04 (SPEC-03): Popup / Dashboard の脆弱性表示（収録範囲・多件数折りたたみ・ディストリ版）', () => {
    it('固定 DB で Apache 2.4.62 を照合したとき、ポップアップとダッシュボードに「収録 DB 上は該当なし」「収録 3 件」「dataVersion」が出る', async () => {
      const { matchOfflineAdvisories } = await import('../src/detection/advisory');
      const rawFixtureDb = (await import('./fixtures/advisory-db.fixture.json')).default;
      const match = matchOfflineAdvisories('Apache', '2.4.62', rawFixtureDb as unknown as Parameters<typeof matchOfflineAdvisories>[2]);

      const apacheTech: DetectedTechnology = {
        technology: 'Apache',
        category: 'web-server',
        detected: true,
        confidence: 100,
        confidenceLevel: 'high',
        version: '2.4.62',
        evidence: [],
        advisoryMatchStatus: match.matchStatus,
        advisories: match.advisories,
        eolInfo: match.eolInfo,
        productAdvisoryCount: match.productAdvisoryCount,
        productSources: match.productSources,
        advisoryDataVersion: match.advisoryDataVersion,
        advisoryStatusLabel: match.advisoryStatusLabel,
      };

      const popupHtml = renderTechModalHtml(apacheTech);
      const dashTableHtml = renderLibrarySecurityTableHtml([apacheTech]);
      const dashFullHtml = renderFullTechnologiesHtml([apacheTech]);

      for (const html of [popupHtml, dashTableHtml, dashFullHtml]) {
        expect(html).toContain('収録 DB 上は該当なし');
        expect(html).toContain('収録 3 件');
        expect(html).toContain('curated / NVD');
        expect(html).toContain('dataVersion: 20261031');
      }
    });

    it('12 件該当する固定データで、表示が 5 件＋「ほか 7 件」になり、先頭が KEV のエントリである', async () => {
      const { matchOfflineAdvisories } = await import('../src/detection/advisory');
      const manyDb = {
        dataVersion: '20261031',
        generatedAt: '2026-10-31T00:00:00Z',
        coverage: {
          technologies: ['many-lib'],
          byProduct: {
            'many-lib': { count: 12, sources: ['curated', 'OSV', 'NVD'] },
          },
        },
        libraries: {
          'many-lib': {
            aliases: ['many-lib'],
            eol: [{ cycle: '1.x', eolDate: null, status: 'Supported' }],
            versions: [
              ...Array.from({ length: 11 }, (_, i) => ({
                range: '< 2.0.0',
                cve: `CVE-2026-00${String(i + 1).padStart(2, '0')}`,
                cvssScore: 5.0 + (i % 5) * 0.5,
                severity: i === 0 ? 'critical' : i < 4 ? 'high' : 'medium',
                title: `Vuln ${i + 1}`,
                fixedVersion: i === 10 ? '1.9.9' : `1.0.${i + 1}`,
                fixStatus: 'fixed' as const,
                kev: false,
                origin: 'auto',
              })),
              {
                range: '< 2.0.0',
                cve: 'CVE-2026-9999',
                cvssScore: 7.2,
                severity: 'high',
                title: 'KEV Priority Entry',
                fixedVersion: '1.2.0',
                fixStatus: 'fixed' as const,
                kev: true,
                kevDateAdded: '2026-05-01',
                origin: 'curated',
              },
            ],
          },
        },
      };

      const match = matchOfflineAdvisories('many-lib', '1.0.0', manyDb as unknown as Parameters<typeof matchOfflineAdvisories>[2]);
      const manyTech: DetectedTechnology = {
        technology: 'many-lib',
        category: 'js-framework',
        detected: true,
        confidence: 100,
        confidenceLevel: 'high',
        version: '1.0.0',
        evidence: [],
        advisoryMatchStatus: match.matchStatus,
        advisories: match.advisories,
        productAdvisoryCount: match.productAdvisoryCount,
        productSources: match.productSources,
        advisoryDataVersion: match.advisoryDataVersion,
      };

      // ポップアップの検証
      const popupContainer = document.createElement('div');
      popupContainer.innerHTML = renderTechModalHtml(manyTech);
      const allPopupCards = popupContainer.querySelectorAll('.advisory-card');
      const hiddenPopupCards = popupContainer.querySelectorAll('details.advisory-more .advisory-card');
      expect(allPopupCards).toHaveLength(12);
      expect(hiddenPopupCards).toHaveLength(7);
      expect(allPopupCards.length - hiddenPopupCards.length).toBe(5);
      expect(popupContainer.querySelector('details.advisory-more > summary')?.textContent).toContain('ほか 7 件');
      expect(allPopupCards[0].textContent).toContain('CVE-2026-9999');
      expect(allPopupCards[0].textContent).toContain('悪用確認済み（CISA KEV）');
      // 推奨版は全12件から計算された 1.9.9 が表示されること
      expect(popupContainer.innerHTML).toContain('1.9.9');

      // ダッシュボード（技術詳細カード）の検証
      const dashContainer = document.createElement('div');
      dashContainer.innerHTML = renderFullTechnologiesHtml([manyTech]);
      const allDashCards = dashContainer.querySelectorAll('.advisory-card');
      const hiddenDashCards = dashContainer.querySelectorAll('details.advisory-more .advisory-card');
      expect(allDashCards).toHaveLength(12);
      expect(hiddenDashCards).toHaveLength(7);
      expect(allDashCards.length - hiddenDashCards.length).toBe(5);
      expect(dashContainer.querySelector('details.advisory-more > summary')?.textContent).toContain('ほか 7 件');
      expect(allDashCards[0].textContent).toContain('CVE-2026-9999');
      expect(allDashCards[0].textContent).toContain('悪用確認済み（CISA KEV）');

      // ダッシュボード（一覧テーブル）の検証
      const tableContainer = document.createElement('table');
      tableContainer.innerHTML = `<tbody>${renderLibrarySecurityTableHtml([manyTech])}</tbody>`;
      expect(tableContainer.textContent).toContain('ほか 7 件');
      expect(tableContainer.textContent).toContain('CVE-2026-9999');
      expect(tableContainer.textContent).toContain('1.9.9');
    });

    it('Apache/2.4.41 (Ubuntu) で Needs Review のまま、「上流版では N 件」が表示される', async () => {
      const { matchOfflineAdvisories } = await import('../src/detection/advisory');
      const rawFixtureDb = (await import('./fixtures/advisory-db.fixture.json')).default;
      const match = matchOfflineAdvisories('Apache', '2.4.41 (Ubuntu)', rawFixtureDb as unknown as Parameters<typeof matchOfflineAdvisories>[2]);

      const distroTech: DetectedTechnology = {
        technology: 'Apache',
        category: 'web-server',
        detected: true,
        confidence: 100,
        confidenceLevel: 'high',
        version: '2.4.41 (Ubuntu)',
        evidence: [],
        advisoryMatchStatus: match.matchStatus,
        advisories: match.advisories,
        productAdvisoryCount: match.productAdvisoryCount,
        productSources: match.productSources,
        advisoryDataVersion: match.advisoryDataVersion,
        upstreamAdvisoriesCount: match.upstreamAdvisoriesCount,
      };

      const popupHtml = renderTechModalHtml(distroTech);
      const dashTableHtml = renderLibrarySecurityTableHtml([distroTech]);
      const dashFullHtml = renderFullTechnologiesHtml([distroTech]);

      for (const html of [popupHtml, dashTableHtml, dashFullHtml]) {
        expect(html).toContain('Needs Review');
        expect(html).toContain('上流版では 1 件');
      }
    });

    it('収録件数 0 の技術（Tailwind CSS）は「この技術の脆弱性は収録していません」と表示される', async () => {
      const { matchOfflineAdvisories } = await import('../src/detection/advisory');
      const rawFixtureDb = (await import('./fixtures/advisory-db.fixture.json')).default;
      const match = matchOfflineAdvisories('Tailwind CSS', '3.4.1', rawFixtureDb as unknown as Parameters<typeof matchOfflineAdvisories>[2]);

      const tailwindTech: DetectedTechnology = {
        technology: 'Tailwind CSS',
        category: 'js-framework',
        detected: true,
        confidence: 95,
        confidenceLevel: 'high',
        version: '3.4.1',
        evidence: [],
        advisoryMatchStatus: match.matchStatus,
        advisories: match.advisories,
        productAdvisoryCount: match.productAdvisoryCount,
        productSources: match.productSources,
        advisoryDataVersion: match.advisoryDataVersion,
        advisoryStatusLabel: match.advisoryStatusLabel,
      };

      const popupHtml = renderTechModalHtml(tailwindTech);
      const dashTableHtml = renderLibrarySecurityTableHtml([tailwindTech]);
      const dashFullHtml = renderFullTechnologiesHtml([tailwindTech]);

      for (const html of [popupHtml, dashTableHtml, dashFullHtml]) {
        expect(html).toContain('この技術の脆弱性は収録していません');
      }
    });
  });
});
