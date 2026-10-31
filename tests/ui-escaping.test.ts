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
});
