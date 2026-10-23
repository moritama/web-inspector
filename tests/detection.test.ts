/**
 * Web Technology & Security Inspector
 * 技術検出エンジンの単体テスト (tests/detection.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../src/detection/engine';
import { DomSignals, NetworkSignals } from '../src/shared/types';

describe('DetectionEngine', () => {
  const engine = new DetectionEngine();

  const emptyDom: DomSignals = {
    url: 'https://example.com/',
    title: 'Example',
    metaTags: [],
    scriptUrls: [],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: [],
    cookiesFromDocument: [],
    cssAssets: [],
  };

  it('X-Powered-By ヘッダーから PHP 8.2 を正確に検出できること', () => {
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {
        'x-powered-by': ['PHP/8.2.14'],
        server: ['Apache/2.4.58 (Unix)'],
      },
      cookies: [],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
      network,
    });

    const php = results.find((r) => r.technology === 'PHP');
    expect(php).toBeDefined();
    expect(php?.detected).toBe(true);
    expect(php?.version).toBe('8.2.14');
    expect(php?.confidence).toBeGreaterThanOrEqual(80);
    expect(php?.confidenceLevel).toBe('high');
    expect(php?.evidence.some((e) => e.name === 'x-powered-by')).toBe(true);

    const apache = results.find((r) => r.technology === 'Apache');
    expect(apache).toBeDefined();
    expect(apache?.version).toBe('2.4.58');
  });

  it('metaタグおよびスクリプトから WordPress を検出できること', () => {
    const dom: DomSignals = {
      ...emptyDom,
      metaTags: [{ name: 'generator', content: 'WordPress 6.4.2' }],
      scriptUrls: ['https://example.com/wp-includes/js/jquery/jquery.min.js'],
      linkUrls: [{ rel: 'stylesheet', href: 'https://example.com/wp-content/themes/theme/style.css' }],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
    });

    const wp = results.find((r) => r.technology === 'WordPress');
    expect(wp).toBeDefined();
    expect(wp?.version).toBe('6.4.2');
    expect(wp?.confidence).toBeGreaterThanOrEqual(80);
  });

  it('DOM属性から React および Next.js を検出できること', () => {
    const dom: DomSignals = {
      ...emptyDom,
      domMarkers: ['script#__NEXT_DATA__', '__NEXT_DATA__', '[data-reactroot]'],
      scriptUrls: ['https://example.com/_next/static/chunks/main.js'],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
    });

    const nextjs = results.find((r) => r.technology === 'Next.js');
    expect(nextjs).toBeDefined();
    expect(nextjs?.confidenceLevel).toBe('high');

    const react = results.find((r) => r.technology === 'React');
    expect(react).toBeDefined();
  });

  it('Cookieおよびヘッダーから Laravel を検出できること', () => {
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {
        'x-powered-by': ['Laravel/10.15.0'],
      },
      cookies: [
        { name: 'laravel_session', value: 'dummy' },
        { name: 'XSRF-TOKEN', value: 'dummy' },
      ],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
      network,
    });

    const laravel = results.find((r) => r.technology === 'Laravel');
    expect(laravel).toBeDefined();
    expect(laravel?.detected).toBe(true);
    expect(laravel?.version).toBe('10.15.0');
    expect(laravel?.confidenceLevel).toBe('high');
  });

  it('X-Powered-By または connect.sid Cookie から Node.js を検出できること', () => {
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {
        'x-powered-by': ['Express'],
        server: ['Node.js/20.10.0'],
      },
      cookies: [{ name: 'connect.sid', value: 's%3A123' }],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
      network,
    });

    const node = results.find((r) => r.technology === 'Node.js');
    expect(node).toBeDefined();
    expect(node?.detected).toBe(true);
    expect(node?.version).toBe('20.10.0');
    expect(node?.confidenceLevel).toBe('high');
  });

  it('XSRF-TOKEN Cookie単体では、個別の3行ではなく1行の候補グループ「Java / Laravel / Node.js (候補)」として集約検出されること', () => {
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {},
      cookies: [{ name: 'XSRF-TOKEN', value: 'token-abc' }],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
      network,
    });

    const candidate = results.find((r) => r.technology === 'Java / Laravel / Node.js (候補)');
    const laravel = results.find((r) => r.technology === 'Laravel');
    const java = results.find((r) => r.technology === 'Java');
    const node = results.find((r) => r.technology === 'Node.js');
    const php = results.find((r) => r.technology === 'PHP');

    // 1行の候補グループとして集約検出されること
    expect(candidate).toBeDefined();
    expect(candidate?.isCandidateGroup).toBe(true);
    expect(candidate?.confidence).toBe(35);
    expect(candidate?.confidenceLevel).toBe('low');
    expect(candidate?.candidateTechnologies).toEqual([
      'Java (Spring Boot)',
      'Laravel (PHP)',
      'Node.js (Express)',
    ]);
    expect(candidate?.evidence[0]?.detail).toContain('いずれかが稼働している可能性');

    // 個別の3行はリストに出ないこと
    expect(laravel).toBeUndefined();
    expect(java).toBeUndefined();
    expect(node).toBeUndefined();

    // 確信度50%未満のため、連動検知（PHP）は発動しないこと
    expect(php).toBeUndefined();
  });

  it('laravel_session（85%）が存在する場合、Laravelが確定し、XSRF-TOKEN由来のJavaやNode.js候補は抑制（非表示）されること', () => {
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {},
      cookies: [
        { name: 'laravel_session', value: 'session-secret' },
        { name: 'XSRF-TOKEN', value: 'token-abc' },
      ],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
      network,
    });

    const laravel = results.find((r) => r.technology === 'Laravel');
    const php = results.find((r) => r.technology === 'PHP');
    const java = results.find((r) => r.technology === 'Java');
    const node = results.find((r) => r.technology === 'Node.js');
    const candidate = results.find((r) => r.technology === 'Java / Laravel / Node.js (候補)');

    // Laravelが確定検出（85%）されること
    expect(laravel).toBeDefined();
    expect(laravel?.confidence).toBe(85);

    // 連動検知によりPHPも確定（80%）されること
    expect(php).toBeDefined();
    expect(php?.confidenceLevel).toBe('high');

    // XSRF-TOKEN由来の他言語や候補グループは綺麗に抑制されること
    expect(java).toBeUndefined();
    expect(node).toBeUndefined();
    expect(candidate).toBeUndefined();
  });

  it('Next.js 検出時に Node.js と React が連動検出（Implication）されること', () => {
    const dom: DomSignals = {
      ...emptyDom,
      domMarkers: ['script#__NEXT_DATA__'],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
    });

    const nextjs = results.find((r) => r.technology === 'Next.js');
    expect(nextjs).toBeDefined();
    expect(nextjs?.confidence).toBeGreaterThanOrEqual(80);

    // 連動検知された Node.js
    const node = results.find((r) => r.technology === 'Node.js');
    expect(node).toBeDefined();
    expect(node?.versionSource).toBe('implication');
    expect(node?.confidenceLevel).toBe('high');
    expect(node?.evidence.some((e) => e.name === '連動検出 (Implication)' && e.source === 'Next.js')).toBe(true);

    // 連動検知された React
    const react = results.find((r) => r.technology === 'React');
    expect(react).toBeDefined();
    expect(react?.evidence.some((e) => e.name === '連動検出 (Implication)' && e.source === 'Next.js')).toBe(true);
  });

  it('WordPress 検出時に PHP ヘッダーが無くても PHP が連動検出されること', () => {
    const dom: DomSignals = {
      ...emptyDom,
      metaTags: [{ name: 'generator', content: 'WordPress 6.4.2' }],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
    });

    const wp = results.find((r) => r.technology === 'WordPress');
    expect(wp).toBeDefined();

    const php = results.find((r) => r.technology === 'PHP');
    expect(php).toBeDefined();
    expect(php?.versionSource).toBe('implication');
    expect(php?.confidenceLevel).toBe('high');
    expect(php?.evidence.some((e) => e.name === '連動検出 (Implication)' && e.source === 'WordPress')).toBe(true);
  });

  it('laravel_session Cookie（確信度85%）検出時に Laravel と連動して PHP が検出されること', () => {
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {},
      cookies: [{ name: 'laravel_session', value: 'session-secret' }],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
      network,
    });

    const laravel = results.find((r) => r.technology === 'Laravel');
    expect(laravel).toBeDefined();
    expect(laravel?.confidence).toBe(85);

    const php = results.find((r) => r.technology === 'PHP');
    expect(php).toBeDefined();
    expect(php?.versionSource).toBe('implication');
    expect(php?.confidenceLevel).toBe('high');
    expect(php?.evidence.some((e) => e.name === '連動検出 (Implication)' && e.source === 'Laravel')).toBe(true);
  });

  it('Nuxt 検出時に Node.js と Vue.js が連動検出されること', () => {
    const dom: DomSignals = {
      ...emptyDom,
      scriptUrls: ['https://example.com/_nuxt/entry.mjs'],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
    });

    const nuxt = results.find((r) => r.technology === 'Nuxt');
    expect(nuxt).toBeDefined();

    const node = results.find((r) => r.technology === 'Node.js');
    expect(node).toBeDefined();
    expect(node?.evidence.some((e) => e.name === '連動検出 (Implication)' && e.source === 'Nuxt')).toBe(true);

    const vue = results.find((r) => r.technology === 'Vue.js');
    expect(vue).toBeDefined();
    expect(vue?.evidence.some((e) => e.name === '連動検出 (Implication)' && e.source === 'Nuxt')).toBe(true);
  });

  it('シグナルが一切ない場合、推測で技術を断定せず未検出となること', () => {
    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
    });

    expect(results.length).toBe(0);
  });
});
