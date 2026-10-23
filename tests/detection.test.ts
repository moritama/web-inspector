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

  it('シグナルが一切ない場合、推測で技術を断定せず未検出となること', () => {
    const results = engine.detect({
      url: 'https://example.com/',
      dom: emptyDom,
    });

    expect(results.length).toBe(0);
  });
});
