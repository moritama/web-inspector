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

  it('Next.js 検出時に Node.js と React が連動検出（Implication）されること (SSR時)', () => {
    const dom: DomSignals = {
      ...emptyDom,
      domMarkers: ['script#__NEXT_DATA__'],
    };
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {
        'x-powered-by': ['Next.js'],
      },
      cookies: [],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
      network,
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

  it('Nuxt 検出時に Node.js と Vue.js が連動検出されること (SSR時)', () => {
    const dom: DomSignals = {
      ...emptyDom,
      scriptUrls: ['https://example.com/_nuxt/entry.mjs'],
    };
    const network: NetworkSignals = {
      url: 'https://example.com/',
      responseHeaders: {
        'x-powered-by': ['Nuxt'],
      },
      cookies: [],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
      network,
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

  // --- IMP-14: バックエンドフレームワーク検出テスト ---
  describe('IMP-14: バックエンドフレームワーク検出', () => {
    it('Spring Boot を X-Application-Context ヘッダーから検出し、Java が連動検出されること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {
          'x-application-context': ['application:8080'],
        },
        cookies: [],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const springBoot = results.find((r) => r.technology === 'Spring Boot');
      expect(springBoot).toBeDefined();
      expect(springBoot?.detectionMethod).toBe('direct');
      expect(springBoot?.runtimeStatus).toBe('confirmed');

      const java = results.find((r) => r.technology === 'Java');
      expect(java).toBeDefined();
      expect(java?.detectionMethod).toBe('inferred');
      expect(java?.implicationType).toBe('runtime-dependency');
      expect(java?.inferredFrom).toBe('Spring Boot');
    });

    it('ASP.NET Core を .AspNetCore.Antiforgery Cookie から検出し、ASP.NET が連動検出されること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {},
        cookies: [{ name: '.AspNetCore.Antiforgery.xxx', value: 'token' }],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const aspnetCore = results.find((r) => r.technology === 'ASP.NET Core');
      expect(aspnetCore).toBeDefined();
      expect(aspnetCore?.detectionMethod).toBe('direct');

      const dotnet = results.find((r) => r.technology === '.NET');
      expect(dotnet).toBeDefined();
      expect(dotnet?.detectionMethod).toBe('inferred');
      expect(dotnet?.implicationType).toBe('runtime-dependency');
    });

    it('Express を X-Powered-By ヘッダーから検出し、Node.js が連動検出されること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {
          'x-powered-by': ['Express'],
        },
        cookies: [],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const express = results.find((r) => r.technology === 'Express');
      expect(express).toBeDefined();

      const node = results.find((r) => r.technology === 'Node.js');
      expect(node).toBeDefined();
      expect(node?.detectionMethod).toBe('inferred');
      expect(node?.implicationType).toBe('runtime-dependency');
    });

    it('FastAPI を Swagger UI ドキュメントから検出し、Python が連動検出されること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        title: 'FastAPI - Swagger UI',
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const fastapi = results.find((r) => r.technology === 'FastAPI');
      expect(fastapi).toBeDefined();

      const python = results.find((r) => r.technology === 'Python');
      expect(python).toBeDefined();
      expect(python?.detectionMethod).toBe('inferred');
    });

    it('CakePHP を cakephp Cookie から検出し、PHP が連動検出されること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {},
        cookies: [{ name: 'cakephp', value: 'session123' }],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const cake = results.find((r) => r.technology === 'CakePHP');
      expect(cake).toBeDefined();

      const php = results.find((r) => r.technology === 'PHP');
      expect(php).toBeDefined();
      expect(php?.detectionMethod).toBe('inferred');
    });
  });

  // --- IMP-15: フロントエンド・UIライブラリ検出テスト ---
  describe('IMP-15: フロントエンド・UIライブラリ検出', () => {
    it('Alpine.js を DOMマーカーから検出できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        domMarkers: ['[x-data]', 'x-data'],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const alpine = results.find((r) => r.technology === 'Alpine.js');
      expect(alpine).toBeDefined();
      expect(alpine?.category).toBe('js-framework');
      expect(alpine?.detectionMethod).toBe('direct');
    });

    it('htmx を DOMマーカーから検出できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        domMarkers: ['[hx-get]', 'hx-get'],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const htmx = results.find((r) => r.technology === 'htmx');
      expect(htmx).toBeDefined();
      expect(htmx?.category).toBe('js-framework');
    });

    it('DataTables, Chart.js, Axios をスクリプトURLから検出できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js',
          'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js',
          'https://unpkg.com/axios@1.6.2/dist/axios.min.js',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      expect(results.some((r) => r.technology === 'DataTables')).toBe(true);
      expect(results.some((r) => r.technology === 'Chart.js')).toBe(true);
      expect(results.some((r) => r.technology === 'Axios')).toBe(true);
    });

    it('Astro を DOMマーカーおよびmeta generatorから検出できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        metaTags: [{ name: 'generator', content: 'Astro v4.0.0' }],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const astro = results.find((r) => r.technology === 'Astro');
      expect(astro).toBeDefined();
      expect(astro?.version).toBe('4.0.0');
    });

    it('SvelteKit を DOMマーカーから検出し、Svelte が連動検出されること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        domMarkers: ['div#svelte', '__sveltekit'],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const sveltekit = results.find((r) => r.technology === 'SvelteKit');
      expect(sveltekit).toBeDefined();

      const svelte = results.find((r) => r.technology === 'Svelte');
      expect(svelte).toBeDefined();
      expect(svelte?.detectionMethod).toBe('inferred');
    });
  });

  // --- IMP-16: ホスティング・外部サービス検出テスト ---
  describe('IMP-16: ホスティング・外部サービス検出', () => {
    it('Vercel を Server ヘッダーおよび X-Vercel-Id から検出し、hosting-cloud カテゴリとなること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {
          server: ['Vercel'],
          'x-vercel-id': ['iad1::iad1::iad1'],
        },
        cookies: [],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const vercel = results.find((r) => r.technology === 'Vercel');
      expect(vercel).toBeDefined();
      expect(vercel?.category).toBe('hosting-cloud');
      expect(vercel?.detectionMethod).toBe('direct');
    });

    it('Netlify を X-Nf-Request-Id ヘッダーから検出できること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {
          'x-nf-request-id': ['01J8ABC...'],
        },
        cookies: [],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const netlify = results.find((r) => r.technology === 'Netlify');
      expect(netlify).toBeDefined();
      expect(netlify?.category).toBe('hosting-cloud');
    });

    it('Azure App Service を ARRAffinity Cookie から検出できること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {},
        cookies: [{ name: 'ARRAffinity', value: 'affinity123' }],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const azure = results.find((r) => r.technology === 'Azure App Service');
      expect(azure).toBeDefined();
      expect(azure?.category).toBe('hosting-cloud');
    });

    it('Google Analytics / GTM をスクリプトURLから検出し、analytics-tracking カテゴリとなること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://www.googletagmanager.com/gtm.js?id=GTM-XXXX',
          'https://www.google-analytics.com/analytics.js',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const gtm = results.find((r) => r.technology === 'Google Tag Manager');
      expect(gtm).toBeDefined();
      expect(gtm?.category).toBe('analytics-tracking');

      const ga = results.find((r) => r.technology === 'Google Analytics');
      expect(ga).toBeDefined();
      expect(ga?.category).toBe('analytics-tracking');
    });

    it('Sentry および reCAPTCHA を security-service カテゴリとして検出できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://browser.sentry-cdn.com/7.x/bundle.min.js',
          'https://www.google.com/recaptcha/api.js',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const sentry = results.find((r) => r.technology === 'Sentry');
      expect(sentry).toBeDefined();
      expect(sentry?.category).toBe('security-service');

      const recaptcha = results.find((r) => r.technology === 'reCAPTCHA');
      expect(recaptcha).toBeDefined();
      expect(recaptcha?.category).toBe('security-service');
    });
  });

  // --- IMP-17: Implication Engine 高度化テスト ---
  describe('IMP-17: Implication Engine 高度化 (直接検出と連動推定の厳密分離)', () => {
    it('Next.js のヘッダーのみ検出された場合、React は連動推定 (inferred) かつ possible (confirmedではない) となること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {
          'x-powered-by': ['Next.js'],
        },
        cookies: [],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const nextjs = results.find((r) => r.technology === 'Next.js');
      expect(nextjs?.detectionMethod).toBe('direct');
      expect(nextjs?.runtimeStatus).toBe('confirmed');

      const react = results.find((r) => r.technology === 'React');
      expect(react?.detectionMethod).toBe('inferred');
      expect(react?.implicationType).toBe('framework-dependency');
      expect(react?.runtimeStatus).toBe('possible');
      expect(react?.runtimeStatus).not.toBe('confirmed');
      expect(react?.inferredFrom).toBe('Next.js');

      // SSRヘッダーが存在するため Node.js も連動検出
      const node = results.find((r) => r.technology === 'Node.js');
      expect(node).toBeDefined();
      expect(node?.detectionMethod).toBe('inferred');
      expect(node?.runtimeStatus).toBe('unknown');
    });

    it('[data-reactroot] などの直接DOM観測がある場合、React は直接検出 (direct) かつ confirmed となること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        domMarkers: ['[data-reactroot]', 'data-reactroot'],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const react = results.find((r) => r.technology === 'React');
      expect(react).toBeDefined();
      expect(react?.detectionMethod).toBe('direct');
      expect(react?.runtimeStatus).toBe('confirmed');
    });

    it('静的配信 (SSG) のNext.js (SSRヘッダーなし) では、Node.js は連動検出されないこと', () => {
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

      const react = results.find((r) => r.technology === 'React');
      expect(react).toBeDefined();
      expect(react?.runtimeStatus).toBe('possible');

      // SSRヘッダーがない静的HTMLのため、Node.js は連動されないこと
      const node = results.find((r) => r.technology === 'Node.js');
      expect(node).toBeUndefined();
    });
  });

  // --- レビュー指摘に基づく精度検証・エッジケーステスト ---
  describe('レビュー指摘に基づく精度検証・エッジケーステスト', () => {
    it('Apache-Coyote を Apache と誤判定しないこと', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {
          server: ['Apache-Coyote/1.1'],
        },
        cookies: [],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const apache = results.find((r) => r.technology === 'Apache');
      expect(apache).toBeUndefined();
    });

    it('Cookie AWSALB / AWSALBCORS で aws-alb を検出できること', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {},
        cookies: [
          {
            name: 'AWSALB',
            domain: 'example.com',
            path: '/',
            secure: true,
            httpOnly: false,
            sameSite: 'lax',
          },
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const alb = results.find((r) => r.technology === 'AWS Application Load Balancer');
      expect(alb).toBeDefined();
    });

    it('class="loading-spinner" だけのHTMLで AngularJS を検出しないこと', () => {
      const dom: DomSignals = {
        ...emptyDom,
        htmlSnippets: ['loading-spinner', 'badge-warning-icon'],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const angular = results.find((r) => r.technology === 'Angular');
      expect(angular).toBeUndefined();
    });

    it('AngularJS 1.8.2 を検出した場合に EOL (2022年1月公式終了) と判定されること', () => {
      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        runtimeVersions: { angularjs: '1.8.2' },
      });

      const angularjs = results.find((r) => r.technology === 'AngularJS');
      expect(angularjs).toBeDefined();
      expect(angularjs?.version).toBe('1.8.2');
      expect(angularjs?.supportStatus).toBe('EOL');
      expect(angularjs?.eolDate).toMatch(/^2022-01/);
    });

    it('コードブロック <pre><code> などのHTMLスニペットに含まれる ng-app で AngularJS を誤検知しないこと', () => {
      const dom: DomSignals = {
        ...emptyDom,
        htmlSnippets: [
          '<pre><code><div ng-app="myApp">...</div></code></pre>',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const angularjs = results.find((r) => r.technology === 'AngularJS');
      expect(angularjs).toBeUndefined();
    });

    it('meta generator がなくても、wp-embed.min.js?ver=6.4.2 から WordPress 6.4.2 を特定できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://example.com/wp-includes/js/wp-embed.min.js?ver=6.4.2',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const wp = results.find((r) => r.technology === 'WordPress');
      expect(wp).toBeDefined();
      expect(wp?.version).toBe('6.4.2');
      expect(wp?.confidence).toBeGreaterThanOrEqual(90);
    });

    it('style.min.css?ver=6.4.2 からも WordPress 6.4.2 を特定できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        linkUrls: [
          {
            rel: 'stylesheet',
            href: 'https://example.com/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2',
          },
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const wp = results.find((r) => r.technology === 'WordPress');
      expect(wp).toBeDefined();
      expect(wp?.version).toBe('6.4.2');
      expect(wp?.confidence).toBeGreaterThanOrEqual(90);
    });

    it('wp-includes/js/jquery/jquery.min.js?ver=3.7.1 単体では WordPress 3.7.1 と誤検知しないこと', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const wp = results.find((r) => r.technology === 'WordPress');
      // 一般の/wp-includes/スクリプトによりWordPress存在自体は検知されるが、バージョンは3.7.1と特定されない
      expect(wp).toBeDefined();
      expect(wp?.version).toBeNull();
    });

    it('CDN URL (unpkg.com/react@18.2.0/...) から React 18.2.0 を特定できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://unpkg.com/react@18.2.0/umd/react.production.min.js',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const react = results.find((r) => r.technology === 'React');
      expect(react).toBeDefined();
      expect(react?.version).toBe('18.2.0');
    });

    it('CDN URL (cdn.jsdelivr.net/npm/vue@3.3.4/...) から Vue.js 3.3.4 を特定できること', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://cdn.jsdelivr.net/npm/vue@3.3.4/dist/vue.global.prod.js',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const vue = results.find((r) => r.technology === 'Vue.js');
      expect(vue).toBeDefined();
      expect(vue?.version).toBe('3.3.4');
    });

    it('Preact CDN URL (preact@10.19.0) から React 10.19.0 と誤検知されないこと', () => {
      const dom: DomSignals = {
        ...emptyDom,
        scriptUrls: [
          'https://cdn.jsdelivr.net/npm/preact@10.19.0/dist/preact.min.js',
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
      });

      const react = results.find((r) => r.technology === 'React');
      expect(react).toBeUndefined();
    });

    it('Railsの_myapp_sessionやCodeIgniterのci_session単独ではLaravelと誤判定されないこと', () => {
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {},
        cookies: [
          { name: '_myapp_session', value: 'rails-session-token' },
          { name: 'ci_session', value: 'ci-session-token' },
          { name: '_gitlab_session', value: 'gitlab-session-token' },
        ],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network,
      });

      const laravel = results.find((r) => r.technology === 'Laravel');
      expect(laravel).toBeUndefined();
    });

    it('myapp_session単独（35%）では閾値未満のためLaravelは検出されず、XSRF-TOKEN（35%）と揃った場合のみLaravelが検出（70%）されること', () => {
      // 1. myapp_session 単独
      const singleResults = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network: {
          url: 'https://example.com/',
          responseHeaders: {},
          cookies: [{ name: 'myapp_session', value: 'laravel-custom-session' }],
        },
      });
      expect(singleResults.find((r) => r.technology === 'Laravel')).toBeUndefined();

      // 2. myapp_session + XSRF-TOKEN の両方が存在
      const combinedResults = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network: {
          url: 'https://example.com/',
          responseHeaders: {},
          cookies: [
            { name: 'myapp_session', value: 'laravel-custom-session' },
            { name: 'XSRF-TOKEN', value: 'laravel-xsrf-token' },
          ],
        },
      });
      const laravel = combinedResults.find((r) => r.technology === 'Laravel');
      expect(laravel).toBeDefined();
      expect(laravel?.confidence).toBe(70);
    });

    it('Next.js静的サイトでx-vercel-idのみ付与されている場合、Node.jsは連動推論されないこと', () => {
      const dom: DomSignals = {
        ...emptyDom,
        domMarkers: ['script#__NEXT_DATA__'],
      };
      const network: NetworkSignals = {
        url: 'https://example.com/',
        responseHeaders: {
          'x-vercel-id': ['iad1::iad1::iad1-12345'],
          'server': ['Vercel'],
        },
        cookies: [],
      };

      const results = engine.detect({
        url: 'https://example.com/',
        dom,
        network,
      });

      const nextjs = results.find((r) => r.technology === 'Next.js');
      expect(nextjs).toBeDefined();

      // 静的ホスティング（x-vercel-idのみ）のためNode.jsは連動推論されないこと
      const node = results.find((r) => r.technology === 'Node.js');
      expect(node).toBeUndefined();
    });

    it('__reactContainer$または__vue_app__がdomMarkersに存在する場合、直接検出かつconfirmedになること', () => {
      const domReact: DomSignals = {
        ...emptyDom,
        domMarkers: ['__reactContainer$'],
      };
      const resultsReact = engine.detect({
        url: 'https://example.com/',
        dom: domReact,
      });
      const react = resultsReact.find((r) => r.technology === 'React');
      expect(react).toBeDefined();
      expect(react?.runtimeStatus).toBe('confirmed');

      const domVue: DomSignals = {
        ...emptyDom,
        domMarkers: ['__vue_app__'],
      };
      const resultsVue = engine.detect({
        url: 'https://example.com/',
        dom: domVue,
      });
      const vue = resultsVue.find((r) => r.technology === 'Vue.js');
      expect(vue).toBeDefined();
      expect(vue?.runtimeStatus).toBe('confirmed');
    });

    it('/laravel-positive の Cookie (laravel_session + XSRF-TOKEN) から Laravel と PHP が検出され Node.js は閾値未満で除外されること', () => {
      const results = engine.detect({
        url: 'http://localhost:3000/laravel-positive',
        dom: emptyDom,
        network: {
          url: 'http://localhost:3000/laravel-positive',
          responseHeaders: {},
          cookies: [
            { name: 'XSRF-TOKEN', value: 'sample_laravel_csrf_token_value' },
            { name: 'laravel_session', value: 'sample_laravel_session_encrypted_value' },
          ],
        },
      });

      // Laravel (85%) が直接検出されていること
      const laravel = results.find((r) => r.technology === 'Laravel');
      expect(laravel).toBeDefined();
      expect(laravel?.confidence).toBe(85);
      expect(laravel?.detectionMethod).toBe('direct');

      // PHP (80%) が連動推論されていること
      const php = results.find((r) => r.technology === 'PHP');
      expect(php).toBeDefined();
      expect(php?.confidence).toBe(80);
      expect(php?.detectionMethod).toBe('inferred');

      // Node.js は XSRF-TOKEN 単独 (35点) のため閾値50%未満となり検出されないこと (否定検証)
      const nodejs = results.find((r) => r.technology === 'Node.js');
      expect(nodejs).toBeUndefined();

      // Java も同様に XSRF-TOKEN 単独 (35点) のため検出されないこと
      const java = results.find((r) => r.technology === 'Java');
      expect(java).toBeUndefined();
    });
  });
});


