/**
 * Web Technology & Security Inspector
 * 技術検出エンジンの単体テスト (tests/detection.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../src/detection/engine';
import { ALL_TECHNOLOGY_RULES } from '../src/detection/rules';
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

  describe('ディストリビューション版バックポート考慮 (SPEC-02 / T04)', () => {
    it('nginx/1.18.0 (Ubuntu) は distroHint: "Ubuntu" かつ advisoryMatchStatus: "Needs Review" となること', () => {
      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network: {
          url: 'https://example.com/',
          responseHeaders: {
            server: ['nginx/1.18.0 (Ubuntu)'],
          },
          cookies: [],
        },
      });

      const nginx = results.find((r) => r.technology === 'Nginx');
      expect(nginx).toBeDefined();
      expect(nginx?.version).toBe('1.18.0');
      expect(nginx?.distroHint).toBe('Ubuntu');
      expect(nginx?.advisoryMatchStatus).toBe('Needs Review');
      expect(nginx?.offlineMatchStatus).toBe('Unknown Version');
    });

    it('Apache/2.4.58 (Unix) は Unix をディストリ扱いせず従来どおり照合されること', () => {
      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network: {
          url: 'https://example.com/',
          responseHeaders: {
            server: ['Apache/2.4.58 (Unix)'],
          },
          cookies: [],
        },
      });

      const apache = results.find((r) => r.technology === 'Apache');
      expect(apache).toBeDefined();
      expect(apache?.version).toBe('2.4.58');
      expect(apache?.distroHint).toBeUndefined();
      expect(apache?.advisoryMatchStatus).not.toBe('Needs Review');
    });

    it('X-Powered-By: PHP/8.1.2-1ubuntu2.14 は distroHint: "Ubuntu" かつ Needs Review となること', () => {
      const results = engine.detect({
        url: 'https://example.com/',
        dom: emptyDom,
        network: {
          url: 'https://example.com/',
          responseHeaders: {
            'x-powered-by': ['PHP/8.1.2-1ubuntu2.14'],
          },
          cookies: [],
        },
      });

      const php = results.find((r) => r.technology === 'PHP');
      expect(php).toBeDefined();
      expect(php?.version).toBe('8.1.2');
      expect(php?.distroHint).toBe('Ubuntu');
      expect(php?.advisoryMatchStatus).toBe('Needs Review');
      expect(php?.offlineMatchStatus).toBe('Unknown Version');
    });
  });

  describe('誤検知の抑制と検出精度 (SPEC-09 / T05)', () => {
    describe('Tailwind CSS の陽性・陰性判定', () => {
      it.each([
        ['d-flex justify-content-between align-items-center'],
        ['container-fluid py-4'],
        ['col-md-6 mb-3 text-muted'],
        ['btn btn-primary px-4'],
      ])('Bootstrap クラス "%s" から Tailwind CSS を検出しないこと', (snippet) => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: { ...emptyDom, htmlSnippets: [snippet] },
        });
        expect(results.some((r) => r.technology === 'Tailwind CSS')).toBe(false);
      });

      it.each([
        ['flex items-center justify-between bg-gray-100 px-4 md:px-8'],
        ['text-slate-700 hover:text-slate-900'],
      ])('Tailwind 固有クラス "%s" から Tailwind CSS を検出できること', (snippet) => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: { ...emptyDom, htmlSnippets: [snippet] },
        });
        const tailwind = results.find((r) => r.technology === 'Tailwind CSS');
        expect(tailwind).toBeDefined();
        expect(tailwind?.confidence).toBeGreaterThanOrEqual(50);
      });
    });

    describe('Font Awesome の陽性・陰性判定', () => {
      it('テーマの small.css / all.css から Font Awesome を検出しないこと', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            linkUrls: [
              { rel: 'stylesheet', href: '/themes/t/css/small.css' },
              { rel: 'stylesheet', href: '/themes/t/css/all.css' },
            ],
          },
        });
        expect(results.some((r) => r.technology === 'Font Awesome')).toBe(false);
      });

      it('cdnjs の CSS URL から Font Awesome を検出できること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            linkUrls: [
              { rel: 'stylesheet', href: 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css' },
            ],
          },
        });
        const fa = results.find((r) => r.technology === 'Font Awesome');
        expect(fa).toBeDefined();
        expect(fa?.confidence).toBeGreaterThanOrEqual(80);
      });

      it('kit.fontawesome.com の スクリプト URL から Font Awesome を検出できること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://kit.fontawesome.com/abc123.js'],
          },
        });
        const fa = results.find((r) => r.technology === 'Font Awesome');
        expect(fa).toBeDefined();
        expect(fa?.confidence).toBeGreaterThanOrEqual(80);
      });
    });

    describe('Chart.js / D3.js の誤検知防止', () => {
      it('orgchart.js / md3.js から Chart.js / D3.js を検出しないこと', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['/js/orgchart.js', '/static/md3.js'],
          },
        });
        expect(results.some((r) => r.technology === 'Chart.js')).toBe(false);
        expect(results.some((r) => r.technology === 'D3.js')).toBe(false);
      });

      it('正規の D3.js スクリプトから D3.js を検出できること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://d3js.org/d3.v7.min.js'],
          },
        });
        expect(results.some((r) => r.technology === 'D3.js')).toBe(true);
      });
    });

    describe('Ruby on Rails の Passenger 単独評価の抑制', () => {
      it('X-Powered-By: Phusion Passenger 単独で Ruby on Rails を高確信度にしないこと', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: emptyDom,
          network: {
            url: 'https://example.com/',
            responseHeaders: {
              'x-powered-by': ['Phusion Passenger(R) 6.0.17'],
            },
            cookies: [],
          },
        });
        const rails = results.find((r) => r.technology === 'Ruby on Rails');
        expect(rails?.confidenceLevel ?? 'low').not.toBe('high');
      });
    });

    describe('DOC-02: Lodash / Moment.js のスクリプトURL検出 (T07)', () => {
      it('cdnjs のスクリプトURLから Lodash およびバージョンを検出できること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js'],
          },
        });
        const lodash = results.find((r) => r.technology === 'Lodash');
        expect(lodash).toBeDefined();
        expect(lodash?.version).toBe('4.17.21');
        expect(lodash?.category).toBe('js-css-library');
        expect(lodash?.confidence).toBeGreaterThanOrEqual(80);
      });

      it('jsdelivr のスクリプトURLから Lodash およびバージョンを検出できること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js'],
          },
        });
        const lodash = results.find((r) => r.technology === 'Lodash');
        expect(lodash).toBeDefined();
        expect(lodash?.version).toBe('4.17.21');
      });

      it('ローカルスクリプトURLから Lodash を検出できること（バージョンなし）', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['/assets/js/lodash.min.js', '/assets/js/lodash.core.js'],
          },
        });
        const lodash = results.find((r) => r.technology === 'Lodash');
        expect(lodash).toBeDefined();
        expect(lodash?.version).toBeNull();
      });

      it('cdnjs のスクリプトURLから Moment.js およびバージョンを検出できること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js'],
          },
        });
        const moment = results.find((r) => r.technology === 'Moment.js');
        expect(moment).toBeDefined();
        expect(moment?.version).toBe('2.29.4');
        expect(moment?.category).toBe('js-css-library');
        expect(moment?.confidence).toBeGreaterThanOrEqual(80);
      });

      it('jsdelivr のスクリプトURLから Moment.js およびバージョンを検出できること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://cdn.jsdelivr.net/npm/moment@2.29.4/moment.min.js'],
          },
        });
        const moment = results.find((r) => r.technology === 'Moment.js');
        expect(moment).toBeDefined();
        expect(moment?.version).toBe('2.29.4');
      });

      it('ローカルスクリプトURLから Moment.js を検出できること（バージョンなし）', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['/static/js/moment-with-locales.min.js'],
          },
        });
        const moment = results.find((r) => r.technology === 'Moment.js');
        expect(moment).toBeDefined();
        expect(moment?.version).toBeNull();
      });

      it('類似名称の無関係なスクリプトから Lodash / Moment.js を誤検出しないこと', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: ['/js/my-lodash.js', '/static/momentary.js'],
          },
        });
        expect(results.some((r) => r.technology === 'Lodash')).toBe(false);
        expect(results.some((r) => r.technology === 'Moment.js')).toBe(false);
      });
    });

    describe('SPEC-10: 同一ライブラリの複数バージョン照合 (T08)', () => {
      it('異なるバージョンの jQuery が同居する場合、instances に昇順で保持され、version に最も古いバージョンが設定され、全インスタンスが脆弱性・EOL照合されること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: [
              'https://example.com/js/jquery-3.7.1.min.js',
              'https://example.com/js/jquery-1.12.4.min.js',
            ],
          },
          runtimeVersions: { jquery: '3.7.1' },
        });

        const jq = results.find((r) => r.technology === 'jQuery');
        expect(jq).toBeDefined();
        // 古い方（リスクが高い方）が version に入る
        expect(jq?.version).toBe('1.12.4');
        expect(jq?.instances).toBeDefined();
        expect(jq?.instances?.length).toBe(2);
        // バージョン昇順で並ぶ
        expect(jq?.instances?.[0].version).toBe('1.12.4');
        expect(jq?.instances?.[1].version).toBe('3.7.1');

        // 1.12.4 は EOL かつ CVE-2020-11022 が該当する
        expect(jq?.instances?.[0].eol.status).toBe('EOL');
        expect(jq?.instances?.[0].supportStatus).toBe('EOL');
        expect(jq?.instances?.[0].advisories.some((a) => a.id === 'CVE-2020-11022')).toBe(true);

        // 3.7.1 は 1.12.4 向けの CVE-2020-11022 に該当せず、同一バージョンエビデンス（script + runtime）が1インスタンスに集約される
        expect(jq?.instances?.[1].advisories.some((a) => a.id === 'CVE-2020-11022')).toBe(false);
        expect(jq?.instances?.[1].evidence.length).toBeGreaterThanOrEqual(2);

        // 技術全体の advisories にも 1.12.4 の CVE が集約されている
        expect(jq?.advisories?.some((a) => a.id === 'CVE-2020-11022')).toBe(true);
      });

      it('同一バージョンの複数エビデンスは 1 つのインスタンスにまとめられ、インスタンス数は最大 5 件に制限されること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            scriptUrls: [
              'https://cdn.example.com/jquery-3.7.1.min.js',
              'https://sub.example.com/jquery-3.7.1.js',
              'https://cdn.example.com/jquery-3.6.0.min.js',
              'https://cdn.example.com/jquery-3.5.1.min.js',
              'https://cdn.example.com/jquery-3.4.1.min.js',
              'https://cdn.example.com/jquery-2.2.4.min.js',
              'https://cdn.example.com/jquery-1.12.4.min.js',
            ],
          },
        });

        const jq = results.find((r) => r.technology === 'jQuery');
        expect(jq).toBeDefined();
        // 最大 5 インスタンスに制限され、古い順から 5 件残る
        expect(jq?.instances?.length).toBe(5);
        expect(jq?.instances?.map((i) => i.version)).toEqual([
          '1.12.4',
          '2.2.4',
          '3.4.1',
          '3.5.1',
          '3.6.0',
        ]);
        expect(jq?.version).toBe('1.12.4');
      });
    });

    describe('T09: 連動推論の確信度と候補ラベル整合 (SPEC-14, DOC-11)', () => {
      it('SPEC-14: Material UI（確信度 85）から係数 0.9 で推論された React の確信度が Math.floor(85 * 0.9) = 76 となること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            domMarkers: ["[class*='MuiButton-']"],
          },
        });

        const mui = results.find((r) => r.technology === 'Material UI');
        expect(mui).toBeDefined();
        expect(mui?.confidence).toBe(85);
        expect(mui?.detectionMethod).toBe('direct');

        const react = results.find((r) => r.technology === 'React');
        expect(react).toBeDefined();
        expect(react?.confidence).toBe(76);
        expect(react?.confidenceLevel).toBe('medium');
        expect(react?.detectionMethod).toBe('inferred');
        expect(react?.runtimeStatus).toBe('possible');
        expect(react?.inferredFrom).toBe('Material UI');
      });

      it('DOC-11: バックエンド候補が 2 つだけ一致したとき、その 2 つだけが候補ラベルと candidateTechnologies に出ること', () => {
        // Node.js ルールを除いたルールセット（Java と Laravel の 2 候補のみが XSRF-TOKEN に一致）
        const twoCandidateRules = ALL_TECHNOLOGY_RULES.filter((r) => r.id !== 'nodejs');
        const customEngine = new DetectionEngine(twoCandidateRules);

        const results = customEngine.detect({
          url: 'https://example.com/',
          dom: emptyDom,
          network: {
            url: 'https://example.com/',
            responseHeaders: {},
            cookies: [{ name: 'XSRF-TOKEN', value: 'token-abc' }],
          },
        });

        const candidate = results.find((r) => r.isCandidateGroup);
        expect(candidate).toBeDefined();
        expect(candidate?.technology).toBe('Java / Laravel (候補)');
        expect(candidate?.candidateTechnologies).toEqual([
          'Java (Spring Boot)',
          'Laravel (PHP)',
        ]);
        expect(candidate?.evidence[0]?.detail).toContain('Java / Laravel');
        expect(candidate?.evidence[0]?.detail).not.toContain('Node.js');
      });
    });

    describe('T11: Cookie 名の重複除去 (IMPL-12)', () => {
      it('IMPL-12: document.cookie と cookies API の 2 経路から同じ名前の Cookie が来ても、根拠の表示は 1 件になること', () => {
        const results = engine.detect({
          url: 'https://example.com/',
          dom: {
            ...emptyDom,
            cookiesFromDocument: ['laravel_session', 'PHPSESSID'],
          },
          network: {
            url: 'https://example.com/',
            responseHeaders: {},
            cookies: [
              { name: 'laravel_session', value: 'dummy1' },
              { name: 'PHPSESSID', value: 'dummy2' },
            ],
          },
        });

        const laravel = results.find((r) => r.technology === 'Laravel');
        expect(laravel).toBeDefined();
        const laravelCookieEvidences =
          laravel?.evidence.filter((e) => e.type === 'cookie-name' && e.name === 'laravel_session') ||
          [];
        expect(laravelCookieEvidences).toHaveLength(1);

        const php = results.find((r) => r.technology === 'PHP');
        expect(php).toBeDefined();
        const phpCookieEvidences =
          php?.evidence.filter((e) => e.type === 'cookie-name' && e.name === 'PHPSESSID') || [];
        expect(phpCookieEvidences).toHaveLength(1);
      });
    });

    describe('v1.7.1 T06 (N2): Angular / AngularJS / Drupal の検出ルール強化と陽性・否定コントロール', () => {
      it('Angular: ビルドメタデータ付き ng-version="22.2.5+sha-d881689" や _nghost- / _ngcontent- / [ng-server-context] で検出され、無関係な属性や AngularJS [ng-app] では誤検出しないこと', () => {
        // 陽性 1: ビルドメタデータ付き ng-version
        const resVersion = engine.detect({
          url: 'https://angular-app.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ['ng-version="22.2.5+sha-d881689"'],
          },
        });
        const ngWithVer = resVersion.find((r) => r.technology === 'Angular');
        expect(ngWithVer).toBeDefined();
        expect(ngWithVer?.version).toBe('22.2.5');
        expect(ngWithVer?.confidence).toBe(95);

        // 陽性 2: ViewEncapsulation / SSR 属性 (_nghost-, _ngcontent-, [ng-server-context])
        const resAlt = engine.detect({
          url: 'https://angular-ssr.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ['_nghost-', '[ng-server-context]'],
          },
        });
        const ngAlt = resAlt.find((r) => r.technology === 'Angular');
        expect(ngAlt).toBeDefined();
        expect(ngAlt?.confidence).toBe(85);

        // 陰性（否定コントロール）: AngularJS の [ng-app] や類似文字列では Angular (v2+) は検出されないこと
        const resNeg = engine.detect({
          url: 'https://non-angular.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ['[ng-app]', 'data-v-'],
            htmlSnippets: ['ng-loading-indicator custom-nghost'],
          },
        });
        expect(resNeg.find((r) => r.technology === 'Angular')).toBeUndefined();
      });

      it('AngularJS: [data-ng-app] / [data-ng-controller] / [ng-model] / .ng-scope / .ng-binding で検出され、loading-spinner や ng-loading では誤検出しないこと', () => {
        // 陽性 1: HTML5 準拠の [data-ng-app]
        const resDataNg = engine.detect({
          url: 'https://angularjs-app.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ['[data-ng-app]', '[data-ng-controller]'],
          },
        });
        expect(resDataNg.find((r) => r.technology === 'AngularJS')).toBeDefined();

        // 陽性 2: ランタイムが付与する .ng-scope / .ng-binding
        const resScope = engine.detect({
          url: 'https://angularjs-runtime.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ['.ng-scope', '.ng-binding'],
          },
        });
        expect(resScope.find((r) => r.technology === 'AngularJS')).toBeDefined();

        // 陰性（否定コントロール）: スピナー等のクラス名や Angular v2+ の ng-version では AngularJS が検出されないこと
        const resNeg = engine.detect({
          url: 'https://non-angularjs.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ['ng-version="22.2.5+sha-d881689"', '_nghost-'],
            htmlSnippets: ['loading-spinner ng-loading-indicator'],
          },
        });
        expect(resNeg.find((r) => r.technology === 'AngularJS')).toBeUndefined();
      });

      it('Drupal: x-drupal-dynamic-cache ヘッダー、data-drupal-* DOM 印、/core/misc/drupal.js、/core/themes/ リンクで検出され、一般的な /core/app.js や Fastly ページでは誤検出しないこと', () => {
        // 陽性 1: x-drupal-dynamic-cache ヘッダー
        const resHeader = engine.detect({
          url: 'https://drupal-header.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://drupal-header.example.test/',
            responseHeaders: {
              'x-drupal-dynamic-cache': ['MISS'],
            },
            cookies: [],
          },
        });
        expect(resHeader.find((r) => r.technology === 'Drupal')).toBeDefined();

        // 陽性 2: data-drupal-* DOM 印
        const resDom = engine.detect({
          url: 'https://drupal-dom.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ['data-drupal-', '[data-drupal-selector]'],
          },
        });
        expect(resDom.find((r) => r.technology === 'Drupal')).toBeDefined();

        // 陽性 3: Drupal コアスクリプトとテーマ CSS リンク
        const resAssets = engine.detect({
          url: 'https://drupal-assets.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://drupal-assets.example.test/core/misc/drupal.js?v=10.2.4'],
            linkUrls: [
              {
                rel: 'stylesheet',
                href: 'https://drupal-assets.example.test/core/themes/olivero/css/base/base.css',
              },
            ],
          },
        });
        expect(resAssets.find((r) => r.technology === 'Drupal')).toBeDefined();

        // 陰性（否定コントロール）: 一般的な /core/app.js や /sites/main.css、Fastly Challenge スクリプトでは Drupal と誤検出しないこと
        const resNeg = engine.detect({
          url: 'https://non-drupal.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: [
              'https://non-drupal.example.test/core/app.js',
              'https://non-drupal.example.test/_fs-ch-1T1wmsGaOgGaSxcX/script.js?reload=true',
            ],
            linkUrls: [
              {
                rel: 'stylesheet',
                href: 'https://non-drupal.example.test/sites/style.css',
              },
            ],
          },
        });
        expect(resNeg.find((r) => r.technology === 'Drupal')).toBeUndefined();
      });
    });

    describe('v1.7.1 T08: サーバー・基盤・言語の検出 (指摘 4, D, G, N6, N9)', () => {
      it('N6: x-vercel-id: hnd1::29cw8-1793972072729-626cb73fc75c を含む応答で distroHint が付かないこと', () => {
        const results = engine.detect({
          url: 'https://vercel-app.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://vercel-app.example.test/',
            responseHeaders: {
              server: ['Vercel'],
              'x-vercel-id': ['hnd1::29cw8-1793972072729-626cb73fc75c'],
            },
            cookies: [],
          },
        });

        const vercel = results.find((r) => r.technology === 'Vercel');
        expect(vercel).toBeDefined();
        expect(vercel?.distroHint).toBeUndefined();
        for (const tech of results) {
          expect(tech.distroHint).toBeUndefined();
        }
      });

      it('N6: Apache/2.4.41 (Ubuntu)・nginx/1.10.3 (Ubuntu)・Apache/2.4.6 (CentOS)・PHP/8.1.2-1ubuntu2.14 が従来どおり動き、fc は .fc\\d{2}\\b のときだけ Fedora と判定されること', () => {
        const cases: Array<{
          headers: Record<string, string[]>;
          tech: string;
          expectedVer: string;
          expectedHint: string;
        }> = [
          {
            headers: { server: ['Apache/2.4.41 (Ubuntu)'] },
            tech: 'Apache',
            expectedVer: '2.4.41',
            expectedHint: 'Ubuntu',
          },
          {
            headers: { server: ['nginx/1.10.3 (Ubuntu)'] },
            tech: 'Nginx',
            expectedVer: '1.10.3',
            expectedHint: 'Ubuntu',
          },
          {
            headers: { server: ['Apache/2.4.6 (CentOS)'] },
            tech: 'Apache',
            expectedVer: '2.4.6',
            expectedHint: 'CentOS',
          },
          {
            headers: { 'x-powered-by': ['PHP/8.1.2-1ubuntu2.14'] },
            tech: 'PHP',
            expectedVer: '8.1.2',
            expectedHint: 'Ubuntu',
          },
          {
            headers: { 'x-powered-by': ['PHP/8.2.10-1.fc38'] },
            tech: 'PHP',
            expectedVer: '8.2.10',
            expectedHint: 'Fedora',
          },
        ];

        for (const c of cases) {
          const res = engine.detect({
            url: 'https://linux-pkg.example.test/',
            dom: emptyDom,
            network: {
              url: 'https://linux-pkg.example.test/',
              responseHeaders: c.headers,
              cookies: [],
            },
          });
          const found = res.find((r) => r.technology === c.tech);
          expect(found).toBeDefined();
          expect(found?.version).toBe(c.expectedVer);
          expect(found?.distroHint).toBe(c.expectedHint);
        }

        // 陰性（否定コントロール）: バージョンが取れないヘッダーや .fc\d{2}\b でない fc 文字列では distroHint が付かない
        const negRes = engine.detect({
          url: 'https://no-distro.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://no-distro.example.test/',
            responseHeaders: {
              server: ['Apache'],
              'x-powered-by': ['PHP/8.2.10-fc38'],
            },
            cookies: [],
          },
        });
        expect(negRes.find((r) => r.technology === 'Apache')?.distroHint).toBeUndefined();
        expect(negRes.find((r) => r.technology === 'PHP')?.distroHint).toBeUndefined();
      });

      it('N9: Server: Apache-Coyote/1.1 および Apache Tomcat から Tomcat と Java（推論）が検出され、Apache は検出されないこと', () => {
        const coyoteResults = engine.detect({
          url: 'https://tomcat-coyote.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://tomcat-coyote.example.test/',
            responseHeaders: {
              server: ['Apache-Coyote/1.1'],
            },
            cookies: [],
          },
        });

        const tomcat = coyoteResults.find((r) => r.technology === 'Tomcat');
        expect(tomcat).toBeDefined();
        expect(tomcat?.category).toBe('web-server');
        expect(tomcat?.detectionMethod).toBe('direct');
        expect(tomcat?.version).toBeNull();

        const java = coyoteResults.find((r) => r.technology === 'Java');
        expect(java).toBeDefined();
        expect(java?.detectionMethod).toBe('inferred');
        expect(java?.inferredFrom).toBe('Tomcat');
        expect(java?.runtimeStatus).toBe('unknown');

        expect(coyoteResults.find((r) => r.technology === 'Apache')).toBeUndefined();

        // Apache Tomcat/9.0.65 の陽性検証
        const tomcatVerResults = engine.detect({
          url: 'https://tomcat-ver.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://tomcat-ver.example.test/',
            responseHeaders: {
              server: ['Apache Tomcat/9.0.65'],
            },
            cookies: [],
          },
        });
        const tomcatWithVer = tomcatVerResults.find((r) => r.technology === 'Tomcat');
        expect(tomcatWithVer).toBeDefined();
        expect(tomcatWithVer?.version).toBe('9.0.65');
        expect(tomcatVerResults.find((r) => r.technology === 'Java')).toBeDefined();
        expect(tomcatVerResults.find((r) => r.technology === 'Apache')).toBeUndefined();
      });

      it('旧 ASP と ASP.NET (指摘 D): スナップショット testasp・testaspnet でそれぞれ Classic ASP・ASP.NET（CLR 2.0 + EOL）になること', () => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const fs = require('node:fs');
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const path = require('node:path');
        const snapDir = path.resolve(__dirname, 'fixtures', 'snapshots');

        const testAspSnap = JSON.parse(
          fs.readFileSync(path.join(snapDir, 'testasp.vulnweb.com.json'), 'utf-8')
        );
        const testAspResults = engine.detect({
          url: testAspSnap.finalUrl || testAspSnap.url,
          dom: emptyDom,
          network: {
            url: testAspSnap.finalUrl || testAspSnap.url,
            responseHeaders: testAspSnap.responseHeaders,
            cookies: testAspSnap.cookies,
          },
        });

        const classicAsp = testAspResults.find((r) => r.technology === 'Classic ASP');
        expect(classicAsp).toBeDefined();
        expect(classicAsp?.category).toBe('framework');
        expect(testAspResults.find((r) => r.technology === 'ASP.NET')).toBeUndefined();

        const testAspNetSnap = JSON.parse(
          fs.readFileSync(path.join(snapDir, 'testaspnet.vulnweb.com.json'), 'utf-8')
        );
        const testAspNetResults = engine.detect({
          url: testAspNetSnap.finalUrl || testAspNetSnap.url,
          dom: emptyDom,
          network: {
            url: testAspNetSnap.finalUrl || testAspNetSnap.url,
            responseHeaders: testAspNetSnap.responseHeaders,
            cookies: testAspNetSnap.cookies,
          },
        });

        const aspnet = testAspNetResults.find((r) => r.technology === 'ASP.NET');
        expect(aspnet).toBeDefined();
        expect(aspnet?.category).toBe('framework');
        expect(aspnet?.version).toBe('.NET Framework 2.0〜3.5（CLR 2.0.50727）');
        expect(aspnet?.supportStatus).toBe('EOL');
        expect(testAspNetResults.find((r) => r.technology === 'Classic ASP')).toBeUndefined();

        // CLR 4.0.30319 の表示形式確認
        const clr4Results = engine.detect({
          url: 'https://aspnet4.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://aspnet4.example.test/',
            responseHeaders: {
              'x-aspnet-version': ['4.0.30319'],
            },
            cookies: [],
          },
        });
        const aspnet4 = clr4Results.find((r) => r.technology === 'ASP.NET');
        expect(aspnet4?.version).toBe('.NET Framework 4.x（CLR 4.0.30319）');
        expect(aspnet4?.supportStatus).toBe('Unknown');
      });

      it('指摘 4: 確信度 60% の Spring Security が「稼働確認済 (confirmed)」にならず、SESSION Cookie があると確信度が上がること', () => {
        // 1. _csrf のみ (確信度 60%, medium)
        const csrfOnlyResults = engine.detect({
          url: 'https://spring.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ["input[name='_csrf']"],
          },
        });

        const springCsrfOnly = csrfOnlyResults.find((r) => r.technology === 'Spring Security');
        expect(springCsrfOnly).toBeDefined();
        expect(springCsrfOnly?.category).toBe('framework');
        expect(springCsrfOnly?.confidence).toBe(60);
        expect(springCsrfOnly?.confidenceLevel).toBe('medium');
        expect(springCsrfOnly?.runtimeStatus).toBe('possible');
        expect(springCsrfOnly?.runtimeStatus).not.toBe('confirmed');

        // 2. _csrf + SESSION Cookie がある場合、確信度が上がる
        const withSessionResults = engine.detect({
          url: 'https://spring.example.test/',
          dom: {
            ...emptyDom,
            domMarkers: ["input[name='_csrf']"],
          },
          network: {
            url: 'https://spring.example.test/',
            responseHeaders: {},
            cookies: [{ name: 'SESSION', value: 'spring-session-id' }],
          },
        });

        const springWithSession = withSessionResults.find(
          (r) => r.technology === 'Spring Security'
        );
        expect(springWithSession).toBeDefined();
        expect(springWithSession!.confidence).toBeGreaterThan(springCsrfOnly!.confidence);

        // 3. 陰性（否定コントロール）: 汎用的な SESSION Cookie 単独では Spring Security を誤検出しないこと
        const sessionOnlyResults = engine.detect({
          url: 'https://generic-session.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://generic-session.example.test/',
            responseHeaders: {},
            cookies: [{ name: 'SESSION', value: 'generic-id' }],
          },
        });
        expect(sessionOnlyResults.find((r) => r.technology === 'Spring Security')).toBeUndefined();
      });

      it('Azure (指摘 G, A): ApplicationGatewayAffinity だけを返すページから Azure Application Gateway が検出され、ai_session/ai_user・スクリプトURLから Application Insights が検出されること', () => {
        // 1. ApplicationGatewayAffinity のみ
        const agwResults = engine.detect({
          url: 'https://azure-gw.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://azure-gw.example.test/',
            responseHeaders: {},
            cookies: [{ name: 'ApplicationGatewayAffinity', value: 'hash123' }],
          },
        });

        const agw = agwResults.find((r) => r.technology === 'Azure Application Gateway');
        expect(agw).toBeDefined();
        expect(agw?.category).toBe('hosting-cloud');

        // 2. Application Insights (Cookie および スクリプト URL)
        const aiCookieResults = engine.detect({
          url: 'https://azure-ai.example.test/',
          dom: emptyDom,
          network: {
            url: 'https://azure-ai.example.test/',
            responseHeaders: {},
            cookies: [
              { name: 'ai_session', value: 'sess' },
              { name: 'ai_user', value: 'usr' },
            ],
          },
        });
        const aiFromCookie = aiCookieResults.find((r) => r.technology === 'Application Insights');
        expect(aiFromCookie).toBeDefined();
        expect(aiFromCookie?.category).toBe('analytics-tracking');

        const aiScriptResults = engine.detect({
          url: 'https://azure-ai-script.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://az416426.vo.msecnd.net/scripts/a/ai.0.js'],
          },
        });
        expect(
          aiScriptResults.find((r) => r.technology === 'Application Insights')
        ).toBeDefined();

        // 3. 陰性（否定コントロール）: 類似Cookie名や別ドメインのスクリプトでは検出しない
        const negResults = engine.detect({
          url: 'https://non-azure.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://non-azure.example.test/vo.msecnd.net/fake.js'],
          },
          network: {
            url: 'https://non-azure.example.test/',
            responseHeaders: {},
            cookies: [
              { name: 'MyApplicationGatewayAffinity', value: '1' },
              { name: 'ai_session_id', value: '2' },
            ],
          },
        });
        expect(
          negResults.find((r) => r.technology === 'Azure Application Gateway')
        ).toBeUndefined();
        expect(negResults.find((r) => r.technology === 'Application Insights')).toBeUndefined();
      });
    });

    describe('v1.7.1 T09: フロント・CMS・計測タグの検出 (N5, E, J, K, E4, L)', () => {
      it('N5 & E: getbootstrap.com のスナップショットで Bootstrap 6.0 が検出され Tailwind CSS が出ず、react.dev のスナップショットでは Tailwind CSS が引き続き出ること', () => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const fs = require('node:fs');
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const path = require('node:path');
        const snapDir = path.resolve(__dirname, 'fixtures', 'snapshots');

        const buildDomFromSnapshot = (
          html: string,
          pageUrl: string,
          resourceTiming: Array<{ name: string; initiatorType?: string }> = []
        ): DomSignals => {
          const metaTags: Array<{ name?: string; property?: string; content: string }> = [];
          for (const m of html.matchAll(/<meta\b([^>]+)>/gi)) {
            const attrs = m[1];
            const nameMatch = attrs.match(/\bname=["']([^"']+)["']/i);
            const propMatch = attrs.match(/\bproperty=["']([^"']+)["']/i);
            const contentMatch = attrs.match(/\bcontent=["']([^"']*)["']/i);
            if (contentMatch && contentMatch[1]) {
              metaTags.push({
                name: nameMatch?.[1],
                property: propMatch?.[1],
                content: contentMatch[1],
              });
            }
          }

          const rawScriptUrls: string[] = [];
          const scriptUrls: string[] = [];
          for (const m of html.matchAll(/<script\b([^>]+)>/gi)) {
            const srcMatch = m[1].match(/\bsrc=["']([^"']+)["']/i);
            if (srcMatch && srcMatch[1]) {
              const raw = srcMatch[1].trim();
              rawScriptUrls.push(raw);
              try {
                scriptUrls.push(new URL(raw, pageUrl).href);
              } catch {
                scriptUrls.push(raw);
              }
            }
          }

          const rawLinkUrls: Array<{ rel: string; href: string }> = [];
          const linkUrls: Array<{ rel: string; href: string }> = [];
          for (const m of html.matchAll(/<link\b([^>]+)>/gi)) {
            const attrs = m[1];
            const hrefMatch = attrs.match(/\bhref=["']([^"']+)["']/i);
            const relMatch = attrs.match(/\brel=["']([^"']+)["']/i);
            if (hrefMatch && hrefMatch[1]) {
              const rawHref = hrefMatch[1].trim();
              const rel = relMatch?.[1] || '';
              rawLinkUrls.push({ rel, href: rawHref });
              let resolvedHref = rawHref;
              try {
                resolvedHref = new URL(rawHref, pageUrl).href;
              } catch {
                // ignore
              }
              linkUrls.push({ rel, href: resolvedHref });
            }
          }

          const classSet = new Set<string>();
          for (const m of html.matchAll(/\bclass=["']([^"']+)["']/gi)) {
            const tokens = m[1].split(/\s+/);
            for (const tok of tokens) {
              if (tok && tok.length > 2) {
                classSet.add(tok);
              }
            }
          }

          return {
            ...emptyDom,
            url: pageUrl,
            metaTags,
            rawScriptUrls,
            scriptUrls,
            rawLinkUrls,
            linkUrls,
            htmlSnippets: Array.from(classSet).slice(0, 60),
            resourceEntries: resourceTiming.map((r) => ({
              url: r.name,
              initiatorType: r.initiatorType || 'other',
            })),
          };
        };

        // 1. getbootstrap.com スナップショット
        const bsSnap = JSON.parse(
          fs.readFileSync(path.join(snapDir, 'getbootstrap.com.json'), 'utf-8')
        );
        const bsHtml = fs.readFileSync(path.join(snapDir, 'getbootstrap.com.html'), 'utf-8');
        const bsPageUrl = bsSnap.finalUrl || bsSnap.url;
        const bsDom = buildDomFromSnapshot(bsHtml, bsPageUrl, bsSnap.resourceTiming || []);

        const bsResults = engine.detect({
          url: bsPageUrl,
          dom: bsDom,
          network: {
            url: bsPageUrl,
            responseHeaders: bsSnap.responseHeaders,
            cookies: bsSnap.cookies,
          },
        });

        const bootstrap = bsResults.find((r) => r.technology === 'Bootstrap');
        expect(bootstrap).toBeDefined();
        expect(bootstrap?.version).toBe('6.0');
        expect(bsResults.find((r) => r.technology === 'Tailwind CSS')).toBeUndefined();

        // 2. react.dev スナップショット
        const reactSnap = JSON.parse(
          fs.readFileSync(path.join(snapDir, 'react.dev.json'), 'utf-8')
        );
        const reactHtml = fs.readFileSync(path.join(snapDir, 'react.dev.html'), 'utf-8');
        const reactPageUrl = reactSnap.finalUrl || reactSnap.url;
        const reactDom = buildDomFromSnapshot(
          reactHtml,
          reactPageUrl,
          reactSnap.resourceTiming || []
        );

        const reactResults = engine.detect({
          url: reactPageUrl,
          dom: reactDom,
          network: {
            url: reactPageUrl,
            responseHeaders: reactSnap.responseHeaders,
            cookies: reactSnap.cookies,
          },
        });

        const tailwind = reactResults.find((r) => r.technology === 'Tailwind CSS');
        expect(tailwind).toBeDefined();
      });

      it('E: Bootstrap の版が runtime および URL パス (/bootstrap-4.3.1/, /docs/6.0/, bootstrap@5.3.3) から取れ、ファイル名だけの根拠では確信度が medium になること', () => {
        // 1. /bootstrap-4.3.1/ パス
        const resPath4 = engine.detect({
          url: 'https://bs4.example.test/',
          dom: {
            ...emptyDom,
            linkUrls: [
              {
                rel: 'stylesheet',
                href: 'https://bs4.example.test/lib/bootstrap-4.3.1/css/bootstrap.min.css',
              },
            ],
          },
        });
        const bs4 = resPath4.find((r) => r.technology === 'Bootstrap');
        expect(bs4?.version).toBe('4.3.1');
        expect(bs4?.confidenceLevel).toBe('high');

        // 2. /docs/6.0/ パス
        const resDocs6 = engine.detect({
          url: 'https://bs6.example.test/',
          dom: {
            ...emptyDom,
            linkUrls: [
              {
                rel: 'stylesheet',
                href: 'https://bs6.example.test/docs/6.0/dist/css/bootstrap.min.css',
              },
            ],
          },
        });
        expect(resDocs6.find((r) => r.technology === 'Bootstrap')?.version).toBe('6.0');

        // 3. bootstrap@5.3.3 パス
        const resCdn5 = engine.detect({
          url: 'https://bs5.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: [
              'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js',
            ],
          },
        });
        expect(resCdn5.find((r) => r.technology === 'Bootstrap')?.version).toBe('5.3.3');

        // 4. ファイル名だけ（バージョンなし）の根拠では確信度が medium (50〜79) になること
        const resFilenameOnly = engine.detect({
          url: 'https://bs-fileonly.example.test/',
          dom: {
            ...emptyDom,
            linkUrls: [
              {
                rel: 'stylesheet',
                href: 'https://bs-fileonly.example.test/assets/css/bootstrap.min.css',
              },
            ],
            cssAssets: [
              {
                href: 'https://bs-fileonly.example.test/assets/css/bootstrap.min.css',
                filename: 'bootstrap.min.css',
                inferredLibrary: 'Bootstrap',
                inferredVersion: null,
                evidenceType: 'css-url',
                confidence: 'medium',
              },
            ],
          },
        });
        const bsFileOnly = resFilenameOnly.find((r) => r.technology === 'Bootstrap');
        expect(bsFileOnly).toBeDefined();
        expect(bsFileOnly?.version).toBeNull();
        expect(bsFileOnly?.confidenceLevel).toBe('medium');
        expect(bsFileOnly!.confidence).toBeGreaterThanOrEqual(50);
        expect(bsFileOnly!.confidence).toBeLessThan(80);
      });

      it('J: 根拠の整理（同じ種別・同じ値の統合、.container 汎用クラスの省略、link[rel="alternate"] の [link] 種別、上限 20 件の維持）', () => {
        // 1. 同じアセットが rawLinkUrls・linkUrls・cssAssets・htmlSnippets(.container) にあっても 1 件にまとまり、.container が省略されること
        const resBs = engine.detect({
          url: 'https://dedupe.example.test/',
          dom: {
            ...emptyDom,
            rawLinkUrls: [{ rel: 'stylesheet', href: '/css/bootstrap-5.3.3.min.css' }],
            linkUrls: [
              { rel: 'stylesheet', href: 'https://dedupe.example.test/css/bootstrap-5.3.3.min.css' },
            ],
            cssAssets: [
              {
                href: 'https://dedupe.example.test/css/bootstrap-5.3.3.min.css',
                filename: 'bootstrap-5.3.3.min.css',
                inferredLibrary: 'Bootstrap',
                inferredVersion: '5.3.3',
                evidenceType: 'css-url',
                confidence: 'medium',
              },
            ],
            htmlSnippets: ['container', 'xl:container'],
          },
        });
        const bs = resBs.find((r) => r.technology === 'Bootstrap');
        expect(bs).toBeDefined();
        expect(bs?.evidence.length).toBe(1);
        expect(bs?.evidence[0].type).toBe('css-url');
        expect(bs?.evidence.some((e) => e.value === 'container')).toBe(false);

        // 2. link[rel="alternate"] の根拠種別が css-url ではなく link になること
        const resWpLink = engine.detect({
          url: 'https://wp-link.example.test/',
          dom: {
            ...emptyDom,
            rawLinkUrls: [
              {
                rel: 'alternate',
                href: 'https://wp-link.example.test/wp-json/wp/v2/pages/10',
              },
            ],
            referenceOnlyUrls: [
              {
                sourceType: 'alternate',
                url: 'https://wp-link.example.test/wp-json/wp/v2/pages/10',
              },
            ],
          },
        });
        const wpFromLink = resWpLink.find((r) => r.technology === 'WordPress');
        expect(wpFromLink).toBeDefined();
        expect(wpFromLink?.evidence.length).toBe(1);
        expect(wpFromLink?.evidence[0].type).toBe('link');
        expect(wpFromLink?.evidence[0].name).toBe('link[rel="alternate"]');

        // 3. IMPL-06 の上限 20 件が維持されること
        const manyScripts = Array.from(
          { length: 25 },
          (_, i) => `https://wp-many.example.test/wp-content/plugins/plugin-${i}/app.js`
        );
        const resMany = engine.detect({
          url: 'https://wp-many.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: manyScripts,
          },
        });
        const wpMany = resMany.find((r) => r.technology === 'WordPress');
        expect(wpMany).toBeDefined();
        expect(wpMany?.evidence.length).toBe(20);
      });

      it('K & E4: WordPress で generator がなくてもコアの ver から版が出て、同梱ライブラリやプラグインの ver と区別され、プラグイン・テーマ一覧と重複なし根拠が得られること', () => {
        const wpDom = {
          ...emptyDom,
          rawScriptUrls: [
            '/wp-includes/js/jquery/jquery.min.js?ver=3.7.1',
            '/wp-includes/js/underscore.min.js?ver=1.13.4',
            '/wp-includes/js/wp-embed.min.js?ver=6.4.3',
            '/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.7',
            '/wp-content/plugins/akismet/_inc/akismet-frontend.js?ver=5.3',
          ],
          scriptUrls: [
            'https://wp-synth.example.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1',
            'https://wp-synth.example.test/wp-includes/js/underscore.min.js?ver=1.13.4',
            'https://wp-synth.example.test/wp-includes/js/wp-embed.min.js?ver=6.4.3',
            'https://wp-synth.example.test/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.7',
            'https://wp-synth.example.test/wp-content/plugins/akismet/_inc/akismet-frontend.js?ver=5.3',
          ],
          rawLinkUrls: [
            {
              rel: 'stylesheet',
              href: '/wp-includes/css/dist/block-library/style.min.css?ver=6.4.3',
            },
            {
              rel: 'stylesheet',
              href: '/wp-content/themes/twentytwentyfour/style.css?ver=1.0',
            },
            {
              rel: 'alternate',
              href: '/wp-json/wp/v2/pages/42',
            },
          ],
          linkUrls: [
            {
              rel: 'stylesheet',
              href: 'https://wp-synth.example.test/wp-includes/css/dist/block-library/style.min.css?ver=6.4.3',
            },
            {
              rel: 'stylesheet',
              href: 'https://wp-synth.example.test/wp-content/themes/twentytwentyfour/style.css?ver=1.0',
            },
          ],
          referenceOnlyUrls: [
            {
              sourceType: 'alternate',
              url: 'https://wp-synth.example.test/wp-json/wp/v2/pages/42',
            },
          ],
        };

        const results = engine.detect({
          url: 'https://wp-synth.example.test/',
          dom: wpDom,
        });

        const wp = results.find((r) => r.technology === 'WordPress');
        expect(wp).toBeDefined();
        // jQuery の 3.7.1 やプラグインの 5.8.7 ではなく、コアの 6.4.3 が特定されること
        expect(wp?.version).toBe('6.4.3');
        expect(wp?.instances?.length).toBe(1);
        expect(wp?.instances?.[0].version).toBe('6.4.3');

        // プラグインとテーマの一覧が取得されていること
        expect(wp?.wpPlugins).toEqual([
          { name: 'contact-form-7', version: '5.8.7' },
          { name: 'akismet', version: '5.3' },
        ]);
        expect(wp?.wpThemes).toEqual([{ name: 'twentytwentyfour', version: '1.0' }]);

        // 同じ根拠が 2 回出ていないこと & クエリ (?ver=...) が除去されていること
        const evKeys = wp!.evidence.map((e) => `${e.type}:${e.value}`);
        expect(new Set(evKeys).size).toBe(evKeys.length);
        for (const ev of wp!.evidence) {
          expect(ev.value.includes('?ver=')).toBe(false);
        }
        // alternate リンクの種別が link であること
        const altEv = wp!.evidence.find((e) => e.value.includes('/wp-json/'));
        expect(altEv?.type).toBe('link');
      });

      it('L: Google Tag Manager (gtm.js / gtag/js) と Facebook SDK (connect.facebook.net) の検出（陽性・陰性）', () => {
        // 1. 陽性: gtag/js と connect.facebook.net
        const posResults = engine.detect({
          url: 'https://tags.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: [
              'https://www.googletagmanager.com/gtag/js?id=G-TEST1234',
              'https://connect.facebook.net/en_US/fbevents.js',
            ],
          },
        });
        expect(posResults.find((r) => r.technology === 'Google Tag Manager')).toBeDefined();
        expect(posResults.find((r) => r.technology === 'Google Analytics')).toBeDefined();
        expect(posResults.find((r) => r.technology === 'Facebook SDK')).toBeDefined();

        // 2. 陽性: gtm.js のみ
        const gtmOnlyResults = engine.detect({
          url: 'https://gtm-only.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: ['https://www.googletagmanager.com/gtm.js?id=GTM-XXXX'],
          },
        });
        expect(gtmOnlyResults.find((r) => r.technology === 'Google Tag Manager')).toBeDefined();

        // 3. 陰性: 関係ないスクリプトでは検出しないこと
        const negResults = engine.detect({
          url: 'https://no-tags.example.test/',
          dom: {
            ...emptyDom,
            scriptUrls: [
              'https://no-tags.example.test/assets/gtm-helper.js',
              'https://no-tags.example.test/assets/facebook-share.js',
            ],
          },
        });
        expect(negResults.find((r) => r.technology === 'Google Tag Manager')).toBeUndefined();
        expect(negResults.find((r) => r.technology === 'Facebook SDK')).toBeUndefined();
      });
    });
  });
});


