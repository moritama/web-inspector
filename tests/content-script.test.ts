// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * Content Script (DOMシグナル抽出) の単体テスト (tests/content-script.test.ts)
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { extractDomSignals } from '../src/content/content-script';
import { checkHttpsAndMixedContent } from '../src/security/https';

describe('extractDomSignals (Content Script)', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    document.head.innerHTML = '';
  });

  it('data-v-xxxxxxxx 属性を持つ要素から Vue のシグナル (data-v-) を検出できること', () => {
    document.body.innerHTML = `
      <div id="app">
        <div data-v-7ba5bd90 class="user-profile">
          <span data-v-7ba5bd90>Hello Vue</span>
        </div>
      </div>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('data-v-');
  });

  it('data-astro-cid-xxxx 属性を持つ要素から Astro のシグナルを検出できること', () => {
    document.body.innerHTML = `
      <main data-astro-cid-j7pv25f6>
        <h1 data-astro-cid-j7pv25f6>Welcome to Astro</h1>
      </main>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('data-astro-cid-');
  });

  it('data-sveltekit-xxx 属性を持つ要素から SvelteKit のシグナルを検出できること', () => {
    document.body.innerHTML = `
      <div data-sveltekit-preload-data="hover">
        <a href="/about">About</a>
      </div>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('data-sveltekit-');
  });

  it('noscript 内に配置された GTM の iframe (ns.html) を検出できること', () => {
    // JS有効時のブラウザ挙動と同様に、noscript タグ内にテキストとして iframe が格納されている場合
    const noscript = document.createElement('noscript');
    noscript.textContent = '<iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX" height="0" width="0" style="display:none;visibility:hidden"></iframe>';
    document.body.appendChild(noscript);

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('googletagmanager.com/ns.html');
  });

  it('AngularJS の [ng-app] 属性要素が存在する場合に domMarkers に検出されること', () => {
    document.body.innerHTML = `
      <div ng-app="myApp" ng-controller="MainCtrl">
        <p>AngularJS content</p>
      </div>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('[ng-app]');
    expect(signals.domMarkers).toContain('[ng-controller]');
  });

  it('T07 (SPEC-15): <img srcset="http://...">, <form action="http://...">, <video src="http://..."> 等が混在コンテンツとして検出され、form は high、img / video は low と判定されること', () => {
    if ((window as any).happyDOM?.setURL) {
      (window as any).happyDOM.setURL('https://example.com/');
    } else {
      window.location.href = 'https://example.com/';
    }

    document.body.innerHTML = `
      <img srcset="http://cdn.example.com/img-1x.jpg 1x, https://cdn.example.com/img-2x.jpg 2x">
      <form action="http://insecure.example.com/submit" method="post"></form>
      <video src="http://media.example.com/movie.mp4"></video>
      <audio src="http://media.example.com/voice.mp3"></audio>
      <video><source src="http://media.example.com/sub.webm"></video>
      <picture><source srcset="http://cdn.example.com/pic.webp 1x"></picture>
      <object data="http://legacy.example.com/flash.swf"></object>
      <embed src="http://legacy.example.com/embed.swf">
    `;

    const signals = extractDomSignals();
    expect(signals.mixedContent).toEqual(
      expect.arrayContaining([
        { resourceType: 'image', url: 'http://cdn.example.com/img-1x.jpg' },
        { resourceType: 'form', url: 'http://insecure.example.com/submit' },
        { resourceType: 'video', url: 'http://media.example.com/movie.mp4' },
        { resourceType: 'audio', url: 'http://media.example.com/voice.mp3' },
        { resourceType: 'video', url: 'http://media.example.com/sub.webm' },
        { resourceType: 'image', url: 'http://cdn.example.com/pic.webp' },
        { resourceType: 'object', url: 'http://legacy.example.com/flash.swf' },
        { resourceType: 'embed', url: 'http://legacy.example.com/embed.swf' },
      ])
    );

    // form 単独での評価: high
    const formItems = signals.mixedContent.filter((i) => i.resourceType === 'form');
    expect(formItems).toHaveLength(1);
    const formChecks = checkHttpsAndMixedContent('https://example.com/', true, formItems);
    const activeCheck = formChecks.find((c) => c.checkId === 'SEC-MIXED-ACTIVE');
    expect(activeCheck?.severity).toBe('high');
    expect(activeCheck?.status).toBe('fail');

    // img / video (パッシブ混在) での評価: low
    const passiveItems = signals.mixedContent.filter(
      (i) => i.resourceType === 'image' || i.resourceType === 'video'
    );
    expect(passiveItems.length).toBeGreaterThanOrEqual(2);
    const passiveChecks = checkHttpsAndMixedContent('https://example.com/', true, passiveItems);
    const passiveCheck = passiveChecks.find((c) => c.checkId === 'SEC-MIXED-PASSIVE');
    expect(passiveCheck?.severity).toBe('low');
    expect(passiveCheck?.status).toBe('warning');
  });

  it('T09 (DOC-06): <link rel="stylesheet"> の URL から Bootstrap バージョンを抽出し、死んでいた CSS コメント抽出には依存しないこと', () => {
    const origConsoleError = console.error;
    console.error = (...args: unknown[]) => {
      const msg = String(args[0] ?? '');
      if (msg.includes('CSS file loading is disabled')) return;
      origConsoleError(...args);
    };
    try {
      document.head.innerHTML = `
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
      `;

      const signals = extractDomSignals();
      expect(signals.cssAssets).toBeDefined();
      expect(signals.cssAssets).toEqual([
        {
          href: 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css',
          filename: 'bootstrap.min.css',
          inferredLibrary: 'Bootstrap',
          inferredVersion: '5.3.2',
          evidenceType: 'css-url',
          confidence: 'medium',
        },
      ]);
    } finally {
      console.error = origConsoleError;
    }
  });
});
