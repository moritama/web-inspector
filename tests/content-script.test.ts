// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * Content Script (DOMシグナル抽出) の単体テスト (tests/content-script.test.ts)
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { extractDomSignals } from '../src/content/content-script';

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
});
