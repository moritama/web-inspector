/**
 * Web Technology & Security Inspector
 * Content Script (src/content/content-script.ts)
 * 閲覧中のWebページ内でDOM、アセット、混在コンテンツを収集します
 */

import { DomSignals, MixedContentItem } from '../shared/types';

/**
 * ページ内のDOM、スクリプト、メタ情報、混在コンテンツを安全に抽出する
 */
export function extractDomSignals(): DomSignals {
  const isPageHttps = window.location.protocol === 'https:';

  // 1. metaタグ収集
  const metaTags: Array<{ name?: string; property?: string; content: string }> = [];
  document.querySelectorAll('meta').forEach((el) => {
    const name = el.getAttribute('name') || undefined;
    const property = el.getAttribute('property') || undefined;
    const content = el.getAttribute('content') || '';
    if (content) {
      metaTags.push({ name, property, content });
    }
  });

  // 2. script src 収集
  const scriptUrls: string[] = [];
  document.querySelectorAll('script[src]').forEach((el) => {
    const src = el.getAttribute('src');
    if (src) {
      scriptUrls.push(src);
    }
  });

  // 3. link href 収集
  const linkUrls: Array<{ rel: string; href: string }> = [];
  document.querySelectorAll('link[href]').forEach((el) => {
    const href = el.getAttribute('href');
    const rel = el.getAttribute('rel') || '';
    if (href) {
      linkUrls.push({ rel, href });
    }
  });

  // 4. 特徴的なDOMマーカーの探査
  const domMarkers: string[] = [];
  const markerSelectors = [
    '#root',
    '#app',
    '#__next',
    '#__nuxt',
    'script#__NEXT_DATA__',
    'script#__NUXT_DATA__',
    '[data-reactroot]',
    '[data-reactid]',
    '[data-v-]',
    '[ng-version]',
    '[ng-app]',
    '[ng-controller]',
    "[class*='svelte-']",
    "input[name='csrfmiddlewaretoken']",
    "meta[name='csrf-param']",
  ];

  markerSelectors.forEach((sel) => {
    try {
      const el = document.querySelector(sel);
      if (el) {
        if (sel === '[ng-version]') {
          domMarkers.push(`ng-version="${el.getAttribute('ng-version')}"`);
        } else if (sel === 'script#__NEXT_DATA__') {
          domMarkers.push('__NEXT_DATA__');
        } else if (sel === 'script#__NUXT_DATA__') {
          domMarkers.push('__NUXT_DATA__');
        } else {
          domMarkers.push(sel);
        }
      }
    } catch {
      // セレクタ評価エラー防止
    }
  });

  // 5. HTMLスニペット（Tailwind等のユーティリティクラス探査用）
  const htmlSnippets: string[] = [];
  const sampleElements = document.querySelectorAll('body, div, nav, header, main, section');
  sampleElements.forEach((el, index) => {
    if (index < 30) {
      const className = el.getAttribute('class');
      if (className) {
        htmlSnippets.push(className);
      }
    }
  });

  // 6. 混在コンテンツ (Mixed Content) の収集
  const mixedContent: MixedContentItem[] = [];
  if (isPageHttps) {
    // 画像
    document.querySelectorAll('img[src]').forEach((el) => {
      const src = el.getAttribute('src');
      if (src && src.startsWith('http://')) {
        mixedContent.push({ resourceType: 'image', url: src });
      }
    });

    // スクリプト
    document.querySelectorAll('script[src]').forEach((el) => {
      const src = el.getAttribute('src');
      if (src && src.startsWith('http://')) {
        mixedContent.push({ resourceType: 'script', url: src });
      }
    });

    // スタイルシート
    document.querySelectorAll('link[rel="stylesheet"][href]').forEach((el) => {
      const href = el.getAttribute('href');
      if (href && href.startsWith('http://')) {
        mixedContent.push({ resourceType: 'stylesheet', url: href });
      }
    });

    // iframe
    document.querySelectorAll('iframe[src]').forEach((el) => {
      const src = el.getAttribute('src');
      if (src && src.startsWith('http://')) {
        mixedContent.push({ resourceType: 'iframe', url: src });
      }
    });
  }

  // 7. document.cookieから名前のみ抽出 (値は絶対に取得・保存しない)
  const cookiesFromDocument: string[] = [];
  try {
    const rawCookies = document.cookie || '';
    if (rawCookies) {
      rawCookies.split(';').forEach((pair) => {
        const trimmed = pair.trim();
        const equalsIndex = trimmed.indexOf('=');
        const name = equalsIndex > -1 ? trimmed.substring(0, equalsIndex).trim() : trimmed;
        if (name && !cookiesFromDocument.includes(name)) {
          cookiesFromDocument.push(name);
        }
      });
    }
  } catch {
    // Cookie読み取り制限時の例外防止
  }

  return {
    url: window.location.href,
    title: document.title || '',
    metaTags,
    scriptUrls,
    linkUrls,
    domMarkers,
    htmlSnippets,
    mixedContent,
    cookiesFromDocument,
  };
}

// Service WorkerまたはPopupからの要求に応答
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'EXTRACT_DOM_SIGNALS') {
    const signals = extractDomSignals();
    sendResponse(signals);
  }
  return true; // 非同期レスポンス許可
});
