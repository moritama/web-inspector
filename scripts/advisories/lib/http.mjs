/**
 * Web Technology & Security Inspector
 * 上流API取得用 HTTP クライアント (scripts/advisories/lib/http.mjs)
 *
 * - ホスト単位の最小リクエスト間隔 (NVD: APIキー無し 6.5秒 / 有り 0.7秒)
 * - 429 / 403 / 5xx / ネットワークエラー時の指数バックオフ再試行
 * - タイムアウト
 * - レスポンスサイズ上限 (異常な巨大応答によるメモリ枯渇防止)
 */

import { sleep } from './util.mjs';

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_BODY_BYTES = 64 * 1024 * 1024;

/**
 * @param {{ fetchImpl?: typeof fetch, minIntervalMs?: Record<string, number>, retries?: number, userAgent?: string, log?: (msg: string) => void }} options
 */
export function createFetchJson(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const minInterval = options.minIntervalMs || {};
  const retries = options.retries ?? 4;
  const userAgent = options.userAgent || 'web-inspector-advisory-sync (+https://github.com/moritama/web-inspector)';
  const log = options.log || (() => {});
  const lastRequestAt = new Map();

  return async function fetchJson(url, init = {}) {
    const host = new URL(url).host;
    let attempt = 0;
    for (;;) {
      const wait = (lastRequestAt.get(host) || 0) + (minInterval[host] || 0) - Date.now();
      if (wait > 0) await sleep(wait);
      lastRequestAt.set(host, Date.now());

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), init.timeoutMs || DEFAULT_TIMEOUT_MS);
      try {
        const res = await fetchImpl(url, {
          method: init.method || 'GET',
          body: init.body,
          headers: {
            Accept: 'application/json',
            'User-Agent': userAgent,
            ...(init.body ? { 'Content-Type': 'application/json' } : {}),
            ...(init.headers || {}),
          },
          signal: controller.signal,
        });
        if (res.status === 429 || res.status === 403 || res.status >= 500) {
          throw Object.assign(new Error(`HTTP ${res.status} ${url}`), { retryable: true });
        }
        if (!res.ok) {
          throw Object.assign(new Error(`HTTP ${res.status} ${url}`), { retryable: false });
        }
        const text = await res.text();
        if (text.length > MAX_BODY_BYTES) throw new Error(`応答サイズが上限を超えました: ${url}`);
        return JSON.parse(text);
      } catch (err) {
        const retryable = err.retryable !== false;
        attempt++;
        if (!retryable || attempt > retries) throw err;
        const backoff = Math.min(60_000, 2000 * 2 ** (attempt - 1));
        log(`  再試行 ${attempt}/${retries} (${backoff}ms後): ${err.message}`);
        await sleep(backoff);
      } finally {
        clearTimeout(timer);
      }
    }
  };
}
