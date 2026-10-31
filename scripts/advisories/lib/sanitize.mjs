/**
 * Web Technology & Security Inspector
 * 外部データのサニタイズ (scripts/advisories/lib/sanitize.mjs)
 *
 * 上流フィード (OSV / NVD / endoflife.date / CISA KEV) は第三者が編集できるデータであり、
 * 拡張機能のUIへそのまま埋め込まれる可能性がある (v1.6.5 時点で adv.title / referenceUrls は
 * innerHTML へ未エスケープで出力されている)。
 * そのため DB 生成時点で以下を強制し、サプライチェーン経由の HTML 注入を防ぐ:
 *   - 制御文字・HTML特殊文字 (< > " ' `) の除去/置換
 *   - 文字数上限
 *   - URL は https かつ許可ホストのみ
 */

/** advisoryUrl / referenceUrls に許可するホスト (完全一致) */
export const ALLOWED_REFERENCE_HOSTS = new Set([
  'nvd.nist.gov',
  'github.com',
  'osv.dev',
  'www.cve.org',
  'endoflife.date',
  'www.cisa.gov',
  'nodejs.org',
  'www.php.net',
  'httpd.apache.org',
  'nginx.org',
  'wordpress.org',
  'blog.jquery.com',
  'getbootstrap.com',
  'laravel.com',
  'angular.dev',
  'angular.io',
  'react.dev',
  'vuejs.org',
]);

const REPLACEMENTS = [
  [/</g, '＜'],
  [/>/g, '＞'],
  [/"/g, '”'],
  [/'/g, '’'],
  [/`/g, '‘'],
];

/**
 * 表示用テキストを安全化する
 * @param {unknown} value
 * @param {number} maxLength
 * @returns {string}
 */
export function cleanText(value, maxLength = 200) {
  if (value === null || value === undefined) return '';
  // eslint-disable-next-line no-control-regex
  let text = String(value).replace(new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028\\u2029\\u202a-\\u202e]', 'g'), ' ');
  for (const [re, rep] of REPLACEMENTS) text = text.replace(re, rep);
  text = text.replace(/\s+/g, ' ').trim();
  if (text.length > maxLength) {
    text = `${text.slice(0, maxLength - 1).trimEnd()}…`;
  }
  return text;
}

/**
 * URL が https かつ許可ホストであればそのまま返し、そうでなければ null
 * @param {unknown} value
 * @param {Set<string>} allowedHosts
 */
export function safeUrl(value, allowedHosts = ALLOWED_REFERENCE_HOSTS) {
  if (!value || typeof value !== 'string') return null;
  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:') return null;
  if (parsed.username || parsed.password) return null;
  if (!allowedHosts.has(parsed.hostname.toLowerCase())) return null;
  const href = parsed.toString();
  if (/["'<>\s`]/.test(href)) return null;
  return href;
}

/** 文字列が DB に格納してよい安全な表示テキストか (検証用) */
export function isSafeText(value) {
  if (typeof value !== 'string') return false;
  // eslint-disable-next-line no-control-regex
  return !/[<>"'`\u0000-\u001f\u007f]/.test(value);
}
