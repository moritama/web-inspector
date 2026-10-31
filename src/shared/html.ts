/**
 * Web Technology & Security Inspector
 * HTML エスケープおよび安全な URL 処理ユーティリティ (src/shared/html.ts) - IMPL-03
 */

/**
 * HTML の特殊文字（&, <, >, ", '）をエスケープする。
 * null または undefined の場合は空文字を返し、文字列以外は String() で変換する。
 *
 * @param value エスケープ対象の値
 * @returns エスケープ後の文字列
 */
export function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  const str = typeof value === 'string' ? value : String(value);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * 安全な外部リンクURL（https: のみ）を検証・返却する。
 * https: 以外のプロトコル（javascript:, data:, http: 等）や解析不能な値は null を返す。
 *
 * @param url 検証対象のURL
 * @returns 有効な https URL 文字列、または null
 */
export function safeHref(url: unknown): string | null {
  if (!url || typeof url !== 'string') {
    return null;
  }
  const trimmed = url.trim();
  if (!trimmed) {
    return null;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'https:') {
      return parsed.href;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * 安全な外部リンクHTML（<a>タグまたはプレーンテキスト）を生成する。
 * safeHref が null の場合はリンクではなく安全にエスケープされたテキストとして表示する。
 * 外部リンクには rel="noopener noreferrer" を付与する。
 *
 * @param url リンク先URL
 * @param label 表示テキスト（省略時はURL文字列）
 * @param options 追加の属性（className, style等）
 * @returns 生成されたHTML文字列
 */
export function renderSafeExternalLink(
  url: unknown,
  label?: string,
  options?: { className?: string; style?: string }
): string {
  const safe = safeHref(url);
  const rawUrl = typeof url === 'string' ? url : String(url ?? '');
  const displayText = escapeHtml(label !== undefined ? label : rawUrl);

  if (safe) {
    const classAttr = options?.className ? ` class="${escapeHtml(options.className)}"` : '';
    const styleAttr = options?.style ? ` style="${escapeHtml(options.style)}"` : '';
    return `<a href="${escapeHtml(safe)}" target="_blank" rel="noopener noreferrer"${classAttr}${styleAttr}>${displayText}</a>`;
  }

  // safeHref が null の場合はリンクではなくテキストとして表示
  if (options?.style || options?.className) {
    const classAttr = options?.className ? ` class="${escapeHtml(options.className)}"` : '';
    const styleAttr = options?.style ? ` style="${escapeHtml(options.style)}"` : '';
    return `<span${classAttr}${styleAttr}>${displayText}</span>`;
  }
  return `<span>${displayText}</span>`;
}
