/**
 * Web Technology & Security Inspector
 * 安全なコンテキスト（Secure Context）判定モジュール (src/shared/secure-context.ts)
 */

/**
 * URL が secure context（W3C Secure Contexts「potentially trustworthy」）の文書になるかを返す (v1.8.2 T05 / H7)
 * 真: https・wss・file、localhost・*.localhost、127.0.0.0/8、[::1]。不正な URL・文字列でない入力は false
 *
 * @param url 判定対象の URL 文字列
 * @returns 安全なコンテキストであれば true、そうでなければ false
 */
export function isSecureContextUrl(url: string): boolean {
  if (typeof url !== 'string' || !url) {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  // 1. スキームが https:、wss:、file: の場合
  const protocol = parsed.protocol.toLowerCase();
  if (protocol === 'https:' || protocol === 'wss:' || protocol === 'file:') {
    return true;
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return false;
  }

  // 2. ホスト名が localhost または .localhost で終わる場合
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return true;
  }

  // 3. ホストが IPv4 で、先頭 8 ビットが 127（127.0.0.0/8）の場合
  const ipv4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1).map(Number);
    if (octets.every((o) => o >= 0 && o <= 255) && octets[0] === 127) {
      return true;
    }
  }

  // 4. ホストが IPv6 の [::1] の場合 (WHATWG URL 解析で圧縮表記に正規化される)
  if (hostname === '[::1]') {
    return true;
  }

  return false;
}
