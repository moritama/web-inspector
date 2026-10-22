/**
 * Web Technology & Security Inspector
 * 安定ID・正規化処理エンジン (src/shared/identity.ts) - IMP-07
 * 
 * 表記揺れ（ホスト名大文字小文字、ポート、ドメイン先頭ドット等）によるFinding IDの変動を防ぎ、
 * 差分比較（Diff）や許容・除外設定（Exceptions）を長期的に安定動作させるための正規化・ID生成機構。
 */

import { FindingIdentity } from './types';

/**
 * 安定ID用のURL正規化
 * - スキーム・ホスト名を小文字化
 * - デフォルトポート（http:80, https:443）を省略
 * - フラグメント（#hash）を除外
 *
 * @param urlStr 入力URL文字列
 * @returns 正規化されたURL文字列
 */
export function normalizeUrlForIdentity(urlStr: string): string {
  try {
    const parsed = new URL(urlStr);
    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();

    // デフォルトポートの除外判定
    let port = parsed.port;
    if ((protocol === 'http:' && port === '80') || (protocol === 'https:' && port === '443')) {
      port = '';
    }

    const hostPart = port ? `${hostname}:${port}` : hostname;
    const pathname = parsed.pathname || '/';
    const search = parsed.search || '';

    return `${protocol}//${hostPart}${pathname}${search}`;
  } catch {
    // パース不能な不正URLの場合は小文字化・トリムでフォールバック
    return urlStr.trim().toLowerCase();
  }
}

/**
 * Cookie Domainの正規化
 * - 先頭のドット（.）を除去
 * - 小文字化
 *
 * @param domain Cookieドメイン文字列
 * @returns 正規化ドメイン
 */
export function normalizeCookieDomain(domain: string): string {
  if (!domain) return '';
  return domain.trim().toLowerCase().replace(/^\.+/, '');
}

/**
 * Cookie固有のリソースキー生成
 * - Host-only と Domain Cookie を厳格に区別
 * - Path、Cookie名の大文字小文字は仕様に従い保持
 * - Partition Key（CHIPS）が存在する場合は識別子に含める
 *
 * @param name Cookie名
 * @param domain ドメイン
 * @param path パス
 * @param hostOnly Host-only属性かどうか
 * @param partitionKey パーティションキー（存在する場合）
 * @returns リソースキー文字列
 */
export function buildCookieResourceKey(
  name: string,
  domain: string,
  path: string,
  hostOnly: boolean,
  partitionKey?: string | null
): string {
  const normDomain = normalizeCookieDomain(domain);
  const scopeType = hostOnly ? 'host' : 'domain';
  const cleanPath = path || '/';
  const baseKey = `${scopeType}:${normDomain}:${cleanPath}:${name}`;

  if (partitionKey) {
    return `${baseKey}:part=${partitionKey}`;
  }
  return baseKey;
}

/**
 * 32ビット FNV-1a ハッシュアルゴリズム
 * 外部ライブラリ依存ゼロで、高速かつ完全に決定論的なハッシュ文字列を生成
 */
function fnv1a32(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    // 32ビット整数乗算: hash * 0x01000193
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * 安定したFinding ID（識別子）を生成する (IMP-07)
 * - 日時、Cookie値、認証情報は一切含めず、決定論的に算出
 * - 仕様バージョンプレフィックス 'find_' を付与
 *
 * @param identity FindingIdentity
 * @returns 安定ハッシュID (例: 'find_a1b2c3d4_e5f6g7h8')
 */
export function generateFindingId(identity: FindingIdentity): string {
  const parts = [
    identity.ruleId,
    identity.origin.trim().toLowerCase(),
    identity.resourceKey,
    identity.targetKey,
    identity.scopeKey || '',
  ];

  const payload = parts.join('|');
  const hash = fnv1a32(payload);
  // より衝突に強い16文字ハッシュにするため、逆順シグネチャも結合
  const reverseHash = fnv1a32(payload.split('').reverse().join(''));

  return `find_${hash}${reverseHash}`;
}

/**
 * SecurityCheckResult から安定したFinding IDを生成するヘルパー (Rev.2.1 IMP-07 / IMP-10)
 */
export function generateFindingIdFromCheck(
  checkId: string,
  urlStr: string,
  targetKey = ''
): string {
  let origin = '';
  try {
    const u = new URL(urlStr);
    origin = `${u.protocol}//${u.hostname}`;
  } catch {
    origin = urlStr;
  }

  return generateFindingId({
    ruleId: checkId,
    origin,
    resourceKey: normalizeUrlForIdentity(urlStr),
    targetKey: targetKey || checkId,
    scopeKey: 'security-check',
  });
}
