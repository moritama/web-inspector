/**
 * Web Technology & Security Inspector
 * 外部通信先・サードパーティドメイン分析エンジン (src/security/domain-analyzer.ts) - IMP-11
 * 
 * Public Suffix List (PSL) に基づき、単純な末尾2階層分割ではなく
 * 登録可能ドメイン（eTLD+1）を正確に判定して、通信先を First-Party / Third-Party に分類します。
 */

import {
  DomainPartyType,
  ExternalConnectionItem,
  ExternalConnectionsAnalysis,
  ExternalServiceCategory,
} from '../shared/types';
import {
  PSL_SOURCE,
  PUBLIC_SUFFIX_EXCEPTIONS,
  PUBLIC_SUFFIX_LIST,
  PUBLIC_SUFFIX_WILDCARDS,
} from './psl-rules.generated';

export {
  PSL_SOURCE,
  PUBLIC_SUFFIX_EXCEPTIONS,
  PUBLIC_SUFFIX_LIST,
  PUBLIC_SUFFIX_WILDCARDS,
};

/**
 * Public Suffix List (PSL) ルールセット型定義 (v1.7.0 T13 / DOC-12)
 */
export interface PslRuleSet {
  suffixes: readonly string[];
  wildcards?: readonly string[];
  exceptions?: readonly string[];
  tlds?: readonly string[];
}

/**
 * サフィックス配列を文字数降順・辞書順で決定的にソートし重複を排除する
 */
function sortSuffixes(list: readonly string[]): string[] {
  return Array.from(new Set(list.map((s) => String(s).trim().toLowerCase()).filter(Boolean))).sort(
    (a, b) => b.length - a.length || a.localeCompare(b)
  );
}

/**
 * Public Suffix List (public_suffix_list.dat) 形式のテキストを解析し、ルールセットを生成する (v1.7.0 T13 / DOC-12)
 *
 * @param rawText PSL形式の文字列
 * @returns PslRuleSet
 */
export function parsePslText(rawText: string): PslRuleSet {
  const suffixes: string[] = [];
  const wildcards: string[] = [];
  const exceptions: string[] = [];
  const tlds: string[] = [];

  if (typeof rawText !== 'string' || !rawText.trim()) {
    return { suffixes: [], wildcards: [], exceptions: [], tlds: [] };
  }

  const lines = rawText.split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    const token = trimmed.split(/\s+/)[0].toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!token) continue;

    if (token.startsWith('!')) {
      const exc = token.slice(1).replace(/^\.+/, '');
      if (exc) exceptions.push(exc);
      continue;
    }

    if (token.startsWith('*.')) {
      const base = token.slice(2).replace(/^\.+/, '');
      if (base) {
        wildcards.push(base);
        if (base.includes('.')) {
          suffixes.push(base);
        }
      }
      continue;
    }

    if (token.includes('.')) {
      suffixes.push(token);
    } else {
      tlds.push(token);
    }
  }

  return {
    suffixes: sortSuffixes(suffixes),
    wildcards: sortSuffixes(wildcards),
    exceptions: sortSuffixes(exceptions),
    tlds: sortSuffixes(tlds),
  };
}

// ホスト名判定結果のインメモリキャッシュ (高速化)
const domainCache = new Map<
  string,
  { registrableDomain: string; publicSuffix: string; isIpOrLocal: boolean }
>();

/**
 * ホスト名がIPアドレス（IPv4/IPv6）またはローカルホストか判定
 */
export function isIpOrLocalHost(hostname: string): boolean {
  const clean = hostname.trim().toLowerCase();
  if (clean === 'localhost' || clean.endsWith('.local') || clean.endsWith('.localhost')) {
    return true;
  }
  // IPv4判定 (例: 127.0.0.1, 192.168.1.1)
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) {
    return true;
  }
  // IPv6判定 (コロンを含む)
  if (clean.includes(':') || clean.startsWith('[') || /^[0-9a-f:]+$/i.test(clean)) {
    return true;
  }
  return false;
}

/**
 * カスタムPSL指定を正規化された PslRuleSet に変換する
 */
function normalizePslRules(customPsl?: PslRuleSet | readonly string[] | string): PslRuleSet {
  if (!customPsl) {
    return {
      suffixes: PUBLIC_SUFFIX_LIST,
      wildcards: PUBLIC_SUFFIX_WILDCARDS,
      exceptions: PUBLIC_SUFFIX_EXCEPTIONS,
    };
  }
  if (typeof customPsl === 'string') {
    return parsePslText(customPsl);
  }
  if (Array.isArray(customPsl)) {
    return {
      suffixes: sortSuffixes(customPsl as readonly string[]),
      wildcards: [],
      exceptions: [],
    };
  }
  const ruleSet = customPsl as PslRuleSet;
  return {
    suffixes: sortSuffixes(ruleSet.suffixes || []),
    wildcards: sortSuffixes(ruleSet.wildcards || []),
    exceptions: sortSuffixes(ruleSet.exceptions || []),
    tlds: ruleSet.tlds ? sortSuffixes(ruleSet.tlds) : undefined,
  };
}

/**
 * ホスト名から Public Suffix List に基づく登録可能ドメイン (eTLD+1) を抽出する (Rev.2.1 IMP-11 / v1.7.0 DOC-12)
 *
 * @param rawHostname 入力ホスト名 (例: "api.sub.example.co.jp", "foo.tokyo.jp")
 * @param customPsl テスト等で使用するカスタムPSLルールセット・PSLテキスト・サフィックス配列 (省略時はビルド時生成のPSLを使用)
 * @returns { registrableDomain: "example.co.jp", publicSuffix: "co.jp", isIpOrLocal: false }
 */
export function parseRegistrableDomain(
  rawHostname: string,
  customPsl?: PslRuleSet | readonly string[] | string
): {
  registrableDomain: string;
  publicSuffix: string;
  isIpOrLocal: boolean;
} {
  const hostname = rawHostname.trim().toLowerCase().replace(/\.$/, '');
  const useCache = customPsl === undefined;

  if (useCache && domainCache.has(hostname)) {
    return domainCache.get(hostname)!;
  }

  // 1. IPアドレスまたはローカルホストの場合
  if (isIpOrLocalHost(hostname)) {
    const result = { registrableDomain: hostname, publicSuffix: '', isIpOrLocal: true };
    if (useCache) domainCache.set(hostname, result);
    return result;
  }

  const parts = hostname.split('.');
  if (parts.length <= 1) {
    const result = { registrableDomain: hostname, publicSuffix: '', isIpOrLocal: true };
    if (useCache) domainCache.set(hostname, result);
    return result;
  }

  const rules = normalizePslRules(customPsl);
  const exceptions = rules.exceptions || [];
  const wildcards = rules.wildcards || [];
  const suffixes = rules.suffixes || [];

  // 2. 例外ルール (!city.kawasaki.jp, !metro.tokyo.jp 等) の判定
  for (const exc of exceptions) {
    if (hostname === exc || hostname.endsWith(`.${exc}`)) {
      const excParts = exc.split('.');
      const suffixParts = excParts.slice(1);
      const publicSuffix = suffixParts.join('.');
      const registrablePartsCount = suffixParts.length + 1;
      const registrableDomain =
        parts.length >= registrablePartsCount
          ? parts.slice(parts.length - registrablePartsCount).join('.')
          : hostname;
      const result = { registrableDomain, publicSuffix, isIpOrLocal: false };
      if (useCache) domainCache.set(hostname, result);
      return result;
    }
  }

  // 3. ワイルドカードルール (*.kawasaki.jp 等) の判定
  for (const wc of wildcards) {
    if (hostname.endsWith(`.${wc}`)) {
      const wcParts = wc.split('.');
      const suffixPartsCount = wcParts.length + 1;
      if (parts.length >= suffixPartsCount) {
        const publicSuffix = parts.slice(parts.length - suffixPartsCount).join('.');
        const registrablePartsCount = suffixPartsCount + 1;
        const registrableDomain =
          parts.length >= registrablePartsCount
            ? parts.slice(parts.length - registrablePartsCount).join('.')
            : hostname;
        const result = { registrableDomain, publicSuffix, isIpOrLocal: false };
        if (useCache) domainCache.set(hostname, result);
        return result;
      }
    }
  }

  // 4. 複合Public Suffix（.co.jp, .tokyo.jp, .com.au等）との最長一致判定
  for (const suffix of suffixes) {
    if (hostname === suffix || hostname.endsWith(`.${suffix}`)) {
      const suffixParts = suffix.split('.');
      const domainIndex = parts.length - suffixParts.length - 1;
      if (domainIndex >= 0) {
        const registrableDomain = parts.slice(domainIndex).join('.');
        const result = { registrableDomain, publicSuffix: suffix, isIpOrLocal: false };
        if (useCache) domainCache.set(hostname, result);
        return result;
      }
      // サフィックスそのもの（例: co.jp, tokyo.jp）
      const result = { registrableDomain: hostname, publicSuffix: suffix, isIpOrLocal: false };
      if (useCache) domainCache.set(hostname, result);
      return result;
    }
  }

  // 5. 一般的な単一TLD（.com, .jp, .org等）の場合: 末尾2ラベルがeTLD+1
  const publicSuffix = parts[parts.length - 1];
  const registrableDomain = parts.slice(-2).join('.');
  const result = { registrableDomain, publicSuffix, isIpOrLocal: false };
  if (useCache) domainCache.set(hostname, result);
  return result;
}

/**
 * ホスト名と登録可能ドメインからサービスの用途カテゴリを推定分類する (Rev.2.1 IMP-11 / 10.5)
 */
export function inferServiceCategory(hostname: string, registrableDomain: string): ExternalServiceCategory {
  const h = hostname.toLowerCase();
  const d = registrableDomain.toLowerCase();

  // アナリティクス / タグ管理
  if (
    h.includes('analytics') ||
    h.includes('googletagmanager') ||
    h.includes('segment') ||
    h.includes('hotjar') ||
    h.includes('clarity.ms') ||
    d === 'google-analytics.com' ||
    d === 'googletagmanager.com' ||
    d === 'mixpanel.com'
  ) {
    return 'analytics';
  }

  // 広告 / マーケティング
  if (
    h.includes('doubleclick') ||
    h.includes('adservice') ||
    h.includes('googlesyndication') ||
    d === 'doubleclick.net' ||
    d === 'criteo.com' ||
    d === 'adroll.com'
  ) {
    return 'advertising';
  }

  // Webフォント
  if (
    h === 'fonts.googleapis.com' ||
    h === 'fonts.gstatic.com' ||
    h.includes('typekit') ||
    d === 'typekit.net' ||
    d === 'fontawesome.com'
  ) {
    return 'fonts';
  }

  // CDN / 静的アセット配信
  if (
    h.includes('cdnjs') ||
    h.includes('jsdelivr') ||
    h.includes('unpkg') ||
    h.includes('static') ||
    h.includes('assets') ||
    d === 'cloudflare.com' ||
    d === 'fastly.net' ||
    d === 'akamai.net' ||
    d === 'cloudfront.net'
  ) {
    return 'cdn';
  }

  // SNSウィジェット・埋め込み
  if (
    h.includes('twitter.com') ||
    h.includes('facebook.net') ||
    h.includes('line.me') ||
    h.includes('instagram.com') ||
    d === 'twimg.com'
  ) {
    return 'social';
  }

  // 外部API
  if (h.startsWith('api.') || h.includes('-api.') || h.includes('.api.')) {
    return 'api';
  }

  return 'other';
}

/**
 * 補助関数: 公開エイリアス
 */
export const parsePublicSuffixAndRegistrableDomain = parseRegistrableDomain;
export const guessServiceCategory = (hostname: string, registrableDomain?: string): ExternalServiceCategory => {
  const regDomain = registrableDomain || parseRegistrableDomain(hostname).registrableDomain;
  return inferServiceCategory(hostname, regDomain);
};

/**
 * 接続先ホストとページURLから PartyType (first-party / third-party / local) を判定する (Rev.2.1 IMP-11 / 10.3)
 */
export function determinePartyType(resHostnameOrUrl: string, pageUrl: string): DomainPartyType {
  let resHost = resHostnameOrUrl;
  try {
    if (resHostnameOrUrl.includes('://')) {
      resHost = new URL(resHostnameOrUrl).hostname;
    }
  } catch {
    resHost = resHostnameOrUrl;
  }

  let pageHost = pageUrl;
  try {
    if (pageUrl.includes('://')) {
      pageHost = new URL(pageUrl).hostname;
    }
  } catch {
    pageHost = pageUrl;
  }

  const resInfo = parseRegistrableDomain(resHost);
  const pageInfo = parseRegistrableDomain(pageHost);

  if (resInfo.isIpOrLocal) {
    return 'local';
  }
  if (resInfo.registrableDomain && pageInfo.registrableDomain && resInfo.registrableDomain === pageInfo.registrableDomain) {
    return 'first-party';
  }
  return 'third-party';
}

/**
 * ページURLと収集されたリソースURL群から、外部通信先・サードパーティ総合分析を実行する (Rev.2.1 IMP-11)
 *
 * @param pageUrl 調査対象ページのURL
 * @param resourceUrls 検出されたスクリプト、スタイル、画像、通信先URLリスト
 * @returns ExternalConnectionsAnalysis
 */
export function analyzeExternalConnections(
  pageUrl: string,
  resourceUrls: string[]
): ExternalConnectionsAnalysis {
  // 引数が配列でない/文字列でない場合の安全な防御処理
  if (Array.isArray(pageUrl) && typeof resourceUrls === 'string') {
    // 引数順が逆渡された場合の救済
    const tmp = pageUrl;
    pageUrl = resourceUrls;
    resourceUrls = tmp;
  }

  let pageHost = '';
  try {
    pageHost = typeof pageUrl === 'string' && pageUrl.includes('://') ? new URL(pageUrl).hostname : String(pageUrl || '');
  } catch {
    pageHost = String(pageUrl || '');
  }

  const pageInfo = parseRegistrableDomain(pageHost);

  // ホスト名ごとのリソース集約
  const hostMap = new Map<string, { count: number; sampleUrls: string[] }>();

  if (Array.isArray(resourceUrls)) {
    for (const rawUrl of resourceUrls) {
      if (!rawUrl || typeof rawUrl !== 'string') continue;

      try {
        const trimmed = rawUrl.trim();
        // http:// または https:// または // (プロトコル相対) で始まる絶対URLのみを対象とする
        if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://') && !trimmed.startsWith('//')) {
          continue;
        }

        const u = new URL(trimmed.startsWith('//') ? `https:${trimmed}` : trimmed, pageUrl);
        const resHost = u.hostname.toLowerCase();
        if (!resHost) continue;

        const current = hostMap.get(resHost) || { count: 0, sampleUrls: [] };
        current.count += 1;
        if (current.sampleUrls.length < 3 && !current.sampleUrls.includes(rawUrl)) {
          current.sampleUrls.push(rawUrl);
        }
        hostMap.set(resHost, current);
      } catch {
        // パース不可なURLはスキップ
      }
    }
  }

  let firstPartyCount = 0;
  let thirdPartyCount = 0;
  const categoryBreakdown: Record<ExternalServiceCategory, number> = {
    cdn: 0,
    analytics: 0,
    advertising: 0,
    fonts: 0,
    social: 0,
    api: 0,
    other: 0,
  };

  const connections: ExternalConnectionItem[] = [];

  for (const [resHost, data] of hostMap) {
    const resInfo = parseRegistrableDomain(resHost);

    let partyType: DomainPartyType = 'third-party';
    if (resInfo.isIpOrLocal) {
      partyType = 'local';
    } else if (resInfo.registrableDomain === pageInfo.registrableDomain) {
      partyType = 'first-party';
      firstPartyCount++;
    } else {
      partyType = 'third-party';
      thirdPartyCount++;
    }

    const category = inferServiceCategory(resHost, resInfo.registrableDomain);
    categoryBreakdown[category]++;

    connections.push({
      hostname: resHost,
      registrableDomain: resInfo.registrableDomain,
      publicSuffix: resInfo.publicSuffix,
      partyType,
      category,
      resourceCount: data.count,
      sampleUrls: data.sampleUrls,
    });
  }

  // 接続数降順ソート
  connections.sort((a, b) => b.resourceCount - a.resourceCount);

  return {
    totalConnections: connections.length,
    firstPartyCount,
    thirdPartyCount,
    categoryBreakdown,
    connections,
  };
}
