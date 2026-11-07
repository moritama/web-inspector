/**
 * Web Technology & Security Inspector
 * Public Suffix List (PSL) パーサー・コード生成・上流取得モジュール (scripts/advisories/lib/psl.mjs)
 *
 * 【役割】
 * - 週次バッチ (fetch-upstream.mjs) で Public Suffix List を取得し data/psl/public_suffix_list.dat に保存する。
 * - ビルド・カタログ生成時 (generate-spec-catalog.mjs) に data/psl/public_suffix_list.dat から
 *   日本の地域型ドメイン (tokyo.jp 等)・都道府県ドメイン・複合 ccTLD・Private Suffix を含む
 *   src/security/psl-rules.generated.ts を決定的に生成する。
 * - スナップショットが未取得の環境（夜間無人モード等）では、警告を出してフォールバック一覧を使用し、
 *   ビルドを止めない (v1.7.0 T13 / DOC-12)。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, '..', '..', '..');

export const PSL_UPSTREAM_URL = 'https://publicsuffix.org/list/public_suffix_list.dat';
export const PSL_DIR = path.join(ROOT_DIR, 'data', 'psl');
export const PSL_SNAPSHOT_PATH = path.join(PSL_DIR, 'public_suffix_list.dat');
export const PSL_GENERATED_TS_PATH = path.join(ROOT_DIR, 'src', 'security', 'psl-rules.generated.ts');

/**
 * スナップショット不在時に使用するフォールバックサフィックス一覧。
 * 従来の手書き一覧 (43件) に加え、日本の地域型・都道府県ドメイン (tokyo.jp 等) を含む。
 */
export const FALLBACK_PUBLIC_SUFFIXES = [
  // 日本の属性型・地域型JPドメイン
  'co.jp',
  'ne.jp',
  'or.jp',
  'ac.jp',
  'go.jp',
  'ed.jp',
  'gr.jp',
  'ad.jp',
  'lg.jp',
  // 日本の都道府県型JPドメイン (47都道府県)
  'hokkaido.jp',
  'aomori.jp',
  'iwate.jp',
  'miyagi.jp',
  'akita.jp',
  'yamagata.jp',
  'fukushima.jp',
  'ibaraki.jp',
  'tochigi.jp',
  'gunma.jp',
  'saitama.jp',
  'chiba.jp',
  'tokyo.jp',
  'kanagawa.jp',
  'niigata.jp',
  'toyama.jp',
  'ishikawa.jp',
  'fukui.jp',
  'yamanashi.jp',
  'nagano.jp',
  'gifu.jp',
  'shizuoka.jp',
  'aichi.jp',
  'mie.jp',
  'shiga.jp',
  'kyoto.jp',
  'osaka.jp',
  'hyogo.jp',
  'nara.jp',
  'wakayama.jp',
  'tottori.jp',
  'shimane.jp',
  'okayama.jp',
  'hiroshima.jp',
  'yamaguchi.jp',
  'tokushima.jp',
  'kagawa.jp',
  'ehime.jp',
  'kochi.jp',
  'fukuoka.jp',
  'saga.jp',
  'nagasaki.jp',
  'kumamoto.jp',
  'oita.jp',
  'miyazaki.jp',
  'kagoshima.jp',
  'okinawa.jp',
  // 日本の政令指定都市型JPドメイン
  'kawasaki.jp',
  'kitakyushu.jp',
  'kobe.jp',
  'nagoya.jp',
  'sapporo.jp',
  'sendai.jp',
  'yokohama.jp',
  // 海外の代表的な複合ccTLD
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'me.uk',
  'ltd.uk',
  'plc.uk',
  'net.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'co.nz',
  'net.nz',
  'org.nz',
  'co.kr',
  'or.kr',
  'ne.kr',
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'com.tw',
  'org.tw',
  'net.tw',
  'com.hk',
  'org.hk',
  'com.sg',
  'com.br',
  'net.br',
  'org.br',
  'co.in',
  'net.in',
  'org.in',
  'co.za',
  'com.my',
  'com.mx',
  'com.ar',
  // 代表的なホスティング / CDN の Private Suffix
  'github.io',
  'githubusercontent.com',
  'gitlab.io',
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'workers.dev',
  'web.app',
  'firebaseapp.com',
  'appspot.com',
  'cloudfront.net',
  's3.amazonaws.com',
  'amazonaws.com',
  'azurewebsites.net',
  'herokuapp.com',
  'onrender.com',
];

export const FALLBACK_WILDCARDS = [
  'kawasaki.jp',
  'kitakyushu.jp',
  'kobe.jp',
  'nagoya.jp',
  'sapporo.jp',
  'sendai.jp',
  'yokohama.jp',
];

export const FALLBACK_EXCEPTIONS = [
  'city.kawasaki.jp',
  'city.kitakyushu.jp',
  'city.kobe.jp',
  'city.nagoya.jp',
  'city.sapporo.jp',
  'city.sendai.jp',
  'city.yokohama.jp',
  'metro.tokyo.jp',
];

/**
 * 文字列リストを文字数の降順・辞書順で決定的にソートし重複を排除する
 */
export function sortSuffixesDeterministically(list) {
  return Array.from(new Set(list.map((s) => String(s).trim().toLowerCase()).filter(Boolean))).sort(
    (a, b) => b.length - a.length || a.localeCompare(b)
  );
}

/**
 * Public Suffix List (public_suffix_list.dat) 形式のテキストを解析する。
 *
 * - `//` で始まるコメント行と空行は無視する。
 * - `!foo.bar` は例外ルール (exceptions) として抽出する。
 * - `*.foo.bar` はワイルドカードルール (wildcards) として抽出し、`foo.bar` 自体も suffixes に含める。
 * - ドットを含む2ラベル以上のルール (`co.jp`, `tokyo.jp`, `github.io` 等) を suffixes として抽出する。
 * - ドットを含まない単一ラベルTLD (`jp`, `com` 等) は tlds として抽出する。
 *
 * @param {string} rawText PSL 形式のテキスト
 * @returns {{ suffixes: string[], wildcards: string[], exceptions: string[], tlds: string[] }}
 */
export function parsePslText(rawText) {
  const suffixes = [];
  const wildcards = [];
  const exceptions = [];
  const tlds = [];

  if (typeof rawText !== 'string' || !rawText.trim()) {
    return { suffixes: [], wildcards: [], exceptions: [], tlds: [] };
  }

  const lines = rawText.split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    // 空白文字以降は仕様上コメントまたは無視対象
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
    suffixes: sortSuffixesDeterministically(suffixes),
    wildcards: sortSuffixesDeterministically(wildcards),
    exceptions: sortSuffixesDeterministically(exceptions),
    tlds: sortSuffixesDeterministically(tlds),
  };
}

/**
 * PSL ルールセットを用いてホスト名から Public Suffix (eTLD) と登録可能ドメイン (eTLD+1) を算出する。
 *
 * @param {string} rawHostname
 * @param {{ suffixes?: readonly string[], wildcards?: readonly string[], exceptions?: readonly string[] }} [rules]
 * @returns {{ publicSuffix: string, registrableDomain: string }}
 */
export function resolveRegistrableDomainWithPsl(rawHostname, rules) {
  const host = String(rawHostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host) {
    return { publicSuffix: '', registrableDomain: '' };
  }

  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
    host.includes(':') ||
    host.startsWith('[')
  ) {
    return { publicSuffix: '', registrableDomain: host };
  }

  const parts = host.split('.');
  if (parts.length < 2) {
    return { publicSuffix: '', registrableDomain: host };
  }

  const suffixes = rules?.suffixes || FALLBACK_PUBLIC_SUFFIXES;
  const wildcards = rules?.wildcards || FALLBACK_WILDCARDS;
  const exceptions = rules?.exceptions || FALLBACK_EXCEPTIONS;

  // 1. 例外ルール (!city.kawasaki.jp 等) の確認
  for (const exc of exceptions) {
    if (host === exc || host.endsWith('.' + exc)) {
      const excParts = exc.split('.');
      // 例外ルールの最上位ラベルを除いた部分が Public Suffix になる
      const suffixParts = excParts.slice(1);
      const publicSuffix = suffixParts.join('.');
      const registrablePartsCount = suffixParts.length + 1;
      const registrableDomain =
        parts.length >= registrablePartsCount
          ? parts.slice(parts.length - registrablePartsCount).join('.')
          : host;
      return { publicSuffix, registrableDomain };
    }
  }

  // 2. ワイルドカードルール (*.kawasaki.jp 等) の確認
  for (const wc of wildcards) {
    if (host.endsWith('.' + wc)) {
      const wcParts = wc.split('.');
      const suffixPartsCount = wcParts.length + 1;
      if (parts.length >= suffixPartsCount) {
        const publicSuffix = parts.slice(parts.length - suffixPartsCount).join('.');
        const registrablePartsCount = suffixPartsCount + 1;
        const registrableDomain =
          parts.length >= registrablePartsCount
            ? parts.slice(parts.length - registrablePartsCount).join('.')
            : host;
        return { publicSuffix, registrableDomain };
      }
    }
  }

  // 3. 複合サフィックス (co.jp, tokyo.jp, github.io 等) の最長一致確認
  const sortedSuffixes = sortSuffixesDeterministically(suffixes);
  for (const suffix of sortedSuffixes) {
    if (host === suffix) {
      return { publicSuffix: suffix, registrableDomain: host };
    }
    if (host.endsWith('.' + suffix)) {
      const suffixParts = suffix.split('.');
      const registrablePartsCount = suffixParts.length + 1;
      if (parts.length >= registrablePartsCount) {
        const registrableDomain = parts.slice(parts.length - registrablePartsCount).join('.');
        return { publicSuffix: suffix, registrableDomain };
      }
      return { publicSuffix: suffix, registrableDomain: host };
    }
  }

  // 4. 通常の単一ラベル TLD (.com, .org, .jp 等)
  const publicSuffix = parts[parts.length - 1];
  const registrableDomain = parts.slice(parts.length - 2).join('.');
  return { publicSuffix, registrableDomain };
}

/**
 * スナップショットファイル (data/psl/public_suffix_list.dat) から PSL ルールを読み込む。
 * スナップショットが存在しない場合は警告を出してフォールバック一覧を返す。
 *
 * @param {{ snapshotPath?: string, warn?: (msg: string) => void }} [options]
 */
export function loadOrFallbackPslRules(options = {}) {
  const snapshotPath = options.snapshotPath || PSL_SNAPSHOT_PATH;
  const warn = options.warn ?? ((msg) => console.warn(msg));

  if (fs.existsSync(snapshotPath)) {
    const raw = fs.readFileSync(snapshotPath, 'utf-8');
    const parsed = parsePslText(raw);
    if (parsed.suffixes.length > 0) {
      return {
        source: 'snapshot',
        ...parsed,
      };
    }
  }

  warn(
    `[psl] スナップショット (${path.relative(ROOT_DIR, snapshotPath)}) が未取得のため、手書きのフォールバック PSL 一覧を使用します。`
  );
  return {
    source: 'fallback',
    suffixes: sortSuffixesDeterministically(FALLBACK_PUBLIC_SUFFIXES),
    wildcards: sortSuffixesDeterministically(FALLBACK_WILDCARDS),
    exceptions: sortSuffixesDeterministically(FALLBACK_EXCEPTIONS),
    tlds: [],
  };
}

/**
 * src/security/psl-rules.generated.ts の TypeScript ソースコード文字列を生成する
 *
 * @param {{ source: 'snapshot' | 'fallback', suffixes: string[], wildcards: string[], exceptions: string[] }} rulesResult
 * @returns {string}
 */
export function renderPslGeneratedTs(rulesResult) {
  const suffixes = sortSuffixesDeterministically(rulesResult.suffixes || []);
  const wildcards = sortSuffixesDeterministically(rulesResult.wildcards || []);
  const exceptions = sortSuffixesDeterministically(rulesResult.exceptions || []);
  const source = rulesResult.source === 'snapshot' ? 'snapshot' : 'fallback';

  return `/**
 * Web Technology & Security Inspector
 * 自動生成された Public Suffix List (PSL) ルール定義 (src/security/psl-rules.generated.ts)
 *
 * ※このファイルは scripts/advisories/lib/psl.mjs (または npm run spec:generate) により自動生成されます。
 * 直接手動で編集しないでください (v1.7.0 T13 / DOC-12)。
 */

export const PSL_SOURCE: 'snapshot' | 'fallback' = '${source}';

export const PUBLIC_SUFFIX_LIST: readonly string[] = ${JSON.stringify(suffixes, null, 2)};

export const PUBLIC_SUFFIX_WILDCARDS: readonly string[] = ${JSON.stringify(wildcards, null, 2)};

export const PUBLIC_SUFFIX_EXCEPTIONS: readonly string[] = ${JSON.stringify(exceptions, null, 2)};
`;
}

/**
 * PSL モジュール (src/security/psl-rules.generated.ts) を生成して書き出す
 *
 * @param {{ snapshotPath?: string, outputPath?: string, warn?: (msg: string) => void }} [options]
 */
export function writeGeneratedPslModule(options = {}) {
  const snapshotPath = options.snapshotPath || PSL_SNAPSHOT_PATH;
  const outputPath = options.outputPath || PSL_GENERATED_TS_PATH;
  const warn = options.warn ?? ((msg) => console.warn(msg));

  const rulesResult = loadOrFallbackPslRules({ snapshotPath, warn });
  const content = renderPslGeneratedTs(rulesResult);

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const current = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, 'utf-8') : null;
  if (current !== content) {
    fs.writeFileSync(outputPath, content, 'utf-8');
  }
  return { ...rulesResult, outputPath, updated: current !== content };
}

/**
 * 上流の Public Suffix List を取得して data/psl/public_suffix_list.dat に保存する
 *
 * @param {{
 *   fetchText?: (url: string) => Promise<string>,
 *   fetchImpl?: typeof fetch,
 *   snapshotPath?: string,
 *   url?: string,
 * }} [options]
 */
export async function fetchPslSnapshot(options = {}) {
  const url = options.url || PSL_UPSTREAM_URL;
  const snapshotPath = options.snapshotPath || PSL_SNAPSHOT_PATH;
  const fetchImpl = options.fetchImpl || globalThis.fetch;

  const fetchText =
    options.fetchText ||
    (async (targetUrl) => {
      const res = await fetchImpl(targetUrl, {
        headers: {
          Accept: 'text/plain',
          'User-Agent': 'web-inspector-advisory-sync/1.0 (+https://github.com/moritama/web-inspector)',
        },
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} for ${targetUrl}`);
      }
      return await res.text();
    });

  const text = await fetchText(url);
  const parsed = parsePslText(text);
  if (parsed.suffixes.length < 10 || !parsed.suffixes.includes('co.jp')) {
    throw new Error('Invalid PSL data: expected suffixes (e.g. co.jp) not found');
  }

  fs.mkdirSync(path.dirname(snapshotPath), { recursive: true });
  fs.writeFileSync(snapshotPath, text.endsWith('\n') ? text : `${text}\n`, 'utf-8');
  return {
    snapshotPath,
    suffixCount: parsed.suffixes.length,
    wildcardCount: parsed.wildcards.length,
    exceptionCount: parsed.exceptions.length,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const res = writeGeneratedPslModule();
  console.log(
    `[psl] 生成完了: ${path.relative(ROOT_DIR, res.outputPath)} (source: ${res.source}, suffixes: ${res.suffixes.length})`
  );
}
