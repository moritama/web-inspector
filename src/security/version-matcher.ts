/**
 * Web Technology & Security Inspector
 * バージョン比較・セマンティック範囲判定ユーティリティ (src/security/version-matcher.ts)
 */

/** 解析済みバージョン構造 */
export interface ParsedVersion {
  /** [major, minor, patch, build] の4要素数値配列 */
  parts: [number, number, number, number];
  /** SemVer 2.0 プレリリース識別子配列（正式版およびディストリ印付きバージョンの場合は null） */
  pre: (string | number)[] | null;
}

/**
 * ワイルドカード字句の正規表現
 * 字句全体が `/^\d+(\.\d+)*\.(x|\*)$/i` に一致するときだけワイルドカードとして扱う
 */
const WILDCARD_TOKEN_RE = /^\d+(\.\d+)*\.(x|\*)$/i;

/**
 * 比較器で解釈可能なプレリリースタグの正規表現
 * `-next.0`, `-next.0.0.0`, `-rc.1`, `-rc1`, `-beta.2`, `-alpha.1` 等を受理し、
 * `-nxt` のような壊れた字句は拒否する
 */
const PRERELEASE_RE = /^(alpha|beta|rc|next|pre|preview|dev|canary|nightly|experimental)(\d+)?(?:\.([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/i;

/**
 * Linuxディストリビューション固有のパッケージバージョン表記（例: "2.4.52-1ubuntu4", "1.18.0-0ubuntu1.4", "2.4.6-97.el7"）かを検出する (Rev.2.1 IMP-06 / 5.6)
 *
 * @param version バージョン文字列
 * @returns boolean
 */
export function isLinuxPackageVersion(version: string | null | undefined): boolean {
  if (!version) return false;
  const lower = version.toLowerCase().trim();
  return /[-+~]([0-9]+)?(ubuntu|deb|debian|el[0-9]|rhel|amzn|redhat|centos|arch|alpine|suse|lp[0-9]|dfsg|fc[0-9]+)/i.test(lower)
    || /\.(?:el\d|fc\d|amzn\d)/i.test(lower);
}

/**
 * プレリリース文字列を SemVer 2.0 比較用の識別子配列に分解する。
 * 解釈できない壊れたプレリリース字句（例: `nxt`）の場合は null を返す。
 *
 * @param rawPre ハイフン以降のプレリリース文字列
 * @returns 識別子配列または null
 */
function parsePrereleaseIdentifiers(rawPre: string): (string | number)[] | null {
  const match = rawPre.match(PRERELEASE_RE);
  if (!match) return null;

  const tag = match[1].toLowerCase();
  const attachedDigits = match[2];
  const rest = match[3];

  const identifiers: (string | number)[] = [tag];
  if (attachedDigits !== undefined) {
    identifiers.push(parseInt(attachedDigits, 10));
  }
  if (rest !== undefined) {
    const tokens = rest.split('.');
    for (const token of tokens) {
      if (!token) return null;
      if (/^\d+$/.test(token)) {
        identifiers.push(parseInt(token, 10));
      } else {
        identifiers.push(token.toLowerCase());
      }
    }
  }

  return identifiers;
}

/**
 * バージョン文字列を数値パート（4要素）とプレリリース識別子へ分解する。
 * - 先頭の `v` / `v.` は無視する
 * - ビルドメタデータ (`+...`) は無視する
 * - Linux ディストリビューションのパッケージ印 (`-4ubuntu2.19`, `-1ubuntu1` 等) は
 *   プレリリースとして扱わず、正式版 (`pre: null`) として数値部のみ抽出する
 * - 解釈できない文字列や壊れたプレリリース字句 (`1.0.0-nxt` 等) は null を返す
 *
 * @param version バージョン文字列
 * @returns 解析済みバージョンまたは null
 */
export function parseVersion(version: string | null | undefined): ParsedVersion | null {
  if (!version || typeof version !== 'string') return null;

  const clean = version.trim().replace(/^v\.?/i, '');
  if (!clean) return null;

  // ディストリビューションの印はプレリリースとして扱わない（2.4.41-1ubuntu1 < 2.4.41 になるのを防ぐ）
  if (isLinuxPackageVersion(version)) {
    const distroMatch = clean.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?/);
    if (!distroMatch) return null;
    return {
      parts: [
        parseInt(distroMatch[1], 10),
        distroMatch[2] !== undefined ? parseInt(distroMatch[2], 10) : 0,
        distroMatch[3] !== undefined ? parseInt(distroMatch[3], 10) : 0,
        distroMatch[4] !== undefined ? parseInt(distroMatch[4], 10) : 0,
      ],
      pre: null,
    };
  }

  // ビルドメタデータ (+...) を検証して無視する
  let withoutBuild = clean;
  const plusIndex = clean.indexOf('+');
  if (plusIndex !== -1) {
    const buildMeta = clean.slice(plusIndex + 1);
    if (!/^[0-9A-Za-z.-]+$/.test(buildMeta)) return null;
    withoutBuild = clean.slice(0, plusIndex);
  }

  const baseMatch = withoutBuild.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$/);
  if (!baseMatch) return null;

  let pre: (string | number)[] | null = null;
  if (baseMatch[5] !== undefined) {
    pre = parsePrereleaseIdentifiers(baseMatch[5]);
    if (!pre) return null;
  }

  return {
    parts: [
      parseInt(baseMatch[1], 10),
      baseMatch[2] !== undefined ? parseInt(baseMatch[2], 10) : 0,
      baseMatch[3] !== undefined ? parseInt(baseMatch[3], 10) : 0,
      baseMatch[4] !== undefined ? parseInt(baseMatch[4], 10) : 0,
    ],
    pre,
  };
}

/**
 * バージョン番号文字列（例: "3.6.0", "4.3.1-beta"）を数値配列にパースする
 *
 * @param version バージョン文字列
 * @returns [major, minor, patch, build]
 */
export function parseVersionParts(version: string | null | undefined): number[] | null {
  const parsed = parseVersion(version);
  if (!parsed) return null;
  return [...parsed.parts];
}

/**
 * 解析済みの2つのバージョンを SemVer 2.0 の順序規則に従って比較する
 */
function compareParsedVersions(p1: ParsedVersion, p2: ParsedVersion): number {
  for (let i = 0; i < 4; i++) {
    const num1 = p1.parts[i] ?? 0;
    const num2 = p2.parts[i] ?? 0;
    if (num1 > num2) return 1;
    if (num1 < num2) return -1;
  }

  // 数値部分が同じ場合: SemVer 2.0 ではプレリリース版は正式版より優先度が低い (例: 3.5.0-rc1 < 3.5.0)
  if (p1.pre === null && p2.pre === null) return 0;
  if (p1.pre === null && p2.pre !== null) return 1;
  if (p1.pre !== null && p2.pre === null) return -1;

  const pre1 = p1.pre!;
  const pre2 = p2.pre!;
  const len = Math.max(pre1.length, pre2.length);

  for (let i = 0; i < len; i++) {
    const id1 = pre1[i];
    const id2 = pre2[i];
    if (id1 === undefined) return -1;
    if (id2 === undefined) return 1;
    if (id1 === id2) continue;

    const isNum1 = typeof id1 === 'number';
    const isNum2 = typeof id2 === 'number';

    if (isNum1 && isNum2) {
      return id1 > id2 ? 1 : -1;
    }
    // SemVer 2.0: 数値のみの識別子は非数値の識別子より常に優先度が低い
    if (isNum1 && !isNum2) return -1;
    if (!isNum1 && isNum2) return 1;

    return String(id1) > String(id2) ? 1 : -1;
  }

  return 0;
}

/**
 * 2つのバージョン番号を比較する
 *
 * @param v1 バージョン1
 * @param v2 バージョン2
 * @returns 1: v1 > v2, -1: v1 < v2, 0: v1 == v2
 */
export function compareVersions(v1: string, v2: string): number {
  const p1 = parseVersion(v1);
  const p2 = parseVersion(v2);

  if (!p1 && !p2) return 0;
  if (!p1) return -1;
  if (!p2) return 1;

  return compareParsedVersions(p1, p2);
}

/**
 * バージョンが指定された単一の比較条件（例: "< 4.3.1", ">= 3.0.0", "= 3.6.0", "4.x", "4.3.x"）を満たすか判定する
 */
export function satisfiesSingleClause(version: string, clause: string): boolean {
  const vParsed = parseVersion(version);
  if (!vParsed) return false;

  const trimmed = clause.trim();
  if (!trimmed || trimmed === '*') return true;

  // 比較演算子の抽出
  const match = trimmed.match(/^(<=|>=|<|>|==|!=|=|\^|~)?\s*(.+)$/);
  if (!match) return false;

  const op = match[1] || '=';
  const targetVer = match[2].trim();
  const targetToken = targetVer.replace(/^v\.?/i, '');

  // ワイルドカード対応: 字句の全体が /^\d+(\.\d+)*\.(x|\*)$/i に一致するときだけワイルドカードとして扱う
  if (WILDCARD_TOKEN_RE.test(targetToken)) {
    const prefixNums = targetToken
      .split('.')
      .slice(0, -1)
      .map((n) => parseInt(n, 10));
    if (prefixNums.length === 0 || prefixNums.length > 4) return false;

    const matchesPrefix = prefixNums.every((num, idx) => vParsed.parts[idx] === num);
    if (op === '=' || op === '==') return matchesPrefix;
    if (op === '!=') return !matchesPrefix;
    return false;
  }

  const tParsed = parseVersion(targetVer);
  if (!tParsed) return false;

  const cmp = compareParsedVersions(vParsed, tParsed);

  switch (op) {
    case '<':
      return cmp < 0;
    case '<=':
      return cmp <= 0;
    case '>':
      return cmp > 0;
    case '>=':
      return cmp >= 0;
    case '=':
    case '==':
      return cmp === 0;
    case '!=':
      return cmp !== 0;
    case '^': {
      // セマンティックバージョニング互換性 (^3.0.0 -> >= 3.0.0 < 4.0.0)
      if (vParsed.parts[0] !== tParsed.parts[0]) return false;
      return cmp >= 0;
    }
    case '~': {
      if (vParsed.parts[0] !== tParsed.parts[0] || vParsed.parts[1] !== tParsed.parts[1]) return false;
      return cmp >= 0;
    }
    default:
      return false;
  }
}

/**
 * バージョンが指定された範囲条件を満たすか判定する
 *
 * - カンマ区切りの場合はAND条件（例: ">= 4.0.0, < 4.3.1"）
 * - "||" 区切りの場合はOR条件（例: "< 7.4.31 || >= 8.0.0, < 8.0.24 || >= 8.1.0, < 8.1.11"）
 *
 * @param version 検査するバージョン (例: "8.0.23")
 * @param rangeSpec バージョン範囲指定 (例: "< 7.4.31 || >= 8.0.0, < 8.0.24")
 * @returns 範囲内であれば true
 */
export function satisfiesVersionRange(version: string | null | undefined, rangeSpec: string): boolean {
  if (!version || parseVersion(version) === null) return false;
  if (!rangeSpec || rangeSpec.trim() === '*' || rangeSpec.trim() === 'all') return true;

  // 1. "||" によるOR条件の分割
  const orBranches = rangeSpec
    .split('||')
    .map((b) => b.trim())
    .filter((b) => b.length > 0);

  // いずれかのブランチ条件を満たせば該当
  for (const branch of orBranches) {
    // 2. カンマ区切りの各句をAND条件として判定
    const clauses = branch
      .split(',')
      .map((c) => c.trim())
      .filter((c) => c.length > 0);

    const branchMatches = clauses.every((clause) => satisfiesSingleClause(version, clause));
    if (branchMatches) {
      return true;
    }
  }

  return false;
}

