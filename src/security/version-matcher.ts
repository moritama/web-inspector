/**
 * Web Technology & Security Inspector
 * バージョン比較・セマンティック範囲判定ユーティリティ (src/security/version-matcher.ts)
 */

/**
 * Linuxディストリビューション固有のパッケージバージョン表記（例: "2.4.52-1ubuntu4", "1.18.0-0ubuntu1.4", "2.4.6-97.el7"）かを検出する (Rev.2.1 IMP-06 / 5.6)
 *
 * @param version バージョン文字列
 * @returns boolean
 */
export function isLinuxPackageVersion(version: string | null | undefined): boolean {
  if (!version) return false;
  const lower = version.toLowerCase().trim();
  return /[-+]([0-9]+)?(ubuntu|deb|debian|el[0-9]|amzn|redhat|centos|arch|alpine|fc[0-9]+)/i.test(lower);
}

/**
 * バージョン番号文字列（例: "3.6.0", "4.3.1-beta"）を数値配列にパースする
 *
 * @param version バージョン文字列
 * @returns [major, minor, patch, preRelease]
 */
export function parseVersionParts(version: string | null | undefined): number[] | null {
  if (!version) return null;

  // 先頭の 'v' や 'v.' を除去
  const clean = version.trim().replace(/^v\.?/i, '');
  const baseMatch = clean.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?/);
  if (!baseMatch) return null;

  const major = parseInt(baseMatch[1], 10);
  const minor = baseMatch[2] !== undefined ? parseInt(baseMatch[2], 10) : 0;
  const patch = baseMatch[3] !== undefined ? parseInt(baseMatch[3], 10) : 0;
  const build = baseMatch[4] !== undefined ? parseInt(baseMatch[4], 10) : 0;

  return [major, minor, patch, build];
}

/**
 * 2つのバージョン番号を比較する
 *
 * @param v1 バージョン1
 * @param v2 バージョン2
 * @returns 1: v1 > v2, -1: v1 < v2, 0: v1 == v2
 */
export function compareVersions(v1: string, v2: string): number {
  const p1 = parseVersionParts(v1);
  const p2 = parseVersionParts(v2);

  if (!p1 && !p2) return 0;
  if (!p1) return -1;
  if (!p2) return 1;

  for (let i = 0; i < 4; i++) {
    const num1 = p1[i] ?? 0;
    const num2 = p2[i] ?? 0;
    if (num1 > num2) return 1;
    if (num1 < num2) return -1;
  }

  return 0;
}

/**
 * バージョンが指定された単一の比較条件（例: "< 4.3.1", ">= 3.0.0", "= 3.6.0"）を満たすか判定する
 */
export function satisfiesSingleClause(version: string, clause: string): boolean {
  const trimmed = clause.trim();
  if (!trimmed || trimmed === '*') return true;

  // 比較演算子の抽出
  const match = trimmed.match(/^([<>=!~^]*)\s*(.+)$/);
  if (!match) return false;

  const op = match[1] || '=';
  const targetVer = match[2].trim();

  // "4.x" や "3.*" のようなワイルドカード対応
  if (targetVer.includes('x') || targetVer.includes('*')) {
    const prefix = targetVer.replace(/[.*x]/g, '');
    const vParts = parseVersionParts(version);
    const tParts = parseVersionParts(prefix);
    if (!vParts || !tParts) return false;
    return vParts[0] === tParts[0];
  }

  const cmp = compareVersions(version, targetVer);

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
      const tParts = parseVersionParts(targetVer);
      const vParts = parseVersionParts(version);
      if (!tParts || !vParts) return false;
      if (vParts[0] !== tParts[0]) return false;
      return cmp >= 0;
    }
    default:
      return cmp === 0;
  }
}

/**
 * バージョンが複合条件（例: ">= 4.0.0, < 4.3.1" または ">= 3.0.0 < 3.5.0"）を満たすか判定する
 *
 * @param version 検査するバージョン (例: "4.3.0")
 * @param rangeSpec バージョン範囲指定 (例: ">= 4.0.0, < 4.3.1")
 * @returns 範囲内であれば true
 */
export function satisfiesVersionRange(version: string | null | undefined, rangeSpec: string): boolean {
  if (!version) return false;
  if (!rangeSpec || rangeSpec.trim() === '*' || rangeSpec.trim() === 'all') return true;

  // カンマまたはスペース区切りの各句をAND条件として判定
  const clauses = rangeSpec
    .split(',')
    .map((c) => c.trim())
    .filter((c) => c.length > 0);

  for (const clause of clauses) {
    if (!satisfiesSingleClause(version, clause)) {
      return false;
    }
  }

  return true;
}
