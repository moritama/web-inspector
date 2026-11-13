/**
 * Web Technology & Security Inspector
 * dpkg の版比較（Debian Policy 5.6.12）(src/security/dpkg-version.ts)
 *
 * ディストリビューション（Debian / Ubuntu）のパッケージの版を比較するためのモジュール。
 * 上流の版比較（version-matcher.ts）とは独立しており、ディストリビューション固有のリビジョンや
 * エポック、チルダ（~）の順序を正しく評価する。
 */

/** 解析済みの dpkg の版 */
export interface DpkgVersion {
  /** epoch（省略時 0）。0〜2147483647 の整数 */
  epoch: number;
  /** upstream_version（必ず数字で始まる） */
  upstream: string;
  /** debian_revision（無いときは空文字 ''） */
  revision: string;
}

/** 文字の比較順序の重み付け（dpkg の order() に準拠） */
function order(c: string | undefined): number {
  if (!c) return 0;
  if (c === '~') return -1;
  if (c >= '0' && c <= '9') return 0;
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
    return c.charCodeAt(0);
  }
  return c.charCodeAt(0) + 256;
}

/** 1文字が数字かどうかを判定 */
function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= '0' && c <= '9';
}

/**
 * 2つのバージョン文字列コンポーネントを dpkg の verrevcmp アルゴリズムで比較
 *
 * Debian Policy 5.6.12 および dpkg の lib/dpkg/version.c に準拠。
 */
function verrevcmp(val: string, ref: string): number {
  let i = 0;
  let j = 0;

  while (i < val.length || j < ref.length) {
    let firstDiff = 0;

    // 非数字部分の比較
    while (
      (i < val.length && !isDigit(val[i])) ||
      (j < ref.length && !isDigit(ref[j]))
    ) {
      const vc = order(val[i]);
      const rc = order(ref[j]);

      if (vc !== rc) {
        return vc - rc;
      }

      i++;
      j++;
    }

    // 先頭のゼロを読み飛ばす
    while (i < val.length && val[i] === '0') {
      i++;
    }
    while (j < ref.length && ref[j] === '0') {
      j++;
    }

    // 数字部分の桁ごとの比較
    while (i < val.length && j < ref.length && isDigit(val[i]) && isDigit(ref[j])) {
      if (firstDiff === 0) {
        firstDiff = val.charCodeAt(i) - ref.charCodeAt(j);
      }
      i++;
      j++;
    }

    // 桁数の多い方が大きい
    if (i < val.length && isDigit(val[i])) {
      return 1;
    }
    if (j < ref.length && isDigit(ref[j])) {
      return -1;
    }
    // 桁数が同じなら最初に異なった数字の大小
    if (firstDiff !== 0) {
      return firstDiff;
    }
  }

  return 0;
}

/**
 * dpkg の版文字列をパースする
 *
 * @param s バージョン文字列
 * @returns パース成功時は DpkgVersion、不正な形式の場合は null
 */
export function parseDpkgVersion(s: string | null | undefined): DpkgVersion | null {
  if (typeof s !== 'string') {
    return null;
  }

  // 前後の空白（スペースとタブ）を取り除く
  const str = s.replace(/^[ \t]+|[ \t]+$/g, '');
  if (str.length === 0) {
    return null;
  }
  // 途中にスペースかタブがあれば null
  if (/[ \t]/.test(str)) {
    return null;
  }

  let epoch = 0;
  let rest = str;

  // 最初のコロンの前を epoch とする
  const colonIdx = str.indexOf(':');
  if (colonIdx !== -1) {
    const epochStr = str.slice(0, colonIdx);
    if (!/^\d+$/.test(epochStr)) {
      return null;
    }
    const epochNum = Number(epochStr);
    if (!Number.isSafeInteger(epochNum) || epochNum < 0 || epochNum > 2147483647) {
      return null;
    }
    epoch = epochNum;
    rest = str.slice(colonIdx + 1);
  }

  // 最後のハイフンで upstream と revision に分ける
  const hyphenIdx = rest.lastIndexOf('-');
  let upstream: string;
  let revision = '';
  if (hyphenIdx !== -1) {
    upstream = rest.slice(0, hyphenIdx);
    revision = rest.slice(hyphenIdx + 1);
    if (revision.length === 0) {
      return null;
    }
  } else {
    upstream = rest;
  }

  // upstream は必須で、数字で始まる必要がある
  if (upstream.length === 0 || !/^[0-9]/.test(upstream)) {
    return null;
  }

  // 許容文字種の検証
  // upstream は [0-9A-Za-z.+~:-]（dpkg の実装に合わせてコロンを許容）
  if (!/^[0-9A-Za-z.+~:\-]+$/.test(upstream)) {
    return null;
  }
  // revision は [0-9A-Za-z.+~]
  if (revision.length > 0 && !/^[0-9A-Za-z.+~]+$/.test(revision)) {
    return null;
  }

  return { epoch, upstream, revision };
}

/**
 * 2つの dpkg 版文字列を比較する
 *
 * @param a バージョン文字列 A
 * @param b バージョン文字列 B
 * @returns a < b なら -1、a == b なら 0、a > b なら 1。いずれかが不正な形式なら null
 */
export function compareDpkgVersions(
  a: string | null | undefined,
  b: string | null | undefined
): -1 | 0 | 1 | null {
  const verA = parseDpkgVersion(a);
  const verB = parseDpkgVersion(b);
  if (!verA || !verB) {
    return null;
  }

  // 1. epoch を比較
  if (verA.epoch < verB.epoch) return -1;
  if (verA.epoch > verB.epoch) return 1;

  // 2. upstream を比較
  const upstreamCmp = verrevcmp(verA.upstream, verB.upstream);
  if (upstreamCmp < 0) return -1;
  if (upstreamCmp > 0) return 1;

  // 3. revision を比較
  const revCmp = verrevcmp(verA.revision, verB.revision);
  if (revCmp < 0) return -1;
  if (revCmp > 0) return 1;

  return 0;
}
