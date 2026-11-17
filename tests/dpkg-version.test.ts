/**
 * dpkg の版比較（v1.8.1 T01）の受け入れテスト
 *
 * 対象: src/security/dpkg-version.ts の parseDpkgVersion / compareDpkgVersions
 * 規則: Debian Policy 5.6.12（https://www.debian.org/doc/debian-policy/ch-controlfields.html#version）
 * 比較例の出典: dpkg 自身のテスト lib/dpkg/t/t-version.c
 *   （https://salsa.debian.org/dpkg-team/dpkg/-/blob/main/lib/dpkg/t/t-version.c 、GPL-2.0-or-later）
 *   t-version.c は版を「epoch・upstream・revision の組」で比べるので、ここでは同じ意味の版の文字列に書き直している。
 *   書き直せないもの（空の版どうしの比較）と、書き直しで入力を変えたものは、各ケースの注記と設計メモに書いた。
 *
 * 上流の版比較（version-matcher）とは別の関数であること、version-matcher の挙動が変わらないことも確かめる。
 */
import { describe, expect, it } from 'vitest';
import { compareDpkgVersions, parseDpkgVersion } from '../src/security/dpkg-version';
import { compareVersions, isLinuxPackageVersion } from '../src/security/version-matcher';

type Sign = -1 | 0 | 1;

/** a と b の比較で期待する結果を確かめ、逆順では符号が反転することも確かめる */
function expectOrder(a: string, b: string, expected: Sign): void {
  expect(compareDpkgVersions(a, b), `${a} と ${b} の比較`).toBe(expected);
  expect(compareDpkgVersions(b, a), `${b} と ${a} の比較（逆順）`).toBe((expected === 0 ? 0 : -expected) as Sign);
}

describe('dpkg-version: dpkg 自身のテスト（lib/dpkg/t/t-version.c）の比較例', () => {
  // test_version_compare() の各ケース。[a, b, 期待, 元のケース]
  const compareCases: Array<[string, string, Sign, string]> = [
    // 元は epoch だけ 1 と 2 で、版は空（dpkg_version_blank）。空の upstream は文字列にできないので upstream を 0 にした
    ['1:0', '2:0', -1, 'a.epoch = 1; b.epoch = 2; test_fail(compare == 0)'],
    ['1-1', '2-1', -1, 'DPKG_VERSION_OBJECT(0, "1", "1") と (0, "2", "1") は等しくない'],
    ['1-1', '1-2', -1, 'DPKG_VERSION_OBJECT(0, "1", "1") と (0, "1", "2") は等しくない'],
    ['0-0', '0-0', 0, 'Test for version equality: (0, "0", "0")'],
    ['0-00', '00-0', 0, 'Test for version equality: (0, "0", "00") と (0, "00", "0")'],
    ['1:2-3', '1:2-3', 0, 'Test for version equality: (1, "2", "3")'],
    ['0-0', '1:0-0', -1, 'Test for epoch difference: (0, "0", "0") < (1, "0", "0")'],
    // 元は upstream が "a" と "b"。数字以外で始まる upstream は解析で null にする（受け入れ条件）ので、先頭に 0 を付けた
    ['0a-0', '0b-0', -1, 'Test for version component difference: (0, "a", "0") < (0, "b", "0")'],
    ['0-a', '0-b', -1, 'Test for revision component difference: (0, "0", "a") < (0, "0", "b")'],
  ];

  it.each(compareCases)('%s と %s の比較が %i になること（%s）', (a, b, expected) => {
    expectOrder(a, b, expected);
  });

  // test_version_parse() の、解析に成功するケース。[入力, epoch, upstream, revision]
  const parseOkCases: Array<[string, number, string, string]> = [
    ['0', 0, '0', ''],
    ['0:0', 0, '0', ''],
    ['0:0-0', 0, '0', '0'],
    ['0:0.0-0.0', 0, '0.0', '0.0'],
    ['1:0', 1, '0', ''],
    ['5:1', 5, '1', ''],
    // Test multiple hyphens（最後のハイフンで分ける）
    ['0:0-0-0', 0, '0-0', '0'],
    ['0:0-0-0-0', 0, '0-0-0', '0'],
    // Test multiple colons（最初のコロンまでが epoch）
    ['0:0:0-0', 0, '0:0', '0'],
    ['0:0:0:0-0', 0, '0:0:0', '0'],
    // Test multiple hyphens and colons
    ['0:0:0-0-0', 0, '0:0-0', '0'],
    ['0:0-0:0-0', 0, '0-0:0', '0'],
    // Test valid characters in upstream version / revision
    ['0:09azAZ.-+~:-0', 0, '09azAZ.-+~:', '0'],
    ['0:0-azAZ09.+~', 0, '0', 'azAZ09.+~'],
  ];

  it.each(parseOkCases)('%s を解析できること（epoch %i・upstream %s・revision %s）', (input, epoch, upstream, revision) => {
    expect(parseDpkgVersion(input)).toMatchObject({ epoch, upstream, revision });
  });

  it('test_version_parse() の等価の例: 解析した版が、期待する組の版と等しく比べられること', () => {
    // 期待する組を文字列にしたもの（"0" と "0:0" は DPKG_VERSION_OBJECT(0, "0", "") と等しい）
    expectOrder('0', '0:0', 0);
    expectOrder('0:0-0', '0-0', 0);
    expectOrder('0:0.0-0.0', '0.0-0.0', 0);
    expectOrder('1:0', '1:0', 0);
    expectOrder('5:1', '5:1', 0);
    expectOrder('0:0-0-0', '0-0-0', 0);
  });

  it('前後の空白（スペースとタブ）は無視して解析すること（Test version with leading and trailing spaces）', () => {
    for (const input of ['  \t0:0-1', '0:0-1\t  ', '\t  0:0-1  \t']) {
      expect(parseDpkgVersion(input), JSON.stringify(input)).toMatchObject({ epoch: 0, upstream: '0', revision: '1' });
      expect(compareDpkgVersions(input, '0-1'), JSON.stringify(input)).toBe(0);
    }
  });

  // test_version_parse() の、解析に失敗するケース。[入力, 元のケース]
  const parseNgCases: Array<[string, string]> = [
    ['', 'Test empty version'],
    ['  ', 'Test empty version'],
    ['0:', 'Test empty upstream version after epoch'],
    [':1.0', 'Test empty epoch in version'],
    ['1.0-', 'Test empty revision in version'],
    ['0:0 0-1', 'Test version with embedded spaces'],
    ['-1:0-1', 'Test version with negative epoch'],
    ['999999999999999999999999:0-1', 'Test version with huge epoch'],
    ['a:0-0', 'Test invalid characters in epoch'],
    ['A:0-0', 'Test invalid characters in epoch'],
    ['-0', 'Test invalid empty upstream version'],
    ['0:-0', 'Test invalid empty upstream version'],
    ['0:abc3-0', 'Test upstream version not starting with a digit'],
    ['0:0-0:0', 'Test invalid characters in revision'],
  ];

  it.each(parseNgCases)('%j は解析できず null になること（%s）', (input) => {
    expect(parseDpkgVersion(input)).toBeNull();
    expect(compareDpkgVersions(input, '0-1')).toBeNull();
    expect(compareDpkgVersions('0-1', input)).toBeNull();
  });

  it('upstream に使えない文字（Test invalid characters in upstream version）を含むと null になること', () => {
    for (const ch of "!#@$%&/|\\<>()[]{};,_=*^'") {
      const input = `0:0${ch}-0`;
      expect(parseDpkgVersion(input), input).toBeNull();
    }
  });

  it('revision に使えない文字（Test invalid characters in revision）を含むと null になること', () => {
    for (const ch of "!#@$%&/|\\<>()[]{}:;,_=*^'") {
      const input = `0:0-${ch}`;
      expect(parseDpkgVersion(input), input).toBeNull();
    }
  });

  it('test_version_relate() の例: 同じ版は 0、上流の版が小さいほうは -1、大きいほうは 1 であること', () => {
    expectOrder('1-1', '1-1', 0);
    expectOrder('1-1', '2-1', -1);
    expectOrder('2-1', '1-1', 1);
  });
});

describe('dpkg-version: 指示書で指定された比較', () => {
  it('7.4.3-4ubuntu2.19 > 7.4.3-4ubuntu2.2（revision の数字は数として比べる）', () => {
    expectOrder('7.4.3-4ubuntu2.19', '7.4.3-4ubuntu2.2', 1);
  });

  it('1:1.0 > 2.0（epoch を最初に比べる）', () => {
    expectOrder('1:1.0', '2.0', 1);
  });

  it('1.0~rc1 < 1.0（~ は空より前）', () => {
    expectOrder('1.0~rc1', '1.0', -1);
  });

  it('2.4.62-1~deb11u1 < 2.4.62-1~deb12u1（revision の中の ~ の後も交互に比べる）', () => {
    expectOrder('2.4.62-1~deb11u1', '2.4.62-1~deb12u1', -1);
  });
});

describe('dpkg-version: Debian Policy 5.6.12 の規則', () => {
  it('~ はどんな文字よりも、部分の終わりよりも前に並ぶこと（~~ < ~~a < ~ < 空 < a）', () => {
    const sorted = ['1.0~~', '1.0~~a', '1.0~', '1.0', '1.0a'];
    for (let i = 0; i < sorted.length - 1; i++) {
      expectOrder(sorted[i], sorted[i + 1], -1);
    }
  });

  it('文字はすべての記号より前に並ぶこと（a < +、a < .）', () => {
    expectOrder('1.0a', '1.0+', -1);
    expectOrder('1.0a', '1.0.', -1);
  });

  it('文字どうしは ASCII の順であること（Z < a）', () => {
    expectOrder('1.0Z', '1.0a', -1);
  });

  it('数字の部分は数として比べ、先頭の 0 は無視すること', () => {
    expectOrder('1.10', '1.9', 1);
    expectOrder('1.01', '1.1', 0);
    expectOrder('1.002-1', '1.2-1', 0);
  });

  it('桁の多い数字の部分も正しく比べること（数の精度に依存しない）', () => {
    expectOrder('1.12345678901234567890', '1.12345678901234567889', 1);
    expectOrder('1.99999999999999999999', '1.100000000000000000000', -1);
  });

  it('revision が無いことは revision が 0 であることと同じであること', () => {
    expectOrder('2.0', '2.0-0', 0);
    expectOrder('2.0', '2.0-1', -1);
  });

  it('epoch を省略すると 0 として扱い、epoch は数として比べること', () => {
    expectOrder('2.0', '0:2.0', 0);
    expectOrder('10:1.0', '9:1.0', 1);
  });

  it('upstream が等しいときだけ revision を比べること', () => {
    expectOrder('2.0-9', '2.1-1', -1);
    expectOrder('2.1-1', '2.1-1ubuntu1', -1);
  });

  it('上流の SemVer 比較と違い、1.0 < 1.0.0 であること（文字の無い部分と記号の比較）', () => {
    expectOrder('1.0', '1.0.0', -1);
  });

  it('ディストリの典型的な版の並び（binNMU・セキュリティ更新）', () => {
    expectOrder('2.4.62-1~deb12u1', '2.4.62-1~deb12u2', -1);
    expectOrder('2.4.62-1~deb12u2', '2.4.62-1', -1);
    expectOrder('8.2.7-1', '8.2.7-1+b1', -1);
    expectOrder('1.18.0-6ubuntu14.4', '1.18.0-6ubuntu14.10', -1);
    expectOrder('7.4.3-4ubuntu2.19', '1:7.0-1', -1);
  });
});

describe('dpkg-version: parseDpkgVersion の戻り値', () => {
  it('epoch・upstream・revision に分けて返すこと（epoch は数）', () => {
    expect(parseDpkgVersion('7.4.3-4ubuntu2.19')).toMatchObject({ epoch: 0, upstream: '7.4.3', revision: '4ubuntu2.19' });
    expect(parseDpkgVersion('1:2.4.62-1~deb12u1')).toMatchObject({ epoch: 1, upstream: '2.4.62', revision: '1~deb12u1' });
  });

  it('revision が無いときは空文字、epoch が無いときは 0 を返すこと', () => {
    expect(parseDpkgVersion('1.0~rc1')).toMatchObject({ epoch: 0, upstream: '1.0~rc1', revision: '' });
  });

  it('epoch の先頭の 0 は数として扱うこと', () => {
    expect(parseDpkgVersion('01:1.0')).toMatchObject({ epoch: 1, upstream: '1.0', revision: '' });
  });
});

describe('dpkg-version: 不正な入力', () => {
  it('空・空白だけ・null・undefined は null になること', () => {
    for (const input of ['', ' ', '\t', null, undefined]) {
      expect(parseDpkgVersion(input), String(input)).toBeNull();
      expect(compareDpkgVersions(input, '1.0'), String(input)).toBeNull();
      expect(compareDpkgVersions('1.0', input), String(input)).toBeNull();
    }
  });

  it('数字以外で始まる上流版は null になること（epoch の有無を問わない）', () => {
    for (const input of ['abc', 'v1.0', '~1.0', '.1', '+1', 'ubuntu1', '1:abc', '1:v2.0-1']) {
      expect(parseDpkgVersion(input), input).toBeNull();
      expect(compareDpkgVersions(input, '1.0'), input).toBeNull();
    }
  });

  it('不正な epoch（空・負・数字以外・小数・巨大）は null になること', () => {
    for (const input of [':1.0', '-1:1.0', 'a:1.0', '1a:1.0', '1.5:1.0', ' :1.0', '999999999999999999999999:1.0']) {
      expect(parseDpkgVersion(input), input).toBeNull();
      expect(compareDpkgVersions('1.0', input), input).toBeNull();
    }
  });

  it('陰性: 正しい版は null にならないこと', () => {
    for (const input of ['0', '1.0', '1:1.0', '1.0~rc1', '7.4.3-4ubuntu2.19', '2.4.62-1~deb11u1', '8.2.7-1+b1']) {
      expect(parseDpkgVersion(input), input).not.toBeNull();
      expect(compareDpkgVersions(input, input), input).toBe(0);
    }
  });
});

describe('dpkg-version: 戻り値の範囲', () => {
  it('compareDpkgVersions は -1・0・1 のどれかだけを返すこと（差の大きさを返さない）', () => {
    const versions = ['1.0', '9.0', '1:1.0', '1.0~rc1', '1.0a', '1.0+', '7.4.3-4ubuntu2.2', '7.4.3-4ubuntu2.19'];
    for (const a of versions) {
      for (const b of versions) {
        const r = compareDpkgVersions(a, b);
        expect([-1, 0, 1], `${a} と ${b}`).toContain(r);
        expect(compareDpkgVersions(b, a), `${b} と ${a}`).toBe(r === 0 ? 0 : -(r as number));
      }
    }
  });
});

describe('dpkg-version: 既存の isLinuxPackageVersion と version-matcher の挙動が変わらないこと', () => {
  it('isLinuxPackageVersion の判定（陽性と陰性）が変わらないこと', () => {
    expect(isLinuxPackageVersion('7.4.3-4ubuntu2.19')).toBe(true);
    expect(isLinuxPackageVersion('2.4.62-1~deb12u1')).toBe(true);
    expect(isLinuxPackageVersion('2.4.6-97.el7')).toBe(true);
    expect(isLinuxPackageVersion('1:1.0')).toBe(false);
    expect(isLinuxPackageVersion('1.0~rc1')).toBe(false);
    expect(isLinuxPackageVersion('1.18.0')).toBe(false);
  });

  it('version-matcher の compareVersions は上流の版の比較のまま（ディストリの印の違いは区別しない）であること', () => {
    // dpkg の比較とは結果が違うことを確かめる（上流の比較を dpkg の比較に置き換えていない）
    expect(compareVersions('7.4.3-4ubuntu2.19', '7.4.3-4ubuntu2.2')).toBe(0);
    expect(compareDpkgVersions('7.4.3-4ubuntu2.19', '7.4.3-4ubuntu2.2')).toBe(1);
    expect(compareVersions('1.0.0-rc1', '1.0.0')).toBe(-1);
    expect(compareVersions('2.4.62', '2.4.58')).toBe(1);
  });
});
