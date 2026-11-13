/**
 * 版の比較の共通関数 isSameRelease（tests/helpers/release-version.ts）の仕様（v1.8.0 T01）
 * 判定は「3 要素が一致し、4 つ目は無いか数字だけ」。
 * ここの版は合成の値で、現在の package.json の版とは関係しない（test-hygiene が現在の版の直書きを検査する）。
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { isSameRelease, readPackageVersion, REPO_ROOT } from './helpers/release-version';

describe('isSameRelease(manifestVersion, pkgVersion)', () => {
  it.each([
    ['3 要素が一致する', '3.4.5', '3.4.5'],
    ['4 つ目が数字（DB だけの自動リリース）', '3.4.5.1', '3.4.5'],
    ['4 つ目が複数桁の数字', '3.4.5.12', '3.4.5'],
  ])('同じリリースとみなす: %s（%s と %s）', (_label, manifestVersion, pkgVersion) => {
    expect(isSameRelease(manifestVersion, pkgVersion)).toBe(true);
  });

  it.each([
    ['3 要素目が違う', '3.4.6', '3.4.5'],
    ['3 要素目が前方一致するだけ', '3.4.50', '3.4.5'],
    ['先頭に数字が続く', '13.4.5', '3.4.5'],
    ['4 つ目が数字でない', '3.4.5.a', '3.4.5'],
    ['4 つ目がプレリリース風', '3.4.5-beta', '3.4.5'],
    ['4 つ目が空', '3.4.5.', '3.4.5'],
    ['5 つ目がある', '3.4.5.1.2', '3.4.5'],
    ['manifest が 2 要素', '3.4', '3.4.5'],
    ['package.json の版が 3 要素でない', '3.4.5.1', '3.4.5.1'],
    ['空文字', '', '3.4.5'],
  ])('同じリリースとみなさない: %s（%s と %s）', (_label, manifestVersion, pkgVersion) => {
    expect(isSameRelease(manifestVersion, pkgVersion)).toBe(false);
  });
});

describe('readPackageVersion()', () => {
  it('package.json の version をそのまま返すこと', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8'));
    expect(readPackageVersion()).toBe(pkg.version);
  });

  it('現在の public/manifest.json の版は、package.json の版と同じリリースであること', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'public', 'manifest.json'), 'utf-8'));
    expect(isSameRelease(manifest.version, readPackageVersion())).toBe(true);
  });
});
