/**
 * 版の比較の共通関数（v1.8.0 T01）
 *
 * テストに版の文字列を直接書かないための補助。期待値は package.json の version から取る。
 * DB だけの自動リリースでは manifest の版に 4 つ目の番号（DB のリビジョン）が付くので、
 * manifest と package.json は「3 要素が一致し、4 つ目は無いか数字だけ」で同じリリースとみなす。
 */
import * as fs from 'fs';
import * as path from 'path';

export const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** package.json の version を返す */
export function readPackageVersion(): string {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8')) as { version?: unknown };
  if (typeof pkg.version !== 'string' || pkg.version.length === 0) {
    throw new Error('package.json に version がありません');
  }
  return pkg.version;
}

/**
 * manifest の版が package.json の版と同じリリースかどうか。
 * - pkgVersion は「数字.数字.数字」の 3 要素であること
 * - manifestVersion の先頭 3 要素が pkgVersion と一致し、4 つ目は無いか数字だけ（5 つ目以降は不可）
 */
export function isSameRelease(manifestVersion: string, pkgVersion: string): boolean {
  if (typeof manifestVersion !== 'string' || typeof pkgVersion !== 'string') return false;
  if (!/^\d+\.\d+\.\d+$/.test(pkgVersion)) return false;
  const parts = manifestVersion.split('.');
  if (parts.length !== 3 && parts.length !== 4) return false;
  if (!parts.every((p) => /^\d+$/.test(p))) return false;
  return parts.slice(0, 3).join('.') === pkgVersion;
}
