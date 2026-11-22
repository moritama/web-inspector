/**
 * Web Technology & Security Inspector
 * v1.8.2 T07: THIRD_PARTY_NOTICES.md・README のライセンスの節・zip への同梱（指示書 §5.2・§5.4、H9）
 *
 * - THIRD_PARTY_NOTICES.md（リポジトリ直下）に、データごとの出典・ライセンス・URL・加工の有無がある
 *   MIT（endoflife.date）は著作権表示と許諾の本文、MPL 2.0（PSL）は本文への参照
 * - README のライセンスの節（コードは MIT、同梱データはそれぞれのライセンス、Ubuntu は CC BY-SA 4.0、詳細は NOTICES）
 * - scripts/package.mjs が作る zip に THIRD_PARTY_NOTICES.md が入る（入れられなければ zip を作らない）
 *
 * 同梱 DB の sources と NOTICES の照合は tests/advisory-db-invariants.test.ts（同梱 DB を読んでよいテスト）で行う。
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { BUNDLED_DATA_SOURCES, NVD_NOTICE, NVD_TERMS_URL } from '../src/shared/data-sources';
// @ts-expect-error scripts/ci/check-data-sources.mjs は型定義を持たない .mjs モジュール
import { checkDataSources } from '../scripts/ci/check-data-sources.mjs';

const ROOT = path.resolve(__dirname, '..');
const NOTICES_PATH = path.join(ROOT, 'THIRD_PARTY_NOTICES.md');
const readNotices = (): string => fs.readFileSync(NOTICES_PATH, 'utf-8');

const byId = (id: string) => {
  const s = BUNDLED_DATA_SOURCES.find((x) => x.id === id);
  if (!s) throw new Error(`BUNDLED_DATA_SOURCES に ${id} がありません`);
  return s;
};

/**
 * 見出し（## 〜 ####）に name を含む節を返す。節は、同じか上の階層の次の見出しの手前まで。
 * 見つからなければ null。
 */
function sectionFor(markdown: string, name: string): string | null {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((l) => /^#{2,4}\s/.test(l) && l.includes(name));
  if (start === -1) return null;
  const level = (lines[start].match(/^#+/) as RegExpMatchArray)[0].length;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    const m = lines[i].match(/^(#+)\s/);
    if (m && m[1].length <= level) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

describe('T07: THIRD_PARTY_NOTICES.md（§5.4）', () => {
  it('リポジトリ直下に THIRD_PARTY_NOTICES.md があること', () => {
    expect(fs.existsSync(NOTICES_PATH)).toBe(true);
  });

  it('7 種類それぞれに見出しの節があり、URL・ライセンスの表記・加工の有無が書かれていること', () => {
    const text = readNotices();
    for (const s of BUNDLED_DATA_SOURCES) {
      const sec = sectionFor(text, s.name);
      expect(sec, `「${s.name}」を見出しに含む節がありません`).not.toBeNull();
      expect(sec!, s.id).toContain(s.url);
      expect(sec!, s.id).toContain(s.licenseLabel);
      if (s.licenseUrl !== null) expect(sec!, s.id).toContain(s.licenseUrl);
      expect(sec!, `${s.id} の節に加工の有無がありません`).toMatch(/加工/);
    }
  });

  it('NVD の節に、表示文（一字一句）と利用規約の URL があること', () => {
    const sec = sectionFor(readNotices(), byId('nvd').name);
    expect(sec).not.toBeNull();
    expect(sec!).toContain(NVD_NOTICE);
    expect(sec!).toContain('This product uses the NVD API but is not endorsed or certified by the NVD.');
    expect(sec!).toContain(NVD_TERMS_URL);
  });

  it('Ubuntu の節に CC BY-SA 4.0 と明記されていること（H9）', () => {
    const sec = sectionFor(readNotices(), byId('ubuntu').name);
    expect(sec).not.toBeNull();
    expect(sec!).toContain('CC BY-SA 4.0');
    expect(sec!).toContain('https://creativecommons.org/licenses/by-sa/4.0/');
  });

  it('陰性: Debian の節は「ライセンスの明記なし」で、ライセンスを割り当てないこと（H9）', () => {
    const sec = sectionFor(readNotices(), byId('debian').name);
    expect(sec).not.toBeNull();
    expect(sec!).toContain('ライセンスの明記なし');
    expect(sec!).not.toMatch(/creativecommons\.org|CC BY|CC0|MIT License|Mozilla Public License|GPL/);
  });

  it('MIT（endoflife.date）は著作権表示と許諾の本文があること', () => {
    const text = readNotices();
    expect(text).toContain('Copyright 2020 endoflife.date contributors');
    expect(text).toContain(
      'Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software")'
    );
    expect(text).toContain(
      'The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.'
    );
    expect(text).toContain('THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND');
  });

  it('MPL 2.0（Public Suffix List）は本文への参照と、元のファイルの URL があること', () => {
    const sec = sectionFor(readNotices(), byId('psl').name);
    expect(sec).not.toBeNull();
    expect(sec!).toContain('https://mozilla.org/MPL/2.0/');
    expect(sec!).toContain('https://publicsuffix.org/list/public_suffix_list.dat');
    expect(sec!).toContain('psl-rules.generated.ts');
  });

  it('陰性: 配布物に入らない Launchpad・sources.debian.org を出典の節として載せないこと（§5.2 の表の下）', () => {
    const headings = readNotices()
      .split(/\r?\n/)
      .filter((l) => /^#{2,4}\s/.test(l));
    for (const h of headings) {
      expect(h).not.toMatch(/launchpad/i);
      expect(h).not.toMatch(/sources\.debian\.org/i);
    }
  });

  it('陰性: NOTICES に無い出典が DB に入ると、CI のチェック（check-data-sources）が不合格にすること', () => {
    const extra = {
      name: 'Example Synthetic Feed',
      url: 'https://feed.example.test/',
      ecosystem: null,
      license: 'CC0-1.0',
      retrievedAt: null,
      recordCount: 0,
    };
    const result = checkDataSources({ db: { sources: [extra] }, noticesText: readNotices() });
    expect(result.ok).toBe(false);
    expect(result.issues.join('\n')).toContain('Example Synthetic Feed');
  });

  it('作業者の環境を示す文字列（ローカルパス）を含まないこと', () => {
    expect(readNotices()).not.toMatch(/\/Users\/|\/home\/[a-z]|C:\\Users\\/);
  });
});

describe('T07: README のライセンスの節（§5.4）', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf-8');
  const sec = sectionFor(readme, 'ライセンス') ?? '';

  it('「## ライセンス」の節があり、コードは MIT と書かれていること', () => {
    expect(sec).not.toBe('');
    expect(sec).toContain('MIT');
  });

  it('同梱データはそれぞれのライセンスに従い、Ubuntu の部分は CC BY-SA 4.0、詳細は THIRD_PARTY_NOTICES.md と書かれていること', () => {
    expect(sec).toContain('同梱データ');
    expect(sec).toContain('Ubuntu');
    expect(sec).toContain('CC BY-SA 4.0');
    expect(sec).toContain('THIRD_PARTY_NOTICES.md');
  });
});

const hasZipTools =
  spawnSync('zip', ['-v'], { encoding: 'utf-8' }).status === 0 &&
  spawnSync('unzip', ['-v'], { encoding: 'utf-8' }).status === 0;

describe.skipIf(!hasZipTools)('T07: scripts/package.mjs の zip に THIRD_PARTY_NOTICES.md が入る（§5.4）', () => {
  const PKG_VERSION = '0.0.1';
  const ZIP_NAME = `web-inspector-v${PKG_VERSION}.zip`;
  const created: string[] = [];

  /** os.tmpdir() に、ビルド済みの dist と public/manifest.json を持つ作業場所を作る（realpath で解決する） */
  function makeWorkdir(withNotices: boolean): string {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 't07-package-')));
    created.push(dir);
    fs.mkdirSync(path.join(dir, 'dist'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'public'), { recursive: true });
    const manifest = JSON.stringify({ manifest_version: 3, name: 'test', version: PKG_VERSION });
    fs.writeFileSync(path.join(dir, 'dist', 'manifest.json'), manifest);
    fs.writeFileSync(path.join(dir, 'dist', 'popup.html'), '<!doctype html><title>t</title>');
    fs.writeFileSync(path.join(dir, 'public', 'manifest.json'), manifest);
    if (withNotices) {
      fs.writeFileSync(path.join(dir, 'THIRD_PARTY_NOTICES.md'), '# Third-party notices (synthetic for test)\n');
    }
    return dir;
  }

  function runPackage(cwd: string) {
    return spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'package.mjs')], { cwd, encoding: 'utf-8' });
  }

  afterEach(() => {
    for (const d of created.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it('作業場所（カレントディレクトリ）の THIRD_PARTY_NOTICES.md が zip の直下に入ること', () => {
    const dir = makeWorkdir(true);
    const res = runPackage(dir);
    expect(res.status, `${res.stdout}\n${res.stderr}`).toBe(0);
    const zipPath = path.join(dir, 'release', ZIP_NAME);
    expect(fs.existsSync(zipPath)).toBe(true);
    const list = spawnSync('unzip', ['-Z1', zipPath], { encoding: 'utf-8' }).stdout.split(/\r?\n/).filter(Boolean);
    expect(list).toContain('THIRD_PARTY_NOTICES.md');
    expect(list).toContain('manifest.json');
    const content = spawnSync('unzip', ['-p', zipPath, 'THIRD_PARTY_NOTICES.md'], { encoding: 'utf-8' }).stdout;
    expect(content).toContain('synthetic for test');
  });

  it('陰性: THIRD_PARTY_NOTICES.md が無ければ失敗し、zip を作らないこと', () => {
    const dir = makeWorkdir(false);
    const res = runPackage(dir);
    expect(res.status).not.toBe(0);
    expect(`${res.stdout}\n${res.stderr}`).toContain('THIRD_PARTY_NOTICES');
    expect(fs.existsSync(path.join(dir, 'release', ZIP_NAME))).toBe(false);
  });
});
