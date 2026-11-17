/**
 * v1.8.1 T02: 上流版→リリースの対応表（data/advisories/distro-map.json）と、catalog.json の OS の節
 *
 * 対応表は人が一次資料で調べて書く curated のデータ（H3）。ここでは中身の形と、受け入れ条件
 * 「全項目に evidenceUrl と verifiedAt がある」「同じ系統・製品・上流版が複数リリースにある場合も表現できる」を確かめる。
 * 件数・日付は直接書かない。リリースの一覧は指示書の H8 と §6 T02 の「対象」のとおり。
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import type { DistroFamily, DistroMapEntry, DistroMapFile } from '../src/shared/types';
import { REPO_ROOT } from './helpers/release-version';

const MAP_PATH = path.join(REPO_ROOT, 'data', 'advisories', 'distro-map.json');
const CATALOG_PATH = path.join(REPO_ROOT, 'data', 'advisories', 'catalog.json');

interface CatalogDistro {
  name?: string;
  eol?: { slug?: string };
  releases?: string[];
}
interface Catalog {
  products: Record<string, unknown>;
  distros?: Record<string, CatalogDistro>;
}

const readMap = (): DistroMapFile => JSON.parse(fs.readFileSync(MAP_PATH, 'utf-8')) as DistroMapFile;
const readCatalog = (): Catalog => JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf-8')) as Catalog;

/** 系統 → endoflife.date の製品名（指示書 §5.1・§6 T02） */
const FAMILY_SLUGS: Record<DistroFamily, string> = {
  ubuntu: 'ubuntu',
  debian: 'debian',
  rhel: 'rhel',
  centos: 'centos',
  almalinux: 'almalinux',
  rocky: 'rocky-linux',
};
const FAMILIES = Object.keys(FAMILY_SLUGS) as DistroFamily[];
const PRODUCTS = ['apache', 'nginx', 'php', 'openssl'];

/** 収録しなければならないリリース（H8 と、RHEL 系の 7〜10 のうち存在するもの） */
const REQUIRED_RELEASES: Record<DistroFamily, string[]> = {
  debian: ['10', '11', '12', '13'],
  ubuntu: ['18.04', '20.04', '22.04', '24.04'],
  rhel: ['7', '8', '9', '10'],
  centos: ['7', '8'],
  almalinux: ['8', '9', '10'],
  rocky: ['8', '9', '10'],
};

/** 「今日」の上限（時差で UTC の日付が 1 日ずれても落ちないよう、1 日の余裕を持たせる） */
const todayIso = (): string => new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);
const isValidIsoDate = (s: unknown): boolean => {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
};

describe('T02: catalog.json の OS の節（distros）', () => {
  it('6 つの系統が、endoflife.date の製品名（slug）とともにあること', () => {
    const catalog = readCatalog();
    expect(catalog.distros).toBeDefined();
    const distros = catalog.distros as Record<string, CatalogDistro>;
    expect(Object.keys(distros).sort()).toEqual([...FAMILIES].sort());
    for (const family of FAMILIES) {
      expect(distros[family].eol?.slug, family).toBe(FAMILY_SLUGS[family]);
      expect(Array.isArray(distros[family].releases), family).toBe(true);
    }
  });

  it('H8 のリリースと、RHEL / CentOS / AlmaLinux / Rocky の 7〜10 のうち存在するものが、すべて載っていること', () => {
    const distros = readCatalog().distros as Record<string, CatalogDistro>;
    for (const family of FAMILIES) {
      for (const rel of REQUIRED_RELEASES[family]) {
        expect(distros[family].releases, `${family}:${rel}`).toContain(rel);
      }
    }
  });

  it('存在しないリリース（CentOS Linux 9・10、AlmaLinux 7、Rocky Linux 7）は載せないこと（陰性）', () => {
    const distros = readCatalog().distros as Record<string, CatalogDistro>;
    expect(distros.centos.releases).not.toContain('9');
    expect(distros.centos.releases).not.toContain('10');
    expect(distros.almalinux.releases).not.toContain('7');
    expect(distros.rocky.releases).not.toContain('7');
  });

  it('OS は製品（products）に入れないこと（libraries のキーが増えない。既存の製品の取得結果を変えない）', () => {
    const catalog = readCatalog();
    for (const family of FAMILIES) {
      expect(Object.keys(catalog.products)).not.toContain(family);
      expect(Object.keys(catalog.products)).not.toContain(FAMILY_SLUGS[family]);
    }
    for (const p of ['apache', 'nginx', 'php']) expect(Object.keys(catalog.products)).toContain(p);
  });
});

describe('T02: distro-map.json の形', () => {
  it('ファイルがあり、entries が空でない配列であること', () => {
    expect(fs.existsSync(MAP_PATH)).toBe(true);
    const map = readMap();
    expect(Array.isArray(map.entries)).toBe(true);
    expect(map.entries.length).toBeGreaterThan(0);
  });

  it('受け入れ条件 1: 全項目に evidenceUrl（https の URL）と verifiedAt（YYYY-MM-DD の実在する日付で、今日より後でない）があること', () => {
    for (const e of readMap().entries) {
      const label = `${e.release} ${e.product} ${e.sourcePackage}`;
      expect(typeof e.evidenceUrl, label).toBe('string');
      const u = new URL(e.evidenceUrl);
      expect(u.protocol, label).toBe('https:');
      expect(u.username || u.password, label).toBe('');
      expect(e.evidenceUrl, label).not.toMatch(/["'<>\s`]/);
      expect(isValidIsoDate(e.verifiedAt), `${label}: verifiedAt=${String(e.verifiedAt)}`).toBe(true);
      expect(e.verifiedAt <= todayIso(), `${label}: verifiedAt が未来です`).toBe(true);
    }
  });

  it('各項目が §5.1 の項目（family・release・codename・product・upstreamVersions・sourcePackage）を正しい形で持つこと', () => {
    const distros = readCatalog().distros as Record<string, CatalogDistro>;
    for (const e of readMap().entries) {
      const label = `${e.release} ${e.product}`;
      expect(FAMILIES, label).toContain(e.family);
      // release は「系統:サイクル」で、サイクルは catalog の OS の節にある
      const m = /^([a-z]+):([0-9][0-9.]*)$/.exec(e.release);
      expect(m, label).not.toBeNull();
      expect(m?.[1], label).toBe(e.family);
      expect(distros[e.family].releases, label).toContain(m?.[2]);
      expect(PRODUCTS, label).toContain(e.product);
      // codename は Debian / Ubuntu では小文字の名前、RHEL 系では null
      if (e.family === 'debian' || e.family === 'ubuntu') expect(e.codename, label).toMatch(/^[a-z]+$/);
      else expect(e.codename, label).toBeNull();
      // ソースパッケージ名（Debian Policy 5.6.1 の文字）
      expect(e.sourcePackage, label).toMatch(/^[a-z0-9][a-z0-9.+-]+$/);
      // 上流版だけ（epoch・Debian の revision・~ の付いた版は書かない）
      expect(Array.isArray(e.upstreamVersions) && e.upstreamVersions.length > 0, label).toBe(true);
      for (const v of e.upstreamVersions) expect(v, label).toMatch(/^\d+(?:\.\d+)+[a-z]?$/);
      expect(new Set(e.upstreamVersions).size, `${label}: upstreamVersions が重複しています`).toBe(e.upstreamVersions.length);
    }
  });

  it('同じ「リリース・製品・ソースパッケージ」の項目は 1 つだけであること', () => {
    const seen = new Set<string>();
    for (const e of readMap().entries) {
      const key = `${e.release}|${e.product}|${e.sourcePackage}`;
      expect(seen.has(key), `重複: ${key}`).toBe(false);
      seen.add(key);
    }
  });

  it('catalog の OS の節にある全リリースに、少なくとも 1 つの項目があること（書き漏れの検出）', () => {
    const distros = readCatalog().distros as Record<string, CatalogDistro>;
    const releases = new Set(readMap().entries.map((e) => e.release));
    for (const family of FAMILIES) {
      for (const rel of distros[family].releases ?? []) expect(releases.has(`${family}:${rel}`), `${family}:${rel}`).toBe(true);
    }
  });

  it('Debian / Ubuntu のソースパッケージ名は §4.1 のとおり（Apache は apache2、PHP は版ごとの phpX.Y で、上流版はその X.Y で始まる）であること', () => {
    for (const e of readMap().entries.filter((x) => x.family === 'debian' || x.family === 'ubuntu')) {
      const label = `${e.release} ${e.product}`;
      if (e.product === 'apache') expect(e.sourcePackage, label).toBe('apache2');
      if (e.product === 'nginx') expect(e.sourcePackage, label).toBe('nginx');
      if (e.product === 'openssl') expect(e.sourcePackage, label).toBe('openssl');
      if (e.product === 'php') {
        const m = /^php(\d+\.\d+)$/.exec(e.sourcePackage);
        expect(m, label).not.toBeNull();
        for (const v of e.upstreamVersions) expect(v.startsWith(`${m?.[1]}.`), `${label}: ${v}`).toBe(true);
      }
    }
  });

  it('H8: Debian / Ubuntu の各リリースに apache・nginx・php・openssl の 4 製品があること', () => {
    const distros = readCatalog().distros as Record<string, CatalogDistro>;
    const entries = readMap().entries;
    for (const family of ['debian', 'ubuntu'] as const) {
      for (const rel of distros[family].releases ?? []) {
        const products = new Set<string>(entries.filter((e) => e.release === `${family}:${rel}`).map((e) => e.product));
        for (const p of PRODUCTS) expect(products.has(p), `${family}:${rel} ${p}`).toBe(true);
      }
    }
  });
});

describe('T02: 受け入れ条件 2（同じ系統・製品・上流版が複数のリリースにある）', () => {
  /** 系統・製品・上流版 → それを含むリリースの一覧 */
  const releasesByUpstream = (entries: DistroMapEntry[]): Map<string, Set<string>> => {
    const out = new Map<string, Set<string>>();
    for (const e of entries) {
      for (const v of e.upstreamVersions) {
        const key = `${e.family}|${e.product}|${v}`;
        if (!out.has(key)) out.set(key, new Set());
        out.get(key)?.add(e.release);
      }
    }
    return out;
  };

  it('一次資料（Launchpad）で確かめた例: nginx の上流版 1.18.0 は Ubuntu 20.04 と 22.04 の両方に載っていること', () => {
    const rels = releasesByUpstream(readMap().entries).get('ubuntu|nginx|1.18.0');
    expect(rels).toBeDefined();
    expect([...(rels ?? [])].sort()).toEqual(['ubuntu:20.04', 'ubuntu:22.04']);
  });

  it('同じ上流版が複数のリリースにあるとき、リリースごとの別の項目として表現されていること（1 つの項目に複数のリリースを詰めない）', () => {
    const entries = readMap().entries;
    const multi = [...releasesByUpstream(entries).entries()].filter(([, rels]) => rels.size >= 2);
    expect(multi.length).toBeGreaterThan(0);
    for (const e of entries) expect(typeof e.release).toBe('string');
  });
});
