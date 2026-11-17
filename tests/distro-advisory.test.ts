/**
 * v1.8.1 T06: CVE ごとのディストリの判定（distroStatus）の単体テスト
 *
 * - §4.2 の 6 区分（not-fixed・open・unknown-revision・no-data・fixed・not-affected）になる入力と、要確認件数への入り方（H4a）
 * - 版の比較は T01 の dpkg 比較だけを使う（§4.2）
 * - 候補のリリースが 2 件以上なら候補ごとに照合し、結果が分かれたら悪いほうを採って注記する（§4.1）
 * - 第三者リポジトリ・バックポート・推定できないリリース・RHEL 系・ディストリのデータが無い DB では判定しない（H5・H9・H1・§5.3）
 * - ディストリにだけある CVE は not-fixed のものだけ並べ、fixed は件数だけ数える（§4.1・§4.2）
 *
 * ディストリのデータは、このファイルの中で作る合成のデータ（T05 の圧縮後の形）を使う。
 */
import * as fs from 'fs';
import * as path from 'path';
import { describe, expect, it } from 'vitest';
import { assessDistroAdvisories } from '../src/detection/distro-advisory';
import { inferDistroFromHeaders } from '../src/detection/distro-inference';
import type {
  AdvisoryDistroSection,
  DistroAdvisoryEntry,
  DistroInference,
  DistroMapEntry,
  DistroSourceRecord,
} from '../src/shared/types';
import { REPO_ROOT } from './helpers/release-version';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

const FORBIDDEN_WORDS = ['該当なし', '安全', 'Not Affected', '影響はありません'];
const ALL_STATUSES = ['not-fixed', 'open', 'unknown-revision', 'no-data', 'fixed', 'not-affected'] as const;
type Status = (typeof ALL_STATUSES)[number];
const COUNTED: Record<Status, boolean> = {
  'not-fixed': true,
  open: true,
  'unknown-revision': true,
  'no-data': true,
  fixed: false,
  'not-affected': false,
};

const TODAY = new Date().toISOString().slice(0, 10);
const PKG = '7.4.3-4ubuntu2.19';
const OLDER_FIX = '7.4.3-4ubuntu2.10';
const NEWER_FIX = '7.4.3-4ubuntu2.24';
const CVE_A = 'CVE-2022-31628';
const CVE_B = 'CVE-2024-4577';
const CVE_ONLY_DISTRO_1 = 'CVE-2020-7071';
const CVE_ONLY_DISTRO_2 = 'CVE-2021-21702';
const CVE_ONLY_DISTRO_3 = 'CVE-2021-21703';

function mapEntry(release: string, product: DistroMapEntry['product'], upstream: string, sourcePackage: string): DistroMapEntry {
  const [family, cycle] = release.split(':') as [DistroMapEntry['family'], string];
  return {
    family,
    release,
    codename: `${family}-${cycle}`,
    product,
    upstreamVersions: [upstream],
    sourcePackage,
    verifiedAt: TODAY,
    evidenceUrl: 'https://launchpad.net/ubuntu',
  };
}

const SOURCES: DistroSourceRecord[] = [
  { name: 'OSV.dev (Debian Security Tracker)', url: 'https://osv.dev/list?ecosystem=Debian', ecosystem: 'Debian', license: null, licenseNote: '確認中', retrievedAt: null, recordCount: 0 },
  { name: 'OSV.dev (Ubuntu Security Notices)', url: 'https://github.com/canonical/ubuntu-security-notices', ecosystem: 'Ubuntu', license: 'CC-BY-SA-4.0', retrievedAt: null, recordCount: 0 },
  { name: 'endoflife.date', url: 'https://endoflife.date/', ecosystem: null, license: 'MIT', retrievedAt: null, recordCount: 0 },
];

/** 合成の distro 節。advisories は release → sourcePackage → CVE（T05 の形） */
function distroWith(advisories: Record<string, Record<string, DistroAdvisoryEntry[]>> | undefined): AdvisoryDistroSection {
  return {
    releases: [],
    map: [
      mapEntry('ubuntu:20.04', 'php', '7.4.3', 'php7.4'),
      mapEntry('ubuntu:22.04', 'php', '7.4.3', 'php7.4'),
      mapEntry('ubuntu:20.04', 'apache', '2.4.41', 'apache2'),
      mapEntry('debian:12', 'apache', '2.4.62', 'apache2'),
      mapEntry('rhel:9', 'apache', '2.4.62', 'httpd'),
    ],
    ...(advisories ? { advisories, _source: SOURCES } : {}),
  };
}

function fixedEntry(cve: string, fixedVersions: string[], osvIds = [`UBUNTU-${cve}`]): DistroAdvisoryEntry {
  return { cve, status: 'fixed', fixedVersions, osvIds };
}
function openEntry(cve: string, osvIds = [`UBUNTU-${cve}`]): DistroAdvisoryEntry {
  return { cve, status: 'open', fixedVersions: [], osvIds };
}
function notAffectedEntry(cve: string, osvIds = [`UBUNTU-${cve}`]): DistroAdvisoryEntry {
  return { cve, status: 'not-affected', fixedVersions: [], osvIds };
}

function inference(candidates: string[], overrides: Partial<DistroInference> = {}): DistroInference {
  const family = (candidates[0]?.split(':')[0] ?? 'ubuntu') as DistroInference['family'];
  return {
    family,
    release: candidates.length === 1 ? candidates[0] : null,
    candidates,
    confidence: candidates.length === 1 ? 'medium' : candidates.length > 1 ? 'low' : 'none',
    evidence: [],
    ...overrides,
  };
}

/** PHP 7.4.3（ubuntu:20.04、php7.4）を、指定のパッケージ版と CVE で判定する */
function assessPhp(entries: DistroAdvisoryEntry[] | undefined, opts: { packageVersion?: string | null; upstreamCves?: string[] } = {}) {
  const advisories: Record<string, Record<string, DistroAdvisoryEntry[]>> =
    entries === undefined ? {} : { 'ubuntu:20.04': { 'php7.4': entries } };
  return assessDistroAdvisories({
    product: 'php',
    upstreamVersion: '7.4.3',
    packageVersion: opts.packageVersion === undefined ? PKG : opts.packageVersion,
    inference: inference(['ubuntu:20.04']),
    upstreamCves: opts.upstreamCves ?? [CVE_A],
    distro: distroWith(advisories),
  });
}

function cveOf(result: ReturnType<typeof assessDistroAdvisories>, cve: string) {
  expect(result, '判定の結果が null').not.toBeNull();
  const found = result!.cves.find((c) => c.cve === cve);
  expect(found, `${cve} が cves に無い`).toBeDefined();
  return found!;
}

describe('T06 前提: パッケージの版（packageVersion）を推定の結果に持たせる', () => {
  const distro = (rawFixtureDb as unknown as { distro: AdvisoryDistroSection }).distro;

  it.each([
    ['PHP/7.4.3-4ubuntu2.19', 'php', '7.4.3-4ubuntu2.19'],
    ['PHP/7.4.33-1+deb11u5', 'php', '7.4.33-1+deb11u5'],
  ] as const)('X-Powered-By: %s のパッケージ版は %s の推定に packageVersion として残る', (value, product, expected) => {
    const r = inferDistroFromHeaders({ 'x-powered-by': [value] }, distro);
    expect(r[product]?.packageVersion).toBe(expected);
  });

  it.each([['Apache/2.4.41 (Ubuntu)', 'apache'], ['nginx/1.18.0 (Ubuntu)', 'nginx']] as const)(
    'Server: %s のように括弧内の OS 名しか無い版では packageVersion を付けない（陰性）',
    (value, product) => {
      const r = inferDistroFromHeaders({ server: [value] }, distro);
      expect(r[product]).toBeDefined();
      expect(r[product]?.packageVersion).toBeUndefined();
    }
  );
});

describe('T06 §4.2: 6 区分それぞれになる入力と、要確認件数への入り方（受け入れ条件 1）', () => {
  const SCENARIOS: Array<[Status, () => ReturnType<typeof assessDistroAdvisories>]> = [
    ['not-fixed', () => assessPhp([fixedEntry(CVE_A, [NEWER_FIX])])],
    ['open', () => assessPhp([openEntry(CVE_A)])],
    ['unknown-revision', () => assessPhp([fixedEntry(CVE_A, [OLDER_FIX])], { packageVersion: null })],
    ['no-data', () => assessPhp([fixedEntry(CVE_B, [OLDER_FIX])])],
    ['fixed', () => assessPhp([fixedEntry(CVE_A, [OLDER_FIX])])],
    ['not-affected', () => assessPhp([notAffectedEntry(CVE_A)])],
  ];

  it.each(SCENARIOS)('%s: 区分と counted（要確認件数に数えるか）が §4.2 の表のとおり', (status, run) => {
    const result = run();
    const c = cveOf(result, CVE_A);
    expect(c.distroStatus).toBe(status);
    expect(c.counted).toBe(COUNTED[status]);
    expect(result!.reviewCount).toBe(COUNTED[status] ? 1 : 0);
  });

  it('6 区分のテストが §4.2 の表の区分をすべて覆う', () => {
    expect(SCENARIOS.map(([s]) => s).sort()).toEqual([...ALL_STATUSES].sort());
  });

  it('reviewCount は、並べた CVE のうち counted のものの件数', () => {
    const result = assessPhp([fixedEntry(CVE_A, [NEWER_FIX]), fixedEntry(CVE_B, [OLDER_FIX])], { upstreamCves: [CVE_A, CVE_B] });
    expect(cveOf(result, CVE_A).distroStatus).toBe('not-fixed');
    expect(cveOf(result, CVE_B).distroStatus).toBe('fixed');
    expect(result!.reviewCount).toBe(result!.cves.filter((c) => c.counted).length);
    expect(result!.reviewCount).toBe(1);
  });

  it('上流の照合で出た CVE は、区分にかかわらずすべて並べる（origin: upstream）', () => {
    const result = assessPhp([fixedEntry(CVE_A, [OLDER_FIX]), notAffectedEntry(CVE_B)], { upstreamCves: [CVE_A, CVE_B] });
    const upstream = result!.cves.filter((c) => c.origin === 'upstream').map((c) => c.cve).sort();
    expect(upstream).toEqual([CVE_A, CVE_B].sort());
  });

  it('no-data: リリースのデータが無い（advisories にリリースのキーが無い）ときも no-data で数える', () => {
    const c = cveOf(assessPhp(undefined), CVE_A);
    expect(c.distroStatus).toBe('no-data');
    expect(c.counted).toBe(true);
  });

  it('no-data: そのリリースにソースパッケージのデータが無いときも no-data で数える', () => {
    const result = assessDistroAdvisories({
      product: 'php',
      upstreamVersion: '7.4.3',
      packageVersion: PKG,
      inference: inference(['ubuntu:20.04']),
      upstreamCves: [CVE_A],
      distro: distroWith({ 'ubuntu:20.04': { apache2: [fixedEntry(CVE_A, [OLDER_FIX])] } }),
    });
    expect(cveOf(result, CVE_A).distroStatus).toBe('no-data');
  });

  it('unknown-revision はディストリに修正版があるときだけ。パッケージ版が無くても open と not-affected はそのまま', () => {
    expect(cveOf(assessPhp([openEntry(CVE_A)], { packageVersion: null }), CVE_A).distroStatus).toBe('open');
    expect(cveOf(assessPhp([notAffectedEntry(CVE_A)], { packageVersion: null }), CVE_A).distroStatus).toBe('not-affected');
  });

  it('Apache（括弧内の OS 名だけ。パッケージ版なし）で修正版があれば unknown-revision', () => {
    const result = assessDistroAdvisories({
      product: 'apache',
      upstreamVersion: '2.4.41',
      packageVersion: null,
      inference: inference(['ubuntu:20.04']),
      upstreamCves: ['CVE-2021-44790'],
      distro: distroWith({ 'ubuntu:20.04': { apache2: [fixedEntry('CVE-2021-44790', ['2.4.41-4ubuntu3.10'])] } }),
    });
    const c = cveOf(result, 'CVE-2021-44790');
    expect(c.distroStatus).toBe('unknown-revision');
    expect(c.fixedVersions).toEqual(['2.4.41-4ubuntu3.10']);
    expect(c.counted).toBe(true);
  });

  it('各 CVE に、照合したリリースとソースパッケージ、修正版、OSV ID が残る', () => {
    const c = cveOf(assessPhp([fixedEntry(CVE_A, [NEWER_FIX], [`UBUNTU-${CVE_A}`, 'USN-5717-1'])]), CVE_A);
    expect(c.release).toBe('ubuntu:20.04');
    expect(c.sourcePackage).toBe('php7.4');
    expect(c.fixedVersions).toEqual([NEWER_FIX]);
    expect([...c.osvIds].sort()).toEqual([`UBUNTU-${CVE_A}`, 'USN-5717-1'].sort());
  });
});

describe('T06 §4.2: 版の比較は T01 の dpkg 比較だけを使う', () => {
  it.each([
    ['revision の数字は数として比べる（2.19 ≧ 2.2）', PKG, ['7.4.3-4ubuntu2.2'], 'fixed'],
    ['同じ版は修正済みの可能性が高い（≧）', PKG, [PKG], 'fixed'],
    ['+esm の付いた修正版より古い', PKG, [`${PKG}+esm1`], 'not-fixed'],
    ['~ は空より前（1~deb12u1 < 1）', '2.4.62-1~deb12u1', ['2.4.62-1'], 'not-fixed'],
    ['epoch が大きい修正版より古い', PKG, ['1:7.4.3-1'], 'not-fixed'],
  ] as Array<[string, string, string[], Status]>)('%s', (_label, pkg, fixedVersions, expected) => {
    const isDebian = pkg.includes('deb');
    const release = isDebian ? 'debian:12' : 'ubuntu:20.04';
    const product = isDebian ? 'apache' : 'php';
    const sourcePackage = isDebian ? 'apache2' : 'php7.4';
    const result = assessDistroAdvisories({
      product,
      upstreamVersion: isDebian ? '2.4.62' : '7.4.3',
      packageVersion: pkg,
      inference: inference([release]),
      upstreamCves: [CVE_A],
      distro: distroWith({ [release]: { [sourcePackage]: [fixedEntry(CVE_A, fixedVersions, [`DEBIAN-${CVE_A}`])] } }),
    });
    expect(cveOf(result, CVE_A).distroStatus).toBe(expected);
  });

  it('修正版が複数あるときは、すべての修正版以上のときだけ fixed（安全側）', () => {
    expect(cveOf(assessPhp([fixedEntry(CVE_A, [OLDER_FIX, NEWER_FIX])]), CVE_A).distroStatus).toBe('not-fixed');
    expect(cveOf(assessPhp([fixedEntry(CVE_A, [OLDER_FIX, '7.4.3-4ubuntu2.2'])]), CVE_A).distroStatus).toBe('fixed');
  });

  it('判定のモジュールは上流の版比較（version-matcher）を使わず、dpkg 比較（dpkg-version）を使う', () => {
    const src = fs.readFileSync(path.join(REPO_ROOT, 'src', 'detection', 'distro-advisory.ts'), 'utf-8');
    expect(src).toMatch(/from\s+['"]\.\.\/security\/dpkg-version['"]/);
    expect(src).not.toMatch(/from\s+['"]\.\.\/security\/version-matcher['"]/);
  });
});

describe('T06 §4.1: 候補のリリースが 2 件で結果が分かれたら悪いほうを採り、注記する（受け入れ条件 2）', () => {
  function assessSplit(e2004: DistroAdvisoryEntry[], e2204: DistroAdvisoryEntry[], upstreamCves = [CVE_A]) {
    return assessDistroAdvisories({
      product: 'php',
      upstreamVersion: '7.4.3',
      packageVersion: PKG,
      inference: inference(['ubuntu:20.04', 'ubuntu:22.04']),
      upstreamCves,
      distro: distroWith({ 'ubuntu:20.04': { 'php7.4': e2004 }, 'ubuntu:22.04': { 'php7.4': e2204 } }),
    });
  }

  it('20.04 では fixed、22.04 では not-fixed → not-fixed を採り、数える。分かれたことを注記する', () => {
    const result = assessSplit([fixedEntry(CVE_A, [OLDER_FIX])], [fixedEntry(CVE_A, [NEWER_FIX])]);
    const c = cveOf(result, CVE_A);
    expect(c.distroStatus).toBe('not-fixed');
    expect(c.counted).toBe(true);
    expect(c.split).toBe(true);
    expect(c.release).toBe('ubuntu:22.04');
    expect(c.fixedVersions).toEqual([NEWER_FIX]);
    expect(result!.splitNote).toMatch(/分かれ/);
    expect(result!.releases).toEqual(['ubuntu:20.04', 'ubuntu:22.04']);
  });

  it('候補ごとの結果（perRelease）を残す', () => {
    const c = cveOf(assessSplit([fixedEntry(CVE_A, [OLDER_FIX])], [fixedEntry(CVE_A, [NEWER_FIX])]), CVE_A);
    const per = Object.fromEntries((c.perRelease ?? []).map((p) => [p.release, p.distroStatus]));
    expect(per).toEqual({ 'ubuntu:20.04': 'fixed', 'ubuntu:22.04': 'not-fixed' });
  });

  it('順番を入れ替えても悪いほうを採る（20.04 が not-fixed、22.04 が fixed）', () => {
    const c = cveOf(assessSplit([fixedEntry(CVE_A, [NEWER_FIX])], [fixedEntry(CVE_A, [OLDER_FIX])]), CVE_A);
    expect(c.distroStatus).toBe('not-fixed');
    expect(c.release).toBe('ubuntu:20.04');
  });

  it('片方が not-affected、もう片方にデータが無い → no-data を採り、数える', () => {
    const c = cveOf(assessSplit([notAffectedEntry(CVE_A)], []), CVE_A);
    expect(c.distroStatus).toBe('no-data');
    expect(c.counted).toBe(true);
    expect(c.split).toBe(true);
  });

  it('両方が同じ結果なら分かれた注記を付けない（陰性）', () => {
    const result = assessSplit([fixedEntry(CVE_A, [OLDER_FIX])], [fixedEntry(CVE_A, ['7.4.3-4ubuntu2.2'])]);
    const c = cveOf(result, CVE_A);
    expect(c.distroStatus).toBe('fixed');
    expect(c.split).toBeFalsy();
    expect(result!.splitNote).toBeUndefined();
  });

  it('候補が 1 件なら分かれた注記を付けない（陰性）', () => {
    const result = assessPhp([fixedEntry(CVE_A, [NEWER_FIX])]);
    expect(cveOf(result, CVE_A).split).toBeFalsy();
    expect(result!.splitNote).toBeUndefined();
  });
});

describe('T06 H5・H9・H1・§5.3: ディストリのデータで判定しない入力（受け入れ条件 3）', () => {
  const ADVISORIES = {
    'ubuntu:20.04': { 'php7.4': [fixedEntry(CVE_A, [OLDER_FIX])], apache2: [fixedEntry(CVE_A, [OLDER_FIX])] },
    'ubuntu:22.04': { 'php7.4': [fixedEntry(CVE_A, [OLDER_FIX])] },
    'rhel:9': { httpd: [fixedEntry(CVE_A, ['2.4.62-1.el9'])] },
  };

  it.each([
    ['第三者リポジトリ（deb.sury.org）', inference([], { family: 'ubuntu', thirdParty: { kind: 'third-party', marker: 'deb.sury.org' } })],
    ['第三者リポジトリ（+ubuntuNN.NN）', inference([], { family: 'ubuntu', thirdParty: { kind: 'third-party', marker: '+ubuntu20.04.1' } })],
    ['バックポート（~bpo）', inference([], { family: 'debian', thirdParty: { kind: 'backport', marker: '~bpo10+1' } })],
    ['リリースを推定できない（確信度 none）', inference([], { family: 'ubuntu' })],
    ['RHEL 系（第2段階まで）', inference(['rhel:9'])],
  ])('%s: null を返す', (_label, inf) => {
    const result = assessDistroAdvisories({
      product: 'php',
      upstreamVersion: '7.4.3',
      packageVersion: PKG,
      inference: inf,
      upstreamCves: [CVE_A],
      distro: distroWith(ADVISORIES),
    });
    expect(result).toBeNull();
  });

  it('第三者の印があれば、candidates に値が残っていてもディストリのデータを使わない', () => {
    const result = assessDistroAdvisories({
      product: 'php',
      upstreamVersion: '7.4.3',
      packageVersion: PKG,
      inference: inference(['ubuntu:20.04'], { thirdParty: { kind: 'third-party', marker: 'deb.sury.org' } }),
      upstreamCves: [CVE_A],
      distro: distroWith(ADVISORIES),
    });
    expect(result).toBeNull();
  });

  it.each([
    ['distro 節が無い DB（null）', null],
    ['distro 節が無い DB（undefined）', undefined],
    ['advisories の無い distro 節（T02 までの DB・固定 DB）', distroWith(undefined)],
  ])('%s: null を返す（第1段階・第2段階の表示のまま）', (_label, distro) => {
    const result = assessDistroAdvisories({
      product: 'php',
      upstreamVersion: '7.4.3',
      packageVersion: PKG,
      inference: inference(['ubuntu:20.04']),
      upstreamCves: [CVE_A],
      distro,
    });
    expect(result).toBeNull();
  });
});

describe('T06 §4.1・§4.2: ディストリにだけある CVE', () => {
  const DISTRO_ONLY = [
    fixedEntry(CVE_ONLY_DISTRO_1, [NEWER_FIX]), // not-fixed
    fixedEntry(CVE_ONLY_DISTRO_2, [OLDER_FIX]), // fixed
    fixedEntry(CVE_ONLY_DISTRO_3, ['7.4.3-4ubuntu2.2']), // fixed
  ];

  it('not-fixed のものは並べて数え（origin: distro）、fixed のものは並べずに件数（otherFixedCount）だけ数える', () => {
    const result = assessPhp([fixedEntry(CVE_A, [OLDER_FIX]), ...DISTRO_ONLY]);
    const listed = result!.cves.map((c) => c.cve);
    const onlyDistro = cveOf(result, CVE_ONLY_DISTRO_1);
    expect(onlyDistro.origin).toBe('distro');
    expect(onlyDistro.distroStatus).toBe('not-fixed');
    expect(onlyDistro.counted).toBe(true);
    expect(listed).not.toContain(CVE_ONLY_DISTRO_2);
    expect(listed).not.toContain(CVE_ONLY_DISTRO_3);
    expect(result!.otherFixedCount).toBe(2);
    expect(result!.reviewCount).toBe(1);
  });

  it('ディストリにだけある open と not-affected の CVE は並べず、数えない（照合の対象は not-fixed だけ）', () => {
    const result = assessPhp([fixedEntry(CVE_A, [OLDER_FIX]), openEntry(CVE_ONLY_DISTRO_1), notAffectedEntry(CVE_ONLY_DISTRO_2)]);
    expect(result!.cves.map((c) => c.cve)).toEqual([CVE_A]);
    expect(result!.otherFixedCount).toBe(0);
    expect(result!.reviewCount).toBe(0);
  });

  it('パッケージ版が取れない（Apache）とき、ディストリにだけある CVE は並べない（unknown-revision を増やさない）', () => {
    const result = assessDistroAdvisories({
      product: 'apache',
      upstreamVersion: '2.4.41',
      packageVersion: null,
      inference: inference(['ubuntu:20.04']),
      upstreamCves: ['CVE-2021-44790'],
      distro: distroWith({
        'ubuntu:20.04': { apache2: [fixedEntry('CVE-2021-44790', ['2.4.41-4ubuntu3.10']), fixedEntry(CVE_ONLY_DISTRO_1, ['2.4.41-4ubuntu3.12'])] },
      }),
    });
    expect(result!.cves.map((c) => c.cve)).toEqual(['CVE-2021-44790']);
    expect(result!.otherFixedCount).toBe(0);
  });
});

describe('T06 §4.2: ESM・出典・文言', () => {
  it('Ubuntu Pro（ESM）だけの修正は esm が付き、文言で「ESM で修正」と区別する', () => {
    const entry: DistroAdvisoryEntry = { cve: CVE_A, status: 'fixed', fixedVersions: [`${PKG}+esm1`], esm: true, osvIds: [`UBUNTU-${CVE_A}`] };
    const c = cveOf(assessPhp([entry]), CVE_A);
    expect(c.esm).toBe(true);
    expect(c.message).toContain('ESM で修正');
  });

  it('標準の修正（esm なし）では「ESM で修正」と書かない（陰性）', () => {
    const c = cveOf(assessPhp([fixedEntry(CVE_A, [NEWER_FIX])]), CVE_A);
    expect(c.esm).toBeFalsy();
    expect(c.message).not.toContain('ESM で修正');
  });

  it('sources に、その系統の OSV の出典（distro._source の要素）が入る', () => {
    const result = assessPhp([fixedEntry(CVE_A, [OLDER_FIX])]);
    const ubuntu = result!.sources.find((s) => s.ecosystem === 'Ubuntu');
    expect(ubuntu).toMatchObject({ name: SOURCES[1].name, url: SOURCES[1].url, license: 'CC-BY-SA-4.0' });
  });

  it.each([
    ['not-fixed', () => assessPhp([fixedEntry(CVE_A, [NEWER_FIX])]), [NEWER_FIX, '更新']],
    ['open', () => assessPhp([openEntry(CVE_A)]), ['未修正']],
    ['unknown-revision', () => assessPhp([fixedEntry(CVE_A, [OLDER_FIX])], { packageVersion: null }), [OLDER_FIX, 'サーバー']],
    ['no-data', () => assessPhp([]), ['バックポート']],
    ['fixed', () => assessPhp([fixedEntry(CVE_A, [OLDER_FIX])]), ['ディストリで修正済みの可能性が高い']],
    ['not-affected', () => assessPhp([notAffectedEntry(CVE_A)]), ['影響なし']],
  ] as Array<[Status, () => ReturnType<typeof assessDistroAdvisories>, string[]]>)(
    '%s: 文言に §4.2 の要旨が入り、禁止語が無い',
    (status, run, keywords) => {
      const result = run();
      const c = cveOf(result, CVE_A);
      expect(c.distroStatus).toBe(status);
      for (const k of keywords) expect(c.message).toContain(k);
      for (const text of [c.message, result!.splitNote ?? '']) {
        for (const w of FORBIDDEN_WORDS) expect(text, `「${w}」を含む`).not.toContain(w);
      }
    }
  );

  it('分かれた注記にも禁止語が無い', () => {
    const result = assessDistroAdvisories({
      product: 'php',
      upstreamVersion: '7.4.3',
      packageVersion: PKG,
      inference: inference(['ubuntu:20.04', 'ubuntu:22.04']),
      upstreamCves: [CVE_A],
      distro: distroWith({ 'ubuntu:20.04': { 'php7.4': [notAffectedEntry(CVE_A)] }, 'ubuntu:22.04': { 'php7.4': [openEntry(CVE_A)] } }),
    });
    expect(result!.splitNote).toBeDefined();
    for (const w of FORBIDDEN_WORDS) expect(result!.splitNote!, `「${w}」を含む`).not.toContain(w);
  });
});
