/**
 * v1.8.1 T03: OS リリースの推定（src/detection/distro-inference.ts）の受け入れテスト
 *
 * 指示書 §3.1（推定の手順と確信度の表）・§3.2（判定）・H4・H5・H9 を、純粋関数
 * inferDistroFromHeaders / judgeDistroEol で確かめる。
 * - 対応表とライフサイクルは固定 DB（tests/fixtures/advisory-db.fixture.json）の distro 節を使う
 * - 日付は直接書かない。固定 DB の日付から前後の日を計算して now に渡す
 * - 印の一覧（§3.1 手順 1・2「印の一覧はテストで固定する」）は、このファイルの it.each が正
 */
import { describe, expect, it } from 'vitest';
import type { AdvisoryDistroSection, DistroInference, DistroReleaseLifecycle } from '../src/shared/types';
import { inferDistroFromHeaders, judgeDistroEol } from '../src/detection/distro-inference';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

const fixtureDistro = (rawFixtureDb as unknown as { distro: AdvisoryDistroSection }).distro;

const FORBIDDEN_WORDS = ['該当なし', '安全', 'Not Affected'];

/** 固定 DB のライフサイクルを 1 件取り出す（無ければテストの前提が崩れているので落とす） */
function lifecycleOf(release: string): DistroReleaseLifecycle {
  const r = fixtureDistro.releases.find((x) => x.release === release);
  if (!r || !r.standardSupportEnd) throw new Error(`固定 DB に ${release} の標準サポート終了日がありません`);
  return r;
}

/** YYYY-MM-DD に日数を足した日の正午（UTC）の Date */
function dayAt(isoDate: string, shiftDays: number): Date {
  return new Date(Date.parse(`${isoDate}T12:00:00Z`) + shiftDays * 86_400_000);
}

/** 固定 DB の対応表で、系統・製品・上流版を含むリリースの一覧 */
function mapReleases(family: string, product: string, upstream: string): string[] {
  return fixtureDistro.map
    .filter((e) => e.family === family && e.product === product && e.upstreamVersions.includes(upstream))
    .map((e) => e.release);
}

function infer(headers: Record<string, string[]>, distro: AdvisoryDistroSection | null | undefined = fixtureDistro) {
  return inferDistroFromHeaders(headers, distro);
}

/** オブジェクトの中の文字列をすべて集める（文言の検査用） */
function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectStrings(v, out));
  return out;
}

function eolText(eol: { label?: string; note?: string; recommendation?: string }): string {
  return [eol.label, eol.note, eol.recommendation].filter(Boolean).join('\n');
}

describe('T03 §3.1 手順 1: ディストリの系統を決める（括弧内の OS 名）', () => {
  it.each([
    ['Apache/2.4.41 (Ubuntu)', 'ubuntu'],
    ['Apache/2.4.56 (Debian)', 'debian'],
    ['Apache/2.4.37 (Red Hat Enterprise Linux)', 'rhel'],
    ['Apache/2.4.6 (CentOS)', 'centos'],
    ['Apache/2.4.62 (AlmaLinux)', 'almalinux'],
    ['Apache/2.4.62 (Rocky Linux)', 'rocky'],
  ])('Server: %s の系統は %s（陽性）', (server, family) => {
    const r = infer({ server: [server] });
    expect(r.apache).toBeDefined();
    expect(r.apache?.family).toBe(family);
  });

  it.each([
    ['Apache/2.4.58 (Unix)'],
    ['Apache/2.4.58 (Win64)'],
    ['Apache/2.4.58 (Fedora)'],
    ['Apache/2.4.58 (Amazon Linux)'],
    ['Apache/2.4.58'],
  ])('Server: %s はディストリの印が無い（対象の系統でない）ので推定結果を付けない（陰性）', (server) => {
    const r = infer({ server: [server] });
    expect(r.apache).toBeUndefined();
  });

  it.each([['nginx/1.24.0'], ['nginx']])('Server: %s は推定結果を付けない（陰性）', (server) => {
    expect(infer({ server: [server] }).nginx).toBeUndefined();
  });

  it.each([['PHP/8.2.10'], ['PHP/8.0.30-1.fc39'], ['PHP/7.4.33']])(
    'X-Powered-By: %s はディストリの印が無いので推定結果を付けない（陰性）',
    (xpb) => {
      expect(infer({ 'x-powered-by': [xpb] }).php).toBeUndefined();
    }
  );
});

describe('T03 §3.1 手順 1・3.1: パッケージ版の印（ubuntuN・debNuM・.elN）', () => {
  it('PHP/7.4.3-4ubuntu2.19 は系統 ubuntu（ubuntuN の印。リリースは書かれていないので対応表で引く）', () => {
    const php = infer({ 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] }).php;
    expect(php?.family).toBe('ubuntu');
    expect(php?.candidates).toEqual(mapReleases('ubuntu', 'php', '7.4.3'));
    expect(php?.thirdParty).toBeUndefined();
  });

  it.each([
    ['PHP/7.4.33-1+deb11u5', 'debian', 'debian:11'],
    ['PHP/8.2.7-1~deb12u1', 'debian', 'debian:12'],
    ['PHP/8.0.30-1.el9', 'rhel', 'rhel:9'],
    ['PHP/8.0.30-1.el9_4', 'rhel', 'rhel:9'],
  ])('%s はパッケージ版にリリースの印があるので %s / %s、確信度 high（§3.1 表 high の 1 行目）', (xpb, family, release) => {
    const php = infer({ 'x-powered-by': [xpb] }).php;
    expect(php?.family).toBe(family);
    expect(php?.release).toBe(release);
    expect(php?.candidates).toEqual([release]);
    expect(php?.confidence).toBe('high');
    expect(php?.thirdParty).toBeUndefined();
  });

  it('リリースの印は対応表に無い上流版でも使う（対応表より印を優先する）', () => {
    // 固定 DB の rhel:9 には php の項目が無い
    expect(mapReleases('rhel', 'php', '8.0.30')).toEqual([]);
    const php = infer({ 'x-powered-by': ['PHP/8.0.30-1.el9'] }).php;
    expect(php?.release).toBe('rhel:9');
    expect(php?.confidence).toBe('high');
  });
});

describe('T03 §3.1 手順 2: 第三者リポジトリ・バックポート（H5・H9）', () => {
  it.each([
    ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1', /deb\.sury\.org|\+ubuntu20\.04/],
    ['PHP/8.3.6-1+ubuntu22.04.1+deb.sury.org+1', /deb\.sury\.org|\+ubuntu22\.04/],
    ['PHP/8.3.6-1+ubuntu24.04.1', /\+ubuntu24\.04/],
  ])('%s は第三者リポジトリ: リリースを推定せず thirdParty を記録する（受け入れ条件 2）', (xpb, marker) => {
    const php = infer({ 'x-powered-by': [xpb] }).php;
    expect(php).toBeDefined();
    expect(php?.thirdParty).toBeDefined();
    expect(php?.thirdParty?.kind).toBe('third-party');
    expect(php?.thirdParty?.marker).toMatch(marker);
    expect(php?.release).toBeNull();
    expect(php?.candidates).toEqual([]);
    expect(php?.confidence).toBe('none');
    expect(php?.note).toContain('第三者リポジトリ');
  });

  it.each([['PHP/7.4.33-1~bpo10+1'], ['PHP/8.2.7-1~bpo11+2']])(
    '%s は Debian のバックポート: リリースを推定せず thirdParty（kind: backport）を記録する（受け入れ条件 2・H9）',
    (xpb) => {
      const php = infer({ 'x-powered-by': [xpb] }).php;
      expect(php?.thirdParty?.kind).toBe('backport');
      expect(php?.thirdParty?.marker).toContain('~bpo');
      expect(php?.release).toBeNull();
      expect(php?.candidates).toEqual([]);
      expect(php?.confidence).toBe('none');
      expect(php?.note).toMatch(/第三者リポジトリ|バックポート/);
    }
  );

  it.each([['PHP/7.4.3-4ubuntu2.19'], ['PHP/7.4.33-1+deb11u5'], ['PHP/8.2.7-1~deb12u1']])(
    '%s はディストリ自身の版なので thirdParty を付けない（陰性）',
    (xpb) => {
      expect(infer({ 'x-powered-by': [xpb] }).php?.thirdParty).toBeUndefined();
    }
  );

  it('第三者リポジトリの製品は、ほかの製品との積集合に加えない（Apache は対応表 1 件のまま medium）', () => {
    // sury の PHP 7.4.3 を積集合に加えると Apache が high になってしまう
    const r = infer({
      server: ['Apache/2.4.41 (Ubuntu)'],
      'x-powered-by': ['PHP/7.4.3-1+ubuntu20.04.1+deb.sury.org+1'],
    });
    expect(r.php?.thirdParty).toBeDefined();
    expect(r.apache?.candidates).toEqual(['ubuntu:20.04']);
    expect(r.apache?.confidence).toBe('medium');
  });
});

describe('T03 §3.1 手順 3・4: 候補と確信度（表の各行。受け入れ条件 1）', () => {
  it('前提: 固定 DB の対応表で Apache 2.4.41 は ubuntu:20.04 だけ、nginx 1.18.0 は ubuntu:20.04 と 22.04、PHP 7.4.3 は ubuntu:20.04 だけ', () => {
    expect(mapReleases('ubuntu', 'apache', '2.4.41')).toEqual(['ubuntu:20.04']);
    expect(mapReleases('ubuntu', 'nginx', '1.18.0').sort()).toEqual(['ubuntu:20.04', 'ubuntu:22.04']);
    expect(mapReleases('ubuntu', 'php', '7.4.3')).toEqual(['ubuntu:20.04']);
    expect(mapReleases('ubuntu', 'openssl', '1.1.1f')).toEqual(['ubuntu:20.04']);
    expect(mapReleases('ubuntu', 'apache', '2.4.99')).toEqual([]);
  });

  it('medium: 対応表で 1 製品から 1 件に絞れた（Apache/2.4.41 (Ubuntu)）', () => {
    const apache = infer({ server: ['Apache/2.4.41 (Ubuntu)'] }).apache;
    expect(apache?.family).toBe('ubuntu');
    expect(apache?.release).toBe('ubuntu:20.04');
    expect(apache?.candidates).toEqual(['ubuntu:20.04']);
    expect(apache?.confidence).toBe('medium');
  });

  it('low: 候補が 2 件以上（nginx/1.18.0 (Ubuntu) は 20.04 と 22.04）。release は 1 件に絞れないので null', () => {
    const nginx = infer({ server: ['nginx/1.18.0 (Ubuntu)'] }).nginx;
    expect(nginx?.family).toBe('ubuntu');
    expect(nginx?.candidates).toHaveLength(2);
    expect(nginx?.candidates).toEqual(expect.arrayContaining(['ubuntu:20.04', 'ubuntu:22.04']));
    expect(nginx?.release).toBeNull();
    expect(nginx?.confidence).toBe('low');
  });

  it('none: 候補が無い（対応表に無い上流版。自前ビルドや PPA の可能性）', () => {
    const apache = infer({ server: ['Apache/2.4.99 (Ubuntu)'] }).apache;
    expect(apache?.family).toBe('ubuntu');
    expect(apache?.candidates).toEqual([]);
    expect(apache?.release).toBeNull();
    expect(apache?.confidence).toBe('none');
    expect(apache?.thirdParty).toBeUndefined();
    expect(apache?.note).toMatch(/リリースを推定でき/);
  });

  it('high: 複数製品の積集合で 1 件に絞れた（nginx 1.18.0 と PHP 7.4.3-4ubuntu2.19 → ubuntu:20.04）', () => {
    const r = infer({ server: ['nginx/1.18.0 (Ubuntu)'], 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] });
    expect(r.nginx?.release).toBe('ubuntu:20.04');
    expect(r.nginx?.candidates).toEqual(['ubuntu:20.04']);
    expect(r.nginx?.confidence).toBe('high');
    expect(r.php?.release).toBe('ubuntu:20.04');
    expect(r.php?.confidence).toBe('high');
  });

  it('high: 同じ Server ヘッダーの OpenSSL も製品として積集合に使う（Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f）', () => {
    const r = infer({ server: ['Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f'] });
    expect(r.apache?.release).toBe('ubuntu:20.04');
    expect(r.apache?.confidence).toBe('high');
    expect(r.openssl?.release).toBe('ubuntu:20.04');
    expect(r.apache?.evidence.some((e) => e.token.includes('OpenSSL/1.1.1f'))).toBe(true);
  });

  it('積集合が空になったら積集合を使わず、製品ごとの候補を並べる（Apache 2.4.41 は 20.04、PHP 8.1.2 は 22.04）', () => {
    expect(mapReleases('ubuntu', 'php', '8.1.2')).toEqual(['ubuntu:22.04']);
    const r = infer({ server: ['Apache/2.4.41 (Ubuntu)'], 'x-powered-by': ['PHP/8.1.2-1ubuntu2.14'] });
    expect(r.apache?.candidates).toEqual(['ubuntu:20.04']);
    expect(r.apache?.confidence).toBe('medium');
    expect(r.php?.candidates).toEqual(['ubuntu:22.04']);
    expect(r.php?.confidence).toBe('medium');
  });

  it('パッケージ版の印から得たリリースも積集合に加える（Apache 2.4.52 (Debian) と PHP +deb11u5 → debian:11 で high）', () => {
    // Apache 2.4.52 は固定 DB で ubuntu:22.04 と debian:11 にあるが、系統が debian なので debian:11 だけが候補
    expect(mapReleases('debian', 'apache', '2.4.52')).toEqual(['debian:11']);
    const r = infer({ server: ['Apache/2.4.52 (Debian)'], 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] });
    expect(r.apache?.candidates).toEqual(['debian:11']);
    expect(r.apache?.confidence).toBe('high');
  });

  it('対応表は「系統・製品・上流版」で引く（同じ上流版でも別の系統のリリースは候補にしない）', () => {
    expect(mapReleases('ubuntu', 'apache', '2.4.52')).toEqual(['ubuntu:22.04']);
    const apache = infer({ server: ['Apache/2.4.52 (Debian)'] }).apache;
    expect(apache?.candidates).toEqual(['debian:11']);
    expect(apache?.confidence).toBe('medium');
  });

  it('confidence は high・medium・low・none のどれか', () => {
    const all = [
      infer({ server: ['Apache/2.4.41 (Ubuntu)'] }).apache,
      infer({ server: ['nginx/1.18.0 (Ubuntu)'] }).nginx,
      infer({ server: ['Apache/2.4.99 (Ubuntu)'] }).apache,
      infer({ 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] }).php,
    ];
    for (const r of all) expect(['high', 'medium', 'low', 'none']).toContain(r?.confidence);
  });
});

describe('T03 §3.1: evidence（どのヘッダーのどの文字列からそう判断したか）', () => {
  it('推定結果にはヘッダー名・ヘッダーの値・判断に使った文字列・説明を持つ根拠が 1 件以上ある', () => {
    const cases: Array<DistroInference | undefined> = [
      infer({ server: ['Apache/2.4.41 (Ubuntu)'] }).apache,
      infer({ server: ['nginx/1.18.0 (Ubuntu)'] }).nginx,
      infer({ server: ['Apache/2.4.99 (Ubuntu)'] }).apache,
      infer({ 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] }).php,
      infer({ 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }).php,
    ];
    for (const r of cases) {
      expect(r).toBeDefined();
      expect(r!.evidence.length).toBeGreaterThan(0);
      for (const e of r!.evidence) {
        expect(['server', 'x-powered-by']).toContain(e.header);
        expect(typeof e.value === 'string' && e.value.length > 0).toBe(true);
        expect(typeof e.token === 'string' && e.token.length > 0).toBe(true);
        expect(typeof e.detail === 'string' && e.detail.length > 0).toBe(true);
      }
    }
  });

  it('括弧内の OS 名から判断したときは、その Server ヘッダーの値と OS 名を根拠に入れる', () => {
    const apache = infer({ server: ['Apache/2.4.41 (Ubuntu)'] }).apache!;
    expect(apache.evidence.some((e) => e.header === 'server' && e.value === 'Apache/2.4.41 (Ubuntu)' && e.token.includes('Ubuntu'))).toBe(true);
  });

  it('パッケージ版の印から判断したときは、その印を根拠に入れる', () => {
    const php = infer({ 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] }).php!;
    expect(php.evidence.some((e) => e.header === 'x-powered-by' && e.token.includes('deb11u5'))).toBe(true);
  });

  it('第三者リポジトリの印を根拠に入れる', () => {
    const php = infer({ 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }).php!;
    expect(php.evidence.some((e) => e.header === 'x-powered-by' && /deb\.sury\.org|\+ubuntu20\.04/.test(e.token))).toBe(true);
  });

  it('積集合で絞ったときは、ほかの製品のヘッダーも根拠に入れる', () => {
    const r = infer({ server: ['nginx/1.18.0 (Ubuntu)'], 'x-powered-by': ['PHP/7.4.3-4ubuntu2.19'] });
    expect(r.nginx!.evidence.some((e) => e.header === 'x-powered-by')).toBe(true);
    expect(r.php!.evidence.some((e) => e.header === 'server')).toBe(true);
  });
});

describe('T03 §5.3: distro 節が無い DB では推定しない（第1段階のまま）', () => {
  it.each([[undefined], [null]])('distro が %s なら、ディストリの印があっても推定結果は空', (distro) => {
    const r = inferDistroFromHeaders(
      {
        server: ['Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f'],
        'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'],
      },
      distro
    );
    expect(r).toEqual({});
  });

  it('ライフサイクルの取得結果が無い（releases が空）DB でも、対応表から推定する（失敗しない）', () => {
    const distro: AdvisoryDistroSection = { releases: [], map: fixtureDistro.map };
    const apache = infer({ server: ['Apache/2.4.41 (Ubuntu)'] }, distro).apache;
    expect(apache?.release).toBe('ubuntu:20.04');
    expect(apache?.confidence).toBe('medium');
  });
});

describe('T03 §3.2: OS のライフサイクルによる EOL 判定（judgeDistroEol）', () => {
  const apacheMedium = () => infer({ server: ['Apache/2.4.41 (Ubuntu)'] }).apache!;
  const nginxLow = () => infer({ server: ['nginx/1.18.0 (Ubuntu)'] }).nginx!;
  const phpHigh = () => infer({ 'x-powered-by': ['PHP/7.4.33-1+deb11u5'] }).php!;

  it('候補が 1 件: 標準サポート終了日の翌日なら EOL。日付はデータから入れ、推定・確信度・延長の可能性を書く', () => {
    const lc = lifecycleOf('ubuntu:20.04');
    const res = judgeDistroEol(apacheMedium(), fixtureDistro, dayAt(lc.standardSupportEnd!, 1));
    expect(res).not.toBeNull();
    expect(res!.basisRelease).toBe('ubuntu:20.04');
    expect(res!.eolInfo.status).toBe('EOL');
    expect(res!.eolInfo.eolDate).toBe(lc.standardSupportEnd);
    const text = eolText(res!.eolInfo);
    expect(text).toContain('Ubuntu 20.04');
    expect(text).toContain('推定');
    expect(text).toMatch(/確信度\s*中/);
    expect(text).toContain(lc.standardSupportEnd!);
    expect(text).toContain('延長されている可能性');
    expect(res!.eolInfo.sourceUrl ?? '').toMatch(/^https:\/\/endoflife\.date\//);
  });

  it('候補が 1 件: 標準サポート終了日の当日・前日は EOL にしない。推定なので Supported とも断定しない（H4）', () => {
    const lc = lifecycleOf('ubuntu:20.04');
    for (const shift of [0, -1]) {
      const res = judgeDistroEol(apacheMedium(), fixtureDistro, dayAt(lc.standardSupportEnd!, shift));
      expect(res).not.toBeNull();
      expect(res!.eolInfo.status).not.toBe('EOL');
      expect(res!.eolInfo.status).not.toBe('Supported');
      expect(res!.eolInfo.eolDate).toBe(lc.standardSupportEnd);
      expect(eolText(res!.eolInfo)).toContain('推定');
    }
  });

  it('確信度 high はパッケージ版の印のリリース（Debian 11）で判定し、「確信度 高」と書く', () => {
    const lc = lifecycleOf('debian:11');
    const res = judgeDistroEol(phpHigh(), fixtureDistro, dayAt(lc.standardSupportEnd!, 1));
    expect(res!.basisRelease).toBe('debian:11');
    expect(res!.eolInfo.status).toBe('EOL');
    expect(eolText(res!.eolInfo)).toContain('Debian 11');
    expect(eolText(res!.eolInfo)).toMatch(/確信度\s*高/);
  });

  it('候補が 2 件以上: いちばん早く終わる候補で判定し、全候補を併記する（「確信度 低」）', () => {
    const early = lifecycleOf('ubuntu:20.04');
    const late = lifecycleOf('ubuntu:22.04');
    expect(early.standardSupportEnd! < late.standardSupportEnd!).toBe(true);
    // 早いほうの終了日の翌日（遅いほうはまだ終わっていない）
    const res = judgeDistroEol(nginxLow(), fixtureDistro, dayAt(early.standardSupportEnd!, 1));
    expect(res!.basisRelease).toBe('ubuntu:20.04');
    expect(res!.eolInfo.status).toBe('EOL');
    expect(res!.eolInfo.eolDate).toBe(early.standardSupportEnd);
    const text = eolText(res!.eolInfo);
    expect(text).toContain('Ubuntu 20.04');
    expect(text).toContain('Ubuntu 22.04');
    expect(text).toMatch(/確信度\s*低/);
  });

  it('候補が 2 件以上: 対応表の順番ではなく終了日で選ぶ（22.04 のほうが早く終わるデータなら 22.04 で判定）', () => {
    const distro: AdvisoryDistroSection = structuredClone(fixtureDistro);
    const r20 = distro.releases.find((r) => r.release === 'ubuntu:20.04')!;
    const r22 = distro.releases.find((r) => r.release === 'ubuntu:22.04')!;
    [r20.standardSupportEnd, r22.standardSupportEnd] = [r22.standardSupportEnd, r20.standardSupportEnd];
    const res = judgeDistroEol(nginxLow(), distro, dayAt(r22.standardSupportEnd!, 1));
    expect(res!.basisRelease).toBe('ubuntu:22.04');
    expect(res!.eolInfo.eolDate).toBe(r22.standardSupportEnd);
    expect(res!.eolInfo.status).toBe('EOL');
  });

  it('候補が無い・第三者リポジトリ・バックポートなら判定しない（null。第1段階の表示のまま）', () => {
    const now = new Date();
    expect(judgeDistroEol(infer({ server: ['Apache/2.4.99 (Ubuntu)'] }).apache!, fixtureDistro, now)).toBeNull();
    expect(judgeDistroEol(infer({ 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }).php!, fixtureDistro, now)).toBeNull();
    expect(judgeDistroEol(infer({ 'x-powered-by': ['PHP/7.4.33-1~bpo10+1'] }).php!, fixtureDistro, now)).toBeNull();
  });

  it('ライフサイクルの取得結果が無い（releases が空）なら判定しない（null）', () => {
    const distro: AdvisoryDistroSection = { releases: [], map: fixtureDistro.map };
    const apache = infer({ server: ['Apache/2.4.41 (Ubuntu)'] }, distro).apache!;
    expect(judgeDistroEol(apache, distro, new Date())).toBeNull();
  });

  it('H4: 推定の結果・判定の文言に「該当なし」「安全」「Not Affected」が無い（受け入れ条件 3）', () => {
    const inferences = [
      apacheMedium(),
      nginxLow(),
      phpHigh(),
      infer({ server: ['Apache/2.4.99 (Ubuntu)'] }).apache!,
      infer({ 'x-powered-by': ['PHP/8.1.2-1+ubuntu20.04.1+deb.sury.org+1'] }).php!,
      infer({ 'x-powered-by': ['PHP/7.4.33-1~bpo10+1'] }).php!,
    ];
    const texts: string[] = [];
    for (const inf of inferences) {
      collectStrings(inf, texts);
      for (const r of fixtureDistro.releases) {
        if (!r.standardSupportEnd) continue;
        for (const shift of [-1, 1]) {
          const res = judgeDistroEol(inf, fixtureDistro, dayAt(r.standardSupportEnd, shift));
          if (res) collectStrings(res.eolInfo, texts);
        }
      }
    }
    expect(texts.length).toBeGreaterThan(0);
    for (const t of texts) {
      for (const w of FORBIDDEN_WORDS) expect(t, `「${w}」を含む: ${t}`).not.toContain(w);
    }
  });
});
