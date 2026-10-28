/**
 * Web Technology & Security Inspector
 * 脆弱性DB 自動更新パイプラインの単体テスト (tests/advisory-pipeline.test.mjs)
 * ネットワークには一切アクセスしない (fetch はすべてモック)。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { computeCvss3BaseScore, deriveSeverity } from '../scripts/advisories/lib/cvss.mjs';
import { cleanText, isSafeText, safeUrl } from '../scripts/advisories/lib/sanitize.mjs';
import { intervalsToSpec, isValidRangeSpec, nvdMatchToInterval, osvAffectedToIntervals } from '../scripts/advisories/lib/range.mjs';
import { compactNvdCve, pickNvdCvss } from '../scripts/advisories/lib/nvd.mjs';
import { compactOsvVuln } from '../scripts/advisories/lib/osv.mjs';
import { normalizeEol } from '../scripts/advisories/lib/eol.mjs';
import { createFetchJson } from '../scripts/advisories/lib/http.mjs';
import { buildDatabase, loadUpstream } from '../scripts/advisories/build-db.mjs';
import { diffDatabases, renderMarkdown } from '../scripts/advisories/diff-db.mjs';
import { nextDbRevision } from '../scripts/advisories/bump-db-revision.mjs';
import { fetchUpstream } from '../scripts/advisories/fetch-upstream.mjs';
import { validateDb } from '../scripts/validate-advisories.mjs';
import { createClient } from '../scripts/cws-publish.mjs';
import { matchOfflineAdvisories } from '../src/detection/advisory';
import { satisfiesVersionRange } from '../src/security/version-matcher';
import { fixtureCatalog, fixtureCurated, fixtureUpstream, rawNvdCve } from './fixtures/advisory-upstream.mjs';

const build = () =>
  buildDatabase({
    catalog: fixtureCatalog,
    curated: fixtureCurated,
    upstream: fixtureUpstream,
    previousDb: null,
    asOf: '2026-10-26',
    generatedAt: '2026-10-26T00:00:00.000Z',
  });

const findAdv = (db, product, id) => db.libraries[product].versions.find((v) => v.cve === id);

describe('CVSS v3 ベーススコア計算', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N', 4.7],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.1],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H', 7.7],
    ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', 9.1],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s => %s', (vector, expected) => {
    expect(computeCvss3BaseScore(vector)?.score).toBe(expected);
  });

  it('不正なベクター・v4 ベクターは null を返す', () => {
    expect(computeCvss3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(computeCvss3BaseScore('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
    expect(computeCvss3BaseScore('')).toBeNull();
  });

  it('重大度はスコアから機械的に導出される', () => {
    expect(deriveSeverity(9.0)).toBe('critical');
    expect(deriveSeverity(8.9)).toBe('high');
    expect(deriveSeverity(4.0)).toBe('medium');
    expect(deriveSeverity(3.9)).toBe('low');
    expect(() => deriveSeverity(11)).toThrow();
  });
});

describe('サニタイズ (サプライチェーン経由のHTML注入防止)', () => {
  it('HTML特殊文字・制御文字を除去し長さを制限する', () => {
    const t = cleanText('<img src=x onerror="alert(1)">\u0000 ok', 30);
    expect(isSafeText(t)).toBe(true);
    expect(t).not.toContain('<');
    expect(cleanText('a'.repeat(300), 50).length).toBe(50);
  });

  it('URL は https かつ許可ホストのみ', () => {
    expect(safeUrl('https://nvd.nist.gov/vuln/detail/CVE-2020-11022')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2020-11022');
    expect(safeUrl('javascript:alert(1)')).toBeNull();
    expect(safeUrl('http://nvd.nist.gov/')).toBeNull();
    expect(safeUrl('https://evil.example/')).toBeNull();
    expect(safeUrl('https://user:pw@github.com/')).toBeNull();
  });
});

describe('影響範囲 (range) 変換', () => {
  it('OSV の複数 introduced/fixed 区間を OR 結合する', () => {
    const r = osvAffectedToIntervals({ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.12.0' }, { introduced: '2.0.0' }, { fixed: '2.2.5' }] }] });
    expect(intervalsToSpec(r.intervals)).toBe('< 1.12.0 || >= 2.0.0, < 2.2.5');
    expect(r.fixed).toEqual(['1.12.0', '2.2.5']);
  });

  it('last_affected は <= 、修正版なしは開区間として扱う', () => {
    expect(intervalsToSpec(osvAffectedToIntervals({ ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { last_affected: '4.17.21' }] }] }).intervals)).toBe('>= 4.0.0, <= 4.17.21');
    const open = osvAffectedToIntervals({ ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }] }] });
    expect(open.openEnded).toBe(true);
    expect(intervalsToSpec(open.intervals)).toBe('>= 1.0.0');
  });

  it('GIT 型の range は無視し、解析不能なバージョンは記録する', () => {
    const r = osvAffectedToIntervals({ ranges: [{ type: 'GIT', events: [{ introduced: 'abc' }] }, { type: 'ECOSYSTEM', events: [{ introduced: 'dev-main' }, { fixed: '1.0' }] }] });
    expect(r.intervals).toHaveLength(0);
    expect(r.unparsable).toContain('dev-main');
  });

  it('NVD cpeMatch を区間へ変換する', () => {
    expect(intervalsToSpec([nvdMatchToInterval({ criteria: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*', vsi: '0.6.18', vee: '1.20.1' })])).toBe('>= 0.6.18, < 1.20.1');
    expect(intervalsToSpec([nvdMatchToInterval({ criteria: 'cpe:2.3:a:php:php:5.3.1:*:*:*:*:*:*:*' })])).toBe('= 5.3.1');
    expect(intervalsToSpec([nvdMatchToInterval({ criteria: 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*', vei: '2.4.50' })])).toBe('<= 2.4.50');
  });

  it('生成された範囲は拡張機能の version-matcher で正しく評価できる', () => {
    const spec = '< 1.12.0 || >= 2.0.0, < 2.2.5';
    expect(isValidRangeSpec(spec)).toBe(true);
    expect(satisfiesVersionRange('1.11.3', spec)).toBe(true);
    expect(satisfiesVersionRange('1.12.0', spec)).toBe(false);
    expect(satisfiesVersionRange('2.2.4', spec)).toBe(true);
    expect(satisfiesVersionRange('2.2.5', spec)).toBe(false);
    expect(isValidRangeSpec('< 1.0 && > 0')).toBe(false);
  });
});

describe('NVD / OSV レコード圧縮', () => {
  it('NVD: ターゲット製品の cpeMatch のみ抽出し、AND 構成の適用条件と Primary スコアを取得する', () => {
    const c = compactNvdCve(rawNvdCve, ['php:php']);
    expect(c.matches).toHaveLength(1);
    expect(c.matches[0]).toMatchObject({ vsi: '8.1.0', vee: '8.1.29' });
    expect(c.conditions).toEqual(['OS: microsoft windows']);
    expect(c.description).toMatch(/^Fictional PHP-CGI/);
    expect(c.cvss).toMatchObject({ score: 8.1, source: 'nvd@nist.gov (Primary)', secondaryScore: 9.8 });
  });

  it('NVD: v4.0 のみの場合はスコアなし (null)', () => {
    expect(pickNvdCvss({ cvssMetricV40: [{ source: 'x', type: 'Primary', cvssData: { baseScore: 9.3 } }] })).toBeNull();
  });

  it('OSV: 対象パッケージ以外の affected を除外する', () => {
    const c = compactOsvVuln(
      {
        id: 'GHSA-aaaa-bbbb-9999',
        aliases: ['CVE-2099-9999'],
        affected: [
          { package: { ecosystem: 'npm', name: 'jquery' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] },
          { package: { ecosystem: 'npm', name: 'jquery-ui' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.0.0' }] }] },
        ],
      },
      { ecosystem: 'npm', name: 'jquery' }
    );
    expect(c.affected).toHaveLength(1);
  });
});

describe('EOL 正規化', () => {
  it('supportedLatestCycles により React 旧メジャーを EOL とする (v1.6.5 誤判定 DB-EOL-1 の再発防止)', () => {
    const eol = normalizeEol(fixtureUpstream.eol.react.cycles, { asOf: '2026-10-26', supportedLatestCycles: 1 });
    expect(eol.map((e) => [e.cycle, e.status])).toEqual([
      ['19', 'Supported'],
      ['18', 'EOL'],
      ['17', 'EOL'],
    ]);
  });

  it('eol 日付が基準日以前なら EOL、support 終了済みなら Maintenance', () => {
    const eol = normalizeEol(fixtureUpstream.eol.jquery.cycles, { asOf: '2026-10-26' });
    expect(eol.map((e) => [e.cycle, e.status, e.eolDate])).toEqual([
      ['4', 'Supported', null],
      ['3', 'Maintenance', null],
      ['2', 'EOL', null],
      ['1', 'EOL', null],
    ]);
    const nginx = normalizeEol(fixtureUpstream.eol.nginx.cycles, { asOf: '2026-10-26' });
    expect(nginx.find((e) => e.cycle === '1.29')).toMatchObject({ status: 'EOL', eolDate: '2026-05-13' });
  });
});

describe('DB 生成 (build-db)', () => {
  it('生成結果は strict 検証 (schema 2.2) に合格する', () => {
    const { db } = build();
    expect(db.schemaVersion).toBe('2.2');
    expect(() => validateDb({ ...db, integrity: undefined, libraries: { ...db.libraries, ...padProducts() } })).not.toThrow();
    // 改ざん検知: libraries を書き換えると integrity 検証で失敗する
    const padded = { ...db, libraries: { ...db.libraries, ...padProducts() } };
    expect(() => validateDb(padded)).toThrow(/integrity/);
  });

  it('同一入力から同一出力 (決定的) で、integrity ダイジェストが一致する', () => {
    expect(JSON.stringify(build().db)).toBe(JSON.stringify(build().db));
  });

  it('curated が自動取得より優先され、乖離は build-report に記録される', () => {
    const { db, report } = build();
    const curated = findAdv(db, 'jquery', 'CVE-2020-11023');
    expect(curated.origin).toBe('curated');
    expect(curated.kev).toBe(true);
    expect(curated.notes).toContain('CISA KEV 登録 (2025-01-23)');
    // OSV 側はベクター計算で 4.7 → curated (6.1) と乖離
    expect(report.drift.some((d) => d.id === 'CVE-2020-11023')).toBe(true);
    // NVD 自動取込が無効な PHP でも、curated と NVD スナップショットの乖離は検出される
    expect(report.drift.some((d) => d.id === 'CVE-2024-4577')).toBe(true);
  });

  it('OSV 由来エントリは NVD Primary スコアを優先し、なければベクターから計算する', () => {
    const { db } = build();
    const a = findAdv(db, 'jquery', 'CVE-2020-11022');
    expect(a).toMatchObject({ origin: 'auto', cvssScore: 6.1, severity: 'medium', scoreSource: 'nvd@nist.gov (Primary)', range: '>= 1.2.0, < 3.5.0', fixedVersion: '3.5.0', fixStatus: 'fixed' });
    const g = findAdv(db, 'jquery', 'GHSA-aaaa-bbbb-0001');
    expect(g).toMatchObject({ cvssScore: 7.5, severity: 'high', advisoryUrl: 'https://github.com/advisories/GHSA-aaaa-bbbb-0001' });
    expect(g.title).not.toMatch(/[<>]/);
    expect(a.references ?? []).not.toContain('javascript:alert(1)');
  });

  it('取り下げ・スコア無し・除外指定のアドバイザリは収録しない', () => {
    const { db, report } = build();
    expect(findAdv(db, 'jquery', 'CVE-2099-0004')).toBeUndefined();
    expect(findAdv(db, 'jquery', 'CVE-2099-0002')).toBeUndefined();
    expect(findAdv(db, 'jquery', 'GHSA-aaaa-bbbb-0003')).toBeUndefined();
    expect(report.excluded.map((e) => e.id)).toContain('GHSA-aaaa-bbbb-0003');
    expect(report.products.jquery.skipped).toMatchObject({ withdrawn: 1, unscored: 1 });
  });

  it('修正版の無い OSV エントリは fixStatus=none', () => {
    const { db } = build();
    expect(findAdv(db, 'lodash', 'CVE-2099-0005')).toMatchObject({ range: '>= 4.0.0, <= 4.17.21', fixedVersion: null, fixStatus: 'none' });
  });

  it('NVD 自動取込: フィルタ・Rejected 除外・適用条件注記・列挙の近似', () => {
    const { db, report } = build();
    expect(findAdv(db, 'nginx', 'CVE-2021-23017')).toMatchObject({ range: '>= 0.6.18, < 1.20.1', fixStatus: 'fixed', cvssScore: 7.7 });
    const cond = findAdv(db, 'nginx', 'CVE-2099-1001');
    expect(cond.summary).toContain('該当の可能性あり (条件: OS: microsoft windows)');
    expect(cond.rangeApproximated).toBe(true);
    expect(cond.range).toBe('>= 1.10.0, <= 1.12.9');
    expect(cond.fixStatus).toBe('unknown');
    expect(cond.notes).toContain('cna@example.org 評価: 9.8');
    expect(findAdv(db, 'nginx', 'CVE-2099-1002')).toBeUndefined();
    expect(findAdv(db, 'nginx', 'CVE-2099-1003')).toBeUndefined();
    expect(report.products.nginx.skipped).toMatchObject({ rejected: 1, filtered: 1 });
  });

  it('autoIngest=false の製品は NVD 候補を収録せず curated のみ', () => {
    const { db, report } = build();
    expect(db.libraries.php.versions.map((v) => v.cve)).toEqual(['CVE-2024-4577']);
    expect(report.products.php).toMatchObject({ nvdCandidates: 1, nvdAutoIngest: false });
    expect(findAdv(db, 'php', 'CVE-2024-4577').summary).not.toMatch(/[<>]/);
  });

  it('EOL: endoflife.date → curated 静的定義 の順で採用される', () => {
    const { db, report } = build();
    expect(report.products.lodash.eolSource).toBe('curated');
    expect(db.libraries.lodash.eol[0]).toEqual({ cycle: '4.x', eolDate: null, status: 'Supported' });
    expect(report.products.react.eolSource).toBe('endoflife.date');
  });

  it('生成 DB は v1.6.5 の advisory.ts (schema 2.1 リーダー) でそのまま照合できる', () => {
    const { db } = build();
    const hit = matchOfflineAdvisories('jQuery', '3.4.1', { libraries: db.libraries, generatedAt: db.generatedAt });
    expect(hit.matchStatus).toBe('Potentially Affected');
    expect(hit.advisories.map((a) => a.id)).toEqual(expect.arrayContaining(['CVE-2020-11022', 'CVE-2020-11023']));
    const clean = matchOfflineAdvisories('jQuery', '3.7.1', { libraries: db.libraries, generatedAt: db.generatedAt });
    expect(clean.advisories).toHaveLength(0);
    expect(matchOfflineAdvisories('React', '17.0.2', { libraries: db.libraries, generatedAt: db.generatedAt }).eolInfo.status).toBe('EOL');
  });

  it('upstream ディレクトリから読み込める', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wi-upstream-'));
    const w = (rel, obj) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), JSON.stringify(obj));
    };
    w('manifest.json', fixtureUpstream.manifest);
    w('osv/npm__jquery.json', fixtureUpstream.osv['npm:jquery']);
    w('nvd/f5__nginx.json', fixtureUpstream.nvd['f5:nginx']);
    w('eol/react.json', fixtureUpstream.eol.react);
    w('kev.json', fixtureUpstream.kev);
    const up = loadUpstream(dir);
    expect(Object.keys(up.osv)).toEqual(['npm:jquery']);
    expect(Object.keys(up.nvd)).toEqual(['f5:nginx']);
    expect(up.eol.react.cycles).toHaveLength(3);
    expect(up.kev.count).toBe(1);
  });
});

describe('DB 差分分類 (diff-db)', () => {
  it('追加のみは minor', () => {
    const { db } = build();
    const base = structuredClone(db);
    base.libraries.jquery.versions = base.libraries.jquery.versions.filter((v) => v.cve !== 'CVE-2020-11022');
    const d = diffDatabases(base, db);
    expect(d.classification).toBe('minor');
    expect(d.added.map((a) => a.cve)).toEqual(['CVE-2020-11022']);
    expect(renderMarkdown(d)).toContain('minor');
  });

  it('curated の削除・EOL 逆行・取得失敗は major', () => {
    const { db } = build();
    const head = structuredClone(db);
    head.libraries.jquery.versions = head.libraries.jquery.versions.filter((v) => v.cve !== 'CVE-2020-11023');
    expect(diffDatabases(db, head).classification).toBe('major');

    const head2 = structuredClone(db);
    head2.libraries.react.eol = head2.libraries.react.eol.map((e) => ({ ...e, status: 'Supported' }));
    const d2 = diffDatabases(db, head2);
    expect(d2.classification).toBe('major');
    expect(d2.reasonsMajor.join()).toContain('EOL → Supported');

    const head3 = { ...structuredClone(db), syncStatus: 'partial' };
    head3.libraries.jquery.versions[0].cvssScore = 6.2;
    expect(diffDatabases(db, head3).classification).toBe('major');
  });

  it('同一なら none。ただし出荷中DBが refreshDays 以上古い場合は鮮度更新の minor', () => {
    const { db } = build();
    expect(diffDatabases(db, structuredClone(db)).classification).toBe('none');
    const old = { ...structuredClone(db), generatedAt: '2026-09-01T00:00:00.000Z' };
    const d = diffDatabases(old, db, { refreshDays: 21 });
    expect(d).toMatchObject({ classification: 'minor', freshnessRefresh: true });
    expect(diffDatabases(db, structuredClone(db), { refreshDays: 21 }).classification).toBe('none');
  });
});

describe('DB リビジョン採番', () => {
  it('manifest.version の第4要素を増やす', () => {
    expect(nextDbRevision('1.6.5')).toBe('1.6.5.1');
    expect(nextDbRevision('1.6.5.9')).toBe('1.6.5.10');
    expect(() => nextDbRevision('1.6')).toThrow();
    expect(() => nextDbRevision('1.6.5.65535')).toThrow();
    expect(() => nextDbRevision('1.6.5-beta')).toThrow();
  });
});

describe('上流取得 (fetch-upstream, fetch はモック)', () => {
  const mkResponse = (status, body) => ({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) });

  it('成功時はスナップショットと manifest を保存し、失敗ソースは stale として前回データを保持する', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wi-fetch-'));
    // 前回スナップショット (EOL) を用意
    fs.mkdirSync(path.join(dir, 'eol'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'eol', 'jquery.json'), JSON.stringify({ slug: 'jquery', cycles: [{ cycle: '3', eol: false }] }));

    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push(url);
      if (url.startsWith('https://api.osv.dev/')) {
        const body = JSON.parse(init.body);
        if (body.package.name === 'jquery') return mkResponse(200, { vulns: [{ id: 'GHSA-aaaa-bbbb-1111', aliases: ['CVE-2099-1111'], affected: [{ package: { ecosystem: 'npm', name: 'jquery' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }] }] }] });
        return mkResponse(200, {});
      }
      if (url.startsWith('https://endoflife.date/')) return mkResponse(404, {});
      if (url.startsWith('https://www.cisa.gov/')) return mkResponse(200, { catalogVersion: 'x', dateReleased: '2026-10-24T00:00:00Z', vulnerabilities: [{ cveID: 'CVE-2099-1111', dateAdded: '2026-01-01' }] });
      if (url.startsWith('https://services.nvd.nist.gov/')) {
        if (url.includes('cveId=')) return mkResponse(200, { vulnerabilities: [{ cve: { id: 'CVE-2099-1111', vulnStatus: 'Analyzed', metrics: { cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { baseScore: 7.5 } }] } } }] });
        return mkResponse(200, { totalResults: 0, vulnerabilities: [] });
      }
      return mkResponse(500, {});
    };
    const fetchJson = createFetchJson({ fetchImpl, retries: 0 });
    const catalog = { products: { jquery: fixtureCatalog.products.jquery, nginx: fixtureCatalog.products.nginx } };
    const { okCount, failCount, manifest } = await fetchUpstream({
      catalog,
      curated: { products: {} },
      upstreamDir: dir,
      fetchJson,
      now: new Date('2026-10-26T00:00:00Z'),
      log: () => {},
    });
    expect(failCount).toBe(2);
    expect(okCount).toBeGreaterThan(0);
    expect(manifest.sources['eol:jquery'].status).toBe('stale');
    expect(manifest.sources['eol:nginx'].status).toBe('failed');
    expect(manifest.sources['osv:npm:jquery']).toMatchObject({ status: 'ok', count: 1 });
    const scores = JSON.parse(fs.readFileSync(path.join(dir, 'nvd-scores.json'), 'utf-8'));
    expect(scores['CVE-2099-1111'].cvss.score).toBe(7.5);
    // 前回の EOL スナップショットは保持されている
    expect(JSON.parse(fs.readFileSync(path.join(dir, 'eol', 'jquery.json'), 'utf-8')).cycles).toHaveLength(1);
    expect(calls.some((u) => u.includes('virtualMatchString=cpe%3A2.3%3Aa%3Af5%3Anginx'))).toBe(true);
  });

  it('HTTP クライアントは 429 を再試行する', async () => {
    let n = 0;
    const fetchImpl = async () => (++n < 2 ? mkResponse(429, {}) : mkResponse(200, { ok: 1 }));
    const fetchJson = createFetchJson({ fetchImpl, retries: 2 });
    // バックオフ待機を短縮するためタイマーは実時間 (2秒) — 1回のみ
    await expect(fetchJson('https://api.osv.dev/v1/query')).resolves.toEqual({ ok: 1 });
    expect(n).toBe(2);
  }, 10_000);
});

describe('Chrome Web Store API v2 クライアント (fetch はモック)', () => {
  it('リフレッシュトークンで認証し、アップロード完了をポーリングして STAGED_PUBLISH で提出する', async () => {
    const zip = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wi-cws-')), 'a.zip');
    fs.writeFileSync(zip, 'PK');
    const calls = [];
    let polls = 0;
    const fetchImpl = async (url, init) => {
      calls.push({ url, method: init.method, body: init.body });
      const json = (obj, status = 200) => ({ ok: status < 300, status, text: async () => JSON.stringify(obj), json: async () => obj });
      if (url === 'https://oauth2.googleapis.com/token') return json({ access_token: 'tkn' });
      if (url.includes(':upload')) return json({ uploadState: 'IN_PROGRESS' });
      if (url.endsWith(':fetchStatus')) return json({ lastAsyncUploadState: ++polls < 2 ? 'IN_PROGRESS' : 'SUCCEEDED' });
      if (url.endsWith(':publish')) return json({ state: 'PENDING_REVIEW' });
      return json({}, 404);
    };
    const client = createClient({
      env: { CWS_PUBLISHER_ID: 'pub', CWS_EXTENSION_ID: 'ext', CWS_CLIENT_ID: 'c', CWS_CLIENT_SECRET: 's', CWS_REFRESH_TOKEN: 'r' },
      fetchImpl,
      sleep: async () => {},
      log: () => {},
    });
    await expect(client.upload(zip)).resolves.toMatchObject({ uploadState: 'SUCCEEDED' });
    await client.publish();
    const pub = calls.find((c) => c.url.endsWith(':publish'));
    expect(pub.url).toBe('https://chromewebstore.googleapis.com/v2/publishers/pub/items/ext:publish');
    expect(JSON.parse(pub.body)).toMatchObject({ publishType: 'STAGED_PUBLISH', skipReview: false, blockOnWarnings: true });
    expect(calls.filter((c) => c.url.includes('oauth2')).length).toBe(1);
    await expect(client.publish({ publishType: 'INVALID' })).rejects.toThrow();
  });
});

/** validateDb の MIN_PRODUCT_COUNT / MIN_ADVISORY_COUNT を満たすためのダミー製品 */
function padProducts() {
  const out = {};
  for (let i = 0; i < 3; i++) {
    out[`dummy${i}`] = {
      aliases: [`dummy${i}`],
      eol: [],
      versions: Array.from({ length: 4 }, (_, j) => ({
        range: '< 1.0.0',
        cve: `CVE-2099-9${i}0${j}`,
        cvssScore: 5,
        severity: 'medium',
        title: 'dummy',
        fixedVersion: '1.0.0',
        fixStatus: 'fixed',
        advisoryUrl: `https://nvd.nist.gov/vuln/detail/CVE-2099-9${i}0${j}`,
        verifiedAt: '2026-10-26',
        scoreSource: 'test',
        origin: 'auto',
      })),
    };
  }
  return out;
}
