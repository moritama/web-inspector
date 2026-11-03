/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOL照合単体テスト (tests/advisory.test.ts)
 * 
 * Rev.2.1 Phase 2 (IMP-06: オフライン脆弱性DB品質・鮮度管理) の網羅的テスト
 */

import { describe, expect, it } from 'vitest';
import {
  AdvisoryDatabase,
  calculateDbFreshness,
  formatAdvisoryRecommendation,
  getAdvisoryDbMetadata,
  matchOfflineAdvisories,
  resolveRecommendedVersion,
} from '../src/detection/advisory';
import fixtureDbJson from './fixtures/advisory-db.fixture.json';

const fixtureDb = fixtureDbJson as unknown as AdvisoryDatabase;

describe('オフライン既知脆弱性・EOL照合テスト (Rev.2.1 IMP-06 / D11-D20)', () => {
  // D16: Matched テスト
  it('D16: 古いjQuery 2.2.4 に対して脆弱性とEOLが正確に検出され Matched となること', () => {
    const result = matchOfflineAdvisories('jQuery', '2.2.4', fixtureDb);

    expect(result.technology).toBe('jQuery');
    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.matchStatus).toBe('Potentially Affected');
    expect(result.advisories.length).toBeGreaterThan(0);

    const cveIds = result.advisories.map((a) => a.id);
    expect(cveIds).toContain('CVE-2015-9251');
    expect(result.eolInfo.status).toBe('EOL');
  });

  it('サポート終了済みの古いPHP 7.4.30 に対してEOLおよび脆弱性が照合され Matched となること', () => {
    const result = matchOfflineAdvisories('PHP', '7.4.30', fixtureDb);

    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.eolInfo.status).toBe('EOL');
    expect(result.matchStatus).toBe('Potentially Affected');
    expect(result.advisories.some((a) => a.id === 'CVE-2022-31628')).toBe(true);
  });

  // D12: No Match テスト
  it('D12: 安全な最新Bootstrap 5.3.3 に対して脆弱性なし (No Match / Not Affected) と判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', '5.3.3', fixtureDb);

    expect(result.offlineMatchStatus).toBe('No Match');
    expect(result.matchStatus).toBe('Not Affected');
    expect(result.advisories.length).toBe(0);
    expect(result.eolInfo.status).toBe('Supported');
  });

  // D11: Not Covered テスト
  it('D11: 未登録の技術の場合は Not Covered (No Data) となること', () => {
    const result = matchOfflineAdvisories('UnknownCustomLib', '1.0.0', fixtureDb);

    expect(result.offlineMatchStatus).toBe('Not Covered');
    expect(result.matchStatus).toBe('No Data');
    expect(result.advisories.length).toBe(0);
    expect(result.eolInfo.status).toBe('Unknown');
  });

  // D15: Unknown Version テスト
  it('D15: バージョンが不明 (null または空文字) の場合、Unknown Version (Needs Review) となること', () => {
    const resultNull = matchOfflineAdvisories('jQuery', null, fixtureDb);
    expect(resultNull.offlineMatchStatus).toBe('Unknown Version');
    expect(resultNull.matchStatus).toBe('Needs Review');
    expect(resultNull.advisories.length).toBe(0);
    expect(resultNull.eolInfo.status).toBe('Unknown');

    const resultEmpty = matchOfflineAdvisories('jQuery', '   ', fixtureDb);
    expect(resultEmpty.offlineMatchStatus).toBe('Unknown Version');
    expect(resultEmpty.matchStatus).toBe('Needs Review');
  });

  // D14: Linuxパッケージ誤変換防止テスト (バックポート考慮)
  it('D14: Ubuntu/Debianパッケージバージョン (例: 2.4.52-1ubuntu4) は誤検知を避けて Unknown Version / Needs Review となること', () => {
    // 通常の SemVer "2.4.52" なら脆弱性 CVE-2021-44790 (< 2.4.52) に一致するが、
    // パッケージ版ではバックポート修正されている可能性が高いため断定を避ける
    const result = matchOfflineAdvisories('Apache', '2.4.52-1ubuntu4', fixtureDb);

    expect(result.offlineMatchStatus).toBe('Unknown Version');
    expect(result.matchStatus).toBe('Needs Review');
    expect(result.advisories.length).toBe(0);
    expect(result.warning).toContain('Linuxディストリビューション固有パッケージ');
  });

  it('D14: Debianパッケージバージョン (例: 1.18.0-0ubuntu1.4) に対しても安全側に倒すこと', () => {
    const result = matchOfflineAdvisories('Nginx', '1.18.0-0ubuntu1.4', fixtureDb);

    expect(result.offlineMatchStatus).toBe('Unknown Version');
    expect(result.matchStatus).toBe('Needs Review');
  });

  it('SPEC-02: distroHint オプション指定時は Unknown Version / Needs Review となりディストリ固有注記が返ること', () => {
    const result = matchOfflineAdvisories('Apache', '2.4.41', fixtureDb, { distroHint: 'Ubuntu' });
    expect(result.offlineMatchStatus).toBe('Unknown Version');
    expect(result.matchStatus).toBe('Needs Review');
    expect(result.advisories.length).toBe(0);
    expect(result.warning).toContain('Ubuntu のディストリビューション版です');
    expect(result.eolInfo.recommendation).toContain('Ubuntu のディストリビューション版です');
  });

  // D13: Stale Data テスト (生成日から31日以上経過したDBスナップショット)
  it('D13: 生成日から31日以上経過しているDBスナップショットは isStale: true / dbFreshness: stale と判定されること', () => {
    // 40日前の日付
    const oldDate = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
    const result = matchOfflineAdvisories('jQuery', '2.2.4', {
      ...fixtureDb,
      generatedAt: oldDate,
    });

    expect(result.isStale).toBe(true);
    expect(result.dbFreshness).toBe('stale');
    // ステータス自体は Matched として維持されること
    expect(result.offlineMatchStatus).toBe('Matched');
  });

  // D18: 鮮度計算ロジック単体テスト
  it('D18: 鮮度レベル判定が経過日数に応じて正確に分類されること', () => {
    const now = Date.now();

    // 2日前 -> fresh
    const freshDate = new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString();
    const fresh = calculateDbFreshness(freshDate);
    expect(fresh.freshness).toBe('fresh');
    expect(fresh.isStale).toBe(false);

    // 15日前 -> moderate
    const modDate = new Date(now - 15 * 24 * 60 * 60 * 1000).toISOString();
    const moderate = calculateDbFreshness(modDate);
    expect(moderate.freshness).toBe('moderate');
    expect(moderate.isStale).toBe(false);

    // 35日前 -> stale
    const staleDate = new Date(now - 35 * 24 * 60 * 60 * 1000).toISOString();
    const stale = calculateDbFreshness(staleDate);
    expect(stale.freshness).toBe('stale');
    expect(stale.isStale).toBe(true);

    // 不正な日付 -> unknown
    const invalid = calculateDbFreshness('invalid-date');
    expect(invalid.freshness).toBe('unknown');
    expect(invalid.isStale).toBe(false);
  });

  // D17: DBメタデータ検証テスト
  it('D17: getAdvisoryDbMetadata() で Rev.2.1 スキーマメタデータが取得できること', () => {
    const meta = getAdvisoryDbMetadata();

    expect(['2.1', '2.2']).toContain(meta.schemaVersion); // 2.2 = 自動生成パイプライン (2.1 上位互換)
    expect(meta.dataVersion).toMatch(/^\d{8}$/); // YYYYMMDD形式
    expect(meta.productCount).toBeGreaterThanOrEqual(5);
    expect(meta.advisoryCount).toBeGreaterThanOrEqual(10);
    expect(meta.sources.length).toBeGreaterThan(0);
    expect(meta.coverage.technologies.length).toBeGreaterThanOrEqual(5);
    expect(['success', 'partial']).toContain(meta.syncStatus);
  });

  it('古いLaravel 8.0.0 に対してEOLおよびCVE-2021-3129が検出されること', () => {
    const result = matchOfflineAdvisories('Laravel', '8.0.0', fixtureDb);

    expect(result.technology).toBe('Laravel');
    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.eolInfo.status).toBe('EOL');
    expect(result.advisories.some((a) => a.id === 'CVE-2021-3129')).toBe(true);
  });

  it('サポート終了済みの古いNode.js 16.14.0 に対してEOLが検出されること', () => {
    const result = matchOfflineAdvisories('Node.js', '16.14.0', fixtureDb);

    expect(result.technology).toBe('Node.js');
    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.eolInfo.status).toBe('EOL');
  });

  it('AngularJS 1.8.3 に対して全バージョン影響のCVE-2022-25869が検出され、修正版なし(null)および移行推奨案内が出力されること', () => {
    const result = matchOfflineAdvisories('AngularJS', '1.8.3', fixtureDb);

    expect(result.technology).toBe('AngularJS');
    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.eolInfo.status).toBe('EOL');
    expect(result.eolInfo.recommendation).toContain('Angularや他のモダンフレームワークへの移行を強く推奨');

    const cve = result.advisories.find((a) => a.id === 'CVE-2022-25869');
    expect(cve).toBeDefined();
    expect(cve?.affectedRange).toBe('<= 1.8.3');
    expect(cve?.fixedVersion).toBeNull();
    expect(cve?.referenceUrls).toContain('https://github.com/advisories/GHSA-prc3-vjfx-vhm9');
  });

  // 複数ブランチ・複数アドバイザリ対応の推奨版導出テスト (レビュー 2-4 対応)
  describe('複数ブランチ・複数アドバイザリ推奨版解決テスト (レビュー 2-4 準拠)', () => {
    it('Apache 2.4.49 検出時に、複数の脆弱性 (CVE-2021-41773: 2.4.50, CVE-2021-42013: 2.4.51, CVE-2021-44790: 2.4.52) の中で全てを解消できる最高バージョン (2.4.52) が推奨されること', () => {
      const result = matchOfflineAdvisories('Apache', '2.4.49', fixtureDb);
      expect(result.advisories.length).toBeGreaterThanOrEqual(2);

      // 先頭エントリの 2.4.50 ではなく、全てを解消する 2.4.52 が導出されること
      const recommended = resolveRecommendedVersion('2.4.49', result.advisories);
      expect(recommended).toBe('2.4.52');

      const recText = formatAdvisoryRecommendation('2.4.49', result.advisories, {
        isEol: result.eolInfo.status === 'EOL',
        technologyName: 'Apache',
      });
      expect(recText).toContain('v2.4.52 以上');
    });

    it('Apache で CVE-2021-41773 (2.4.50) と CVE-2021-42013 (2.4.51) のみ該当する場合、2.4.50 ではなく 2.4.51 が推奨されること', () => {
      const mockAdvisories = [
        { fixedVersion: '2.4.50' }, // CVE-2021-41773
        { fixedVersion: '2.4.51' }, // CVE-2021-42013
      ];
      const recommended = resolveRecommendedVersion('2.4.49', mockAdvisories);
      expect(recommended).toBe('2.4.51');

      const recText = formatAdvisoryRecommendation('2.4.49', mockAdvisories, {
        technologyName: 'Apache',
      });
      expect(recText).toContain('v2.4.51 以上');
      expect(recText).not.toContain('2.4.50');
    });

    it('PHP 8.0.10 検出時に、CVE-2022-31628 の複数ブランチ修正版 (7.4.31 / 8.0.24 / 8.1.11) から利用者の 8.0 系統に対応する 8.0.24 が正確に抽出されること', () => {
      const mockAdvisory = [{ fixedVersion: '7.4.31 / 8.0.24 / 8.1.11' }];
      const recommended = resolveRecommendedVersion('8.0.10', mockAdvisory);
      expect(recommended).toBe('8.0.24');

      const recText = formatAdvisoryRecommendation('8.0.10', mockAdvisory, {
        isEol: false,
        technologyName: 'PHP',
      });
      // 「7.4.31 / 8.0.24 / 8.1.11 以上」といったスラッシュ併記ではなく、単一の明確なバージョンであること
      expect(recText).toContain('v8.0.24 以上');
      expect(recText).not.toContain('7.4.31 / 8.0.24');
    });

    it('PHP 7.4.30 検出時に、CVE-2022-31628 の複数ブランチ修正版から 7.4 系統に対応する 7.4.31 が正確に抽出されること', () => {
      const mockAdvisory = [{ fixedVersion: '7.4.31 / 8.0.24 / 8.1.11' }];
      const recommended = resolveRecommendedVersion('7.4.30', mockAdvisory);
      expect(recommended).toBe('7.4.31');
    });

    it('PHP 8.0.10 実DB照合時: 8.0系パッチが存在しない CVE-2024-4577 (8.1.29) と CVE-2022-31628 (8.0.24) が同時にヒットした場合、全体を解消できる 8.1.29 以上が推奨されること', () => {
      const result = matchOfflineAdvisories('PHP', '8.0.10', fixtureDb);
      const recommended = resolveRecommendedVersion('8.0.10', result.advisories);
      expect(recommended).toBe('8.1.29');
    });

    it('Bootstrap 4.3.0 検出時に、複数ブランチ修正版 (3.4.1 / 4.3.1) から 4.3 系列の 4.3.1 が正確に抽出されること', () => {
      const result = matchOfflineAdvisories('Bootstrap', '4.3.0', fixtureDb);
      expect(result.advisories.some((a) => a.id === 'CVE-2019-8331')).toBe(true);

      const recommended = resolveRecommendedVersion('4.3.0', result.advisories);
      expect(recommended).toBe('4.3.1');

      const recText = formatAdvisoryRecommendation('4.3.0', result.advisories, {
        isEol: false,
        technologyName: 'Bootstrap',
      });
      expect(recText).toContain('v4.3.1 以上');
      expect(recText).not.toContain('3.4.1 / 4.3.1');
    });
  });

  describe('T03 (SPEC-13): fixStatus・KEV・重大度4段階・GHSA参照URLの検証', () => {
    const spec13TestDb: Partial<AdvisoryDatabase> = {
      version: '2026.10-test',
      generatedAt: new Date().toISOString(),
      libraries: {
        'test-lib': {
          aliases: ['test-lib'],
          versions: [
            {
              range: '>= 1.0.0, < 1.1.0',
              cve: 'CVE-2026-0001',
              cvssScore: 9.0,
              severity: 'critical',
              title: 'Fixed critical vulnerability',
              fixedVersion: '1.1.0',
              fixStatus: 'fixed',
              kev: false,
            },
            {
              range: '>= 2.0.0, < 3.0.0',
              cve: 'CVE-2026-0002',
              cvssScore: 7.5,
              severity: 'high',
              title: 'Partial fix vulnerability',
              fixedVersion: '2.5.1 / 3.1.0',
              fixStatus: 'partial',
              kev: false,
            },
            {
              range: '>= 3.0.0, < 3.5.0',
              cve: 'CVE-2026-0003',
              cvssScore: 5.3,
              severity: 'medium',
              title: 'No fix vulnerability',
              fixedVersion: null,
              fixStatus: 'none',
              kev: false,
            },
            {
              range: '>= 4.0.0, < 4.5.0',
              cve: 'CVE-2026-0004',
              cvssScore: 3.1,
              severity: 'low',
              title: 'Unknown fix vulnerability',
              fixedVersion: null,
              fixStatus: 'unknown',
              kev: false,
            },
            {
              range: '>= 5.0.0, < 5.1.0',
              cve: 'GHSA-5cp4-xmrw-59wf',
              ghsa: 'GHSA-5cp4-xmrw-59wf',
              cvssScore: 6.1,
              severity: 'medium',
              title: 'GHSA-only advisory',
              fixedVersion: '5.1.0',
              fixStatus: 'fixed',
              kev: true,
              kevDateAdded: '2025-01-23',
            },
          ],
          eol: [],
        },
      },
    };

    it('fixStatus の 4 値 (fixed / partial / none / unknown) で推奨文言が 4 パターンに分かれ、unknown のみのヒット時に「公式の修正版はありません」が出ないこと', () => {
      // 1. fixed
      const resFixed = matchOfflineAdvisories('test-lib', '1.0.5', spec13TestDb);
      expect(resFixed.advisories[0].fixStatus).toBe('fixed');
      expect(resFixed.advisories[0].severity).toBe('critical');
      const recFixed = formatAdvisoryRecommendation('1.0.5', resFixed.advisories, {
        isEol: false,
        technologyName: 'test-lib',
      });
      expect(recFixed).toContain('v1.1.0 以上');
      expect(recFixed).not.toContain('公式の修正版はありません');

      // 2. partial
      const resPartial = matchOfflineAdvisories('test-lib', '2.1.0', spec13TestDb);
      expect(resPartial.advisories[0].fixStatus).toBe('partial');
      expect(resPartial.advisories[0].severity).toBe('high');
      const recPartial = formatAdvisoryRecommendation('2.1.0', resPartial.advisories, {
        isEol: false,
        technologyName: 'test-lib',
      });
      expect(recPartial).toContain('一部の系列には修正版がありません');
      expect(recPartial).not.toContain('公式の修正版はありません');

      // 3. none
      const resNone = matchOfflineAdvisories('test-lib', '3.1.0', spec13TestDb);
      expect(resNone.advisories[0].fixStatus).toBe('none');
      expect(resNone.advisories[0].severity).toBe('medium');
      const recNone = formatAdvisoryRecommendation('3.1.0', resNone.advisories, {
        isEol: false,
        technologyName: 'test-lib',
      });
      expect(recNone).toContain('公式の修正版はありません');

      // 4. unknown (isEol: false および isEol: true の両方で「公式の修正版はありません」が出ないこと)
      const resUnknown = matchOfflineAdvisories('test-lib', '4.1.0', spec13TestDb);
      expect(resUnknown.advisories[0].fixStatus).toBe('unknown');
      expect(resUnknown.advisories[0].severity).toBe('low');
      const recUnknownNonEol = formatAdvisoryRecommendation('4.1.0', resUnknown.advisories, {
        isEol: false,
        technologyName: 'test-lib',
      });
      expect(recUnknownNonEol).toContain('修正版の情報が DB にありません。ベンダーの情報を確認してください');
      expect(recUnknownNonEol).not.toContain('公式の修正版はありません');

      const recUnknownEol = formatAdvisoryRecommendation('4.1.0', resUnknown.advisories, {
        isEol: true,
        technologyName: 'test-lib',
      });
      expect(recUnknownEol).toContain('修正版の情報が DB にありません。ベンダーの情報を確認してください');
      expect(recUnknownEol).not.toContain('公式の修正版はありません');
    });

    it('GHSA のみの ID にヒットしたとき、referenceUrls に GitHub Advisories の URL が入り NVD+GHSA の URL が入らないこと', () => {
      const resGhsa = matchOfflineAdvisories('test-lib', '5.0.2', spec13TestDb);
      expect(resGhsa.advisories).toHaveLength(1);
      const adv = resGhsa.advisories[0];
      expect(adv.id).toBe('GHSA-5cp4-xmrw-59wf');
      expect(adv.kev).toBe(true);
      expect(adv.kevDateAdded).toBe('2025-01-23');
      expect(adv.referenceUrls).toContain('https://github.com/advisories/GHSA-5cp4-xmrw-59wf');
      expect(adv.referenceUrls.some((u) => u.includes('nvd.nist.gov/vuln/detail/GHSA-'))).toBe(false);
    });

    it('固定 DB の jQuery 3.4.1 で CVE-2020-11023 の kev: true と kevDateAdded が保持されること', () => {
      const res = matchOfflineAdvisories('jQuery', '3.4.1', fixtureDb);
      const kevAdv = res.advisories.find((a) => a.id === 'CVE-2020-11023');
      expect(kevAdv).toBeDefined();
      expect(kevAdv?.kev).toBe(true);
      expect(kevAdv?.kevDateAdded).toBe('2025-01-23');
      expect(kevAdv?.fixStatus).toBe('fixed');
    });
  });

  // --- T04 (SPEC-03): 「収録 DB 上は該当なし」・収録範囲・多件数優先ソート・ディストリ版上流参考件数 ---
  describe('T04 (SPEC-03): 収録 DB 範囲メタデータ・優先順位ソート・ディストリ版上流件数', () => {
    it('固定 DB で Apache 2.4.62 を照合したとき、収録件数・取得元・dataVersion・「収録 DB 上は該当なし」が返ること', () => {
      const res = matchOfflineAdvisories('Apache', '2.4.62', fixtureDb);
      expect(res.matchStatus).toBe('Not Affected');
      expect(res.advisories).toHaveLength(0);
      expect(res.productAdvisoryCount).toBe(3);
      expect(res.productSources).toEqual(['curated', 'NVD']);
      expect(res.advisoryDataVersion).toBe('20261031');
      expect(res.advisoryStatusLabel).toContain('収録 DB 上は該当なし');
    });

    it('収録件数 0 の技術（Tailwind CSS）を照合したとき、productAdvisoryCount=0 と「この技術の脆弱性は収録していません」が返ること', () => {
      const res = matchOfflineAdvisories('Tailwind CSS', '3.4.1', fixtureDb);
      expect(res.matchStatus).toBe('No Data');
      expect(res.productAdvisoryCount).toBe(0);
      expect(res.productSources).toEqual([]);
      expect(res.advisoryStatusLabel).toBe('この技術の脆弱性は収録していません');
    });

    it('ディストリ版 Apache/2.4.41 (Ubuntu) で Needs Review のまま、上流版での該当件数 (upstreamAdvisoriesCount) が算出されること', () => {
      const res = matchOfflineAdvisories('Apache', '2.4.41 (Ubuntu)', fixtureDb);
      expect(res.matchStatus).toBe('Needs Review');
      expect(res.advisories).toHaveLength(0);
      expect(res.upstreamAdvisoriesCount).toBe(1);
      expect(res.productAdvisoryCount).toBe(3);

      const resWithPrefix = matchOfflineAdvisories('Apache', 'Apache/2.4.41 (Ubuntu)', fixtureDb);
      expect(resWithPrefix.matchStatus).toBe('Needs Review');
      expect(resWithPrefix.advisories).toHaveLength(0);
      expect(resWithPrefix.upstreamAdvisoriesCount).toBe(1);
    });

    it('12 件該当するとき、KEV → 重大度 → CVSS の順にソートされ、推奨版は全件から最大バージョンが計算されること', () => {
      const manyDb = {
        dataVersion: '20261031',
        generatedAt: '2026-10-31T00:00:00Z',
        coverage: {
          byProduct: {
            'many-lib': { count: 12, sources: ['curated', 'OSV', 'NVD'] },
          },
        },
        libraries: {
          'many-lib': {
            aliases: ['many-lib'],
            eol: [{ cycle: '1.x', eolDate: null, status: 'Supported' }],
            versions: [
              // 1〜11件目: KEV なし、さまざまな重大度・CVSS・fixedVersion
              ...Array.from({ length: 11 }, (_, i) => ({
                range: '< 2.0.0',
                cve: `CVE-2026-00${String(i + 1).padStart(2, '0')}`,
                cvssScore: 5.0 + (i % 5) * 0.5,
                severity: i === 0 ? 'critical' : i < 4 ? 'high' : 'medium',
                title: `Vuln ${i + 1}`,
                fixedVersion: i === 10 ? '1.9.9' : `1.0.${i + 1}`,
                fixStatus: 'fixed' as const,
                kev: false,
                origin: 'auto',
              })),
              // 12件目: CVSS は中程度だが KEV=true のエントリ（ソート後は先頭に来るべき）
              {
                range: '< 2.0.0',
                cve: 'CVE-2026-9999',
                cvssScore: 7.2,
                severity: 'high',
                title: 'KEV Exploited Vulnerability',
                fixedVersion: '1.2.0',
                fixStatus: 'fixed' as const,
                kev: true,
                kevDateAdded: '2026-05-01',
                origin: 'curated',
              },
            ],
          },
        },
      };

      const res = matchOfflineAdvisories('many-lib', '1.0.0', manyDb as unknown as AdvisoryDatabase);
      expect(res.advisories).toHaveLength(12);
      // 先頭は KEV エントリ
      expect(res.advisories[0].id).toBe('CVE-2026-9999');
      expect(res.advisories[0].kev).toBe(true);
      // 2番目は critical のエントリ
      expect(res.advisories[1].id).toBe('CVE-2026-0001');
      expect(res.advisories[1].severity).toBe('critical');
      // 推奨版は下位（11件目）にあった 1.9.9 も含めて全件から計算されていること
      expect(formatAdvisoryRecommendation('1.0.0', res.advisories)).toContain('1.9.9');
    });
  });
});
