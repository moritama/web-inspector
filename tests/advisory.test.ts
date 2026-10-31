/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOL照合単体テスト (tests/advisory.test.ts)
 * 
 * Rev.2.1 Phase 2 (IMP-06: オフライン脆弱性DB品質・鮮度管理) の網羅的テスト
 */

import { describe, expect, it } from 'vitest';
import {
  calculateDbFreshness,
  formatAdvisoryRecommendation,
  getAdvisoryDbMetadata,
  matchOfflineAdvisories,
  resolveRecommendedVersion,
} from '../src/detection/advisory';

describe('オフライン既知脆弱性・EOL照合テスト (Rev.2.1 IMP-06 / D11-D20)', () => {
  // D16: Matched テスト
  it('D16: 古いjQuery 2.2.4 に対して脆弱性とEOLが正確に検出され Matched となること', () => {
    const result = matchOfflineAdvisories('jQuery', '2.2.4');

    expect(result.technology).toBe('jQuery');
    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.matchStatus).toBe('Potentially Affected');
    expect(result.advisories.length).toBeGreaterThan(0);

    const cveIds = result.advisories.map((a) => a.id);
    expect(cveIds).toContain('CVE-2015-9251');
    expect(result.eolInfo.status).toBe('EOL');
  });

  it('サポート終了済みの古いPHP 7.4.30 に対してEOLおよび脆弱性が照合され Matched となること', () => {
    const result = matchOfflineAdvisories('PHP', '7.4.30');

    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.eolInfo.status).toBe('EOL');
    expect(result.matchStatus).toBe('Potentially Affected');
    expect(result.advisories.some((a) => a.id === 'CVE-2022-31628')).toBe(true);
  });

  // D12: No Match テスト
  it('D12: 安全な最新Bootstrap 5.3.3 に対して脆弱性なし (No Match / Not Affected) と判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', '5.3.3');

    expect(result.offlineMatchStatus).toBe('No Match');
    expect(result.matchStatus).toBe('Not Affected');
    expect(result.advisories.length).toBe(0);
    expect(result.eolInfo.status).toBe('Supported');
  });

  // D11: Not Covered テスト
  it('D11: 未登録の技術の場合は Not Covered (No Data) となること', () => {
    const result = matchOfflineAdvisories('UnknownCustomLib', '1.0.0');

    expect(result.offlineMatchStatus).toBe('Not Covered');
    expect(result.matchStatus).toBe('No Data');
    expect(result.advisories.length).toBe(0);
    expect(result.eolInfo.status).toBe('Unknown');
  });

  // D15: Unknown Version テスト
  it('D15: バージョンが不明 (null または空文字) の場合、Unknown Version (Needs Review) となること', () => {
    const resultNull = matchOfflineAdvisories('jQuery', null);
    expect(resultNull.offlineMatchStatus).toBe('Unknown Version');
    expect(resultNull.matchStatus).toBe('Needs Review');
    expect(resultNull.advisories.length).toBe(0);
    expect(resultNull.eolInfo.status).toBe('Unknown');

    const resultEmpty = matchOfflineAdvisories('jQuery', '   ');
    expect(resultEmpty.offlineMatchStatus).toBe('Unknown Version');
    expect(resultEmpty.matchStatus).toBe('Needs Review');
  });

  // D14: Linuxパッケージ誤変換防止テスト (バックポート考慮)
  it('D14: Ubuntu/Debianパッケージバージョン (例: 2.4.52-1ubuntu4) は誤検知を避けて Unknown Version / Needs Review となること', () => {
    // 通常の SemVer "2.4.52" なら脆弱性 CVE-2021-44790 (< 2.4.52) に一致するが、
    // パッケージ版ではバックポート修正されている可能性が高いため断定を避ける
    const result = matchOfflineAdvisories('Apache', '2.4.52-1ubuntu4');

    expect(result.offlineMatchStatus).toBe('Unknown Version');
    expect(result.matchStatus).toBe('Needs Review');
    expect(result.advisories.length).toBe(0);
    expect(result.warning).toContain('Linuxディストリビューション固有パッケージ');
  });

  it('D14: Debianパッケージバージョン (例: 1.18.0-0ubuntu1.4) に対しても安全側に倒すこと', () => {
    const result = matchOfflineAdvisories('Nginx', '1.18.0-0ubuntu1.4');

    expect(result.offlineMatchStatus).toBe('Unknown Version');
    expect(result.matchStatus).toBe('Needs Review');
  });

  it('SPEC-02: distroHint オプション指定時は Unknown Version / Needs Review となりディストリ固有注記が返ること', () => {
    const result = matchOfflineAdvisories('Apache', '2.4.41', undefined, { distroHint: 'Ubuntu' });
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
    const result = matchOfflineAdvisories('Laravel', '8.0.0');

    expect(result.technology).toBe('Laravel');
    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.eolInfo.status).toBe('EOL');
    expect(result.advisories.some((a) => a.id === 'CVE-2021-3129')).toBe(true);
  });

  it('サポート終了済みの古いNode.js 16.14.0 に対してEOLが検出されること', () => {
    const result = matchOfflineAdvisories('Node.js', '16.14.0');

    expect(result.technology).toBe('Node.js');
    expect(result.offlineMatchStatus).toBe('Matched');
    expect(result.eolInfo.status).toBe('EOL');
  });

  it('AngularJS 1.8.3 に対して全バージョン影響のCVE-2022-25869が検出され、修正版なし(null)および移行推奨案内が出力されること', () => {
    const result = matchOfflineAdvisories('AngularJS', '1.8.3');

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
      const result = matchOfflineAdvisories('Apache', '2.4.49');
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
      const result = matchOfflineAdvisories('PHP', '8.0.10');
      const recommended = resolveRecommendedVersion('8.0.10', result.advisories);
      expect(recommended).toBe('8.1.29');
    });

    it('Bootstrap 4.3.0 検出時に、複数ブランチ修正版 (3.4.1 / 4.3.1) から 4.3 系列の 4.3.1 が正確に抽出されること', () => {
      const result = matchOfflineAdvisories('Bootstrap', '4.3.0');
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
});
