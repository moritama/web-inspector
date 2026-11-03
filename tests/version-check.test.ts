/**
 * Web Technology & Security Inspector
 * Version 1.1 単体テスト (tests/version-check.test.ts)
 * 仕様書13項 (T01〜T18) の検証
 */

import { describe, expect, it } from 'vitest';
import { AdvisoryDatabase, matchOfflineAdvisories } from '../src/detection/advisory';
import fixtureDbJson from './fixtures/advisory-db.fixture.json';
import { DetectionEngine } from '../src/detection/engine';
import { compareVersions, satisfiesVersionRange } from '../src/security/version-matcher';
import { DomSignals } from '../src/shared/types';

const fixtureDb = fixtureDbJson as unknown as AdvisoryDatabase;

describe('Version Matcher Utility', () => {
  it('compareVersions が正しく動作すること', () => {
    expect(compareVersions('4.3.1', '4.3.1')).toBe(0);
    expect(compareVersions('4.3.1', '4.6.2')).toBe(-1);
    expect(compareVersions('5.0.0', '4.3.1')).toBe(1);
    expect(compareVersions('3.6.0', '3.5.0')).toBe(1);
  });

  it('compareVersions が SemVer 2.0 プレリリース・ビルドメタデータ・4要素以上の版番号を正しく比較すること (C1, SPEC-11)', () => {
    // 同じ major.minor.patch ならプレリリース付きは通常版より小さい
    expect(compareVersions('3.5.0-rc1', '3.5.0')).toBe(-1);
    expect(compareVersions('22.0.0-next.0', '22.0.0')).toBe(-1);
    expect(compareVersions('22.0.0', '22.0.0-rc.4')).toBe(1);

    // プレリリース識別子同士の比較（数値は数値比較、英数字は辞書順、連結形式 rc2 < rc10 対応）
    expect(compareVersions('22.0.0-next.1', '22.0.0-next.3')).toBe(-1);
    expect(compareVersions('22.0.0-next.3', '22.0.0-rc.1')).toBe(-1);
    expect(compareVersions('1.0.0-rc2', '1.0.0-rc10')).toBe(-1);
    expect(compareVersions('1.0.0-alpha', '1.0.0-alpha.1')).toBe(-1);
    expect(compareVersions('20.0.0-next.0.0.0', '20.0.0')).toBe(-1);
    expect(compareVersions('20.0.0-next.0.0.0', '20.3.17')).toBe(-1);

    // ビルドメタデータ (+...) は順序比較では無視する
    expect(compareVersions('1.2.3+20130313144700', '1.2.3+exp.sha.5114f85')).toBe(0);
    expect(compareVersions('1.2.3-beta+exp.sha', '1.2.3-beta')).toBe(0);

    // 4要素以上の数値バージョン比較
    expect(compareVersions('1.2.3.4', '1.2.3.5')).toBe(-1);
    expect(compareVersions('1.2.3.0', '1.2.3')).toBe(0);
  });

  it('satisfiesVersionRange のテーブルテスト (C1, SPEC-11)', () => {
    const cases: Array<[string, string, boolean]> = [
      ['22.0.0-next.1', '>= 22.0.0-next.0, < 22.0.0-next.3', true],
      ['22.0.0', '>= 22.0.0-next.0, < 22.0.0-next.3', false],
      ['3.5.0-rc1', '< 3.5.0', true],
      ['4.3.1', '4.x', true],
      ['5.0.0', '4.x', false],
      ['4.4.0', '4.3.x', false],
      ['4.3.9', '4.3.x', true],
      ['2.4.41-1ubuntu1', '< 2.4.41', false],
    ];
    for (const [version, range, expected] of cases) {
      expect(satisfiesVersionRange(version, range), `${version} in ${range}`).toBe(expected);
    }
  });

  it('satisfiesVersionRange が複合範囲を正しく判定すること', () => {
    expect(satisfiesVersionRange('4.3.0', '>= 4.0.0, < 4.3.1')).toBe(true);
    expect(satisfiesVersionRange('4.3.1', '>= 4.0.0, < 4.3.1')).toBe(false);
    expect(satisfiesVersionRange('3.4.1', '< 3.5.0')).toBe(true);
    expect(satisfiesVersionRange('3.6.0', '< 3.5.0')).toBe(false);
  });

  it('satisfiesVersionRange が "||" による複数ブランチ（OR条件）を正しく判定すること', () => {
    // PHP CVE-2022-31628: 7.4.31 未満、8.0.0〜8.0.23、8.1.0〜8.1.10
    const php2022Range = '< 7.4.31 || >= 8.0.0, < 8.0.24 || >= 8.1.0, < 8.1.11';
    expect(satisfiesVersionRange('7.4.30', php2022Range)).toBe(true);
    expect(satisfiesVersionRange('7.4.31', php2022Range)).toBe(false);
    expect(satisfiesVersionRange('8.0.23', php2022Range)).toBe(true);
    expect(satisfiesVersionRange('8.0.24', php2022Range)).toBe(false);
    expect(satisfiesVersionRange('8.1.10', php2022Range)).toBe(true);
    expect(satisfiesVersionRange('8.1.11', php2022Range)).toBe(false);
    expect(satisfiesVersionRange('8.2.0', php2022Range)).toBe(false);
  });

  it('satisfiesVersionRange は解析できないバージョンや壊れた範囲句に対して常に false を返すこと (SPEC-06, SPEC-11)', () => {
    expect(satisfiesVersionRange('abc', '< 3.0.0')).toBe(false);
    expect(satisfiesVersionRange('custom-build', '>= 1.0.0')).toBe(false);
    expect(satisfiesVersionRange('1.0.0-nxt', '>= 1.0.0')).toBe(false);
    expect(satisfiesVersionRange('1.5.0', '>= 1.0.0-nxt')).toBe(false);
    expect(satisfiesVersionRange('1.5.0', '>= 1.0.0-nxt, < 2.0.0')).toBe(false);
  });

  it("'1.x' サイクルが 10.2.0 に一致しないこと (SPEC-04)", () => {
    // AngularJS のサイクルは '1.x' のみ。10.2.0 はこれに一致してはならず、未知系列として Unknown になる
    const result = matchOfflineAdvisories('AngularJS', '10.2.0');
    expect(result.eolInfo.status).not.toBe('EOL');
    expect(result.eolInfo.status).toBe('Unknown');
  });
});

describe('T01 (v1.7.0): Angular プレリリース範囲照合と DB range 構文検証 (C1, SPEC-11)', () => {
  // 上流 OSV と同じ 9 件の Angular 脆弱性レコードを持つ固定 DB フィクスチャ
  const angularFixtureDb: AdvisoryDatabase = {
    version: '2026.10.26-test',
    generatedAt: '2026-10-26T00:00:00Z',
    libraries: {
      angular: {
        aliases: ['Angular'],
        eol: [
          { cycle: '20.x', status: 'Supported', eolDate: '2026-11-21' },
          { cycle: '18.x', status: 'EOL', eolDate: '2025-11-15' },
        ],
        versions: [
          {
            range: '>= 17.0.0-next.0, <= 18.2.14 || >= 19.0.0-next.0, < 19.2.20 || >= 20.0.0-next.0.0.0, < 20.3.18 || >= 21.0.0-next.0, < 21.2.4 || >= 22.0.0-next.0, < 22.0.0-next.3',
            cve: 'CVE-2026-32635',
            cvssScore: 7.5,
            severity: 'high',
            title: 'Angular i18n XSS',
            fixedVersion: '19.2.20 / 20.3.18 / 21.2.4 / 22.0.0-next.3',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-32635',
          },
          {
            range: '<= 19.2.25 || >= 20.0.0-next.0, < 20.3.25 || >= 21.0.0-next.0, < 21.2.17 || >= 22.0.0-next.0, < 22.0.0-rc.4',
            cve: 'CVE-2026-88057',
            cvssScore: 6.1,
            severity: 'medium',
            title: 'Angular XSS 88057',
            fixedVersion: '19.2.26 / 20.3.25 / 21.2.17 / 22.0.0-rc.4',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-88057',
          },
          {
            range: '<= 19.2.25 || >= 20.0.0-next.0, < 20.3.27 || >= 21.0.0-next.0, < 21.2.19 || >= 22.0.0-next.0, < 22.0.1',
            cve: 'CVE-2026-69151',
            cvssScore: 7.5,
            severity: 'high',
            title: 'Angular Vulnerability 69151',
            fixedVersion: '19.2.26 / 20.3.27 / 21.2.19 / 22.0.1',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-69151',
          },
          {
            range: '<= 19.2.25 || >= 20.0.0-next.0, < 20.3.25 || >= 21.0.0-next.0, < 21.2.17 || >= 22.0.0-next.0, < 22.0.1',
            cve: 'CVE-2026-54267',
            cvssScore: 7.5,
            severity: 'high',
            title: 'Angular Vulnerability 54267',
            fixedVersion: '19.2.26 / 20.3.25 / 21.2.17 / 22.0.1',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-54267',
          },
          {
            range: '<= 18.2.14 || >= 19.0.0-next.0, < 19.2.23 || >= 20.0.0-next.0, < 20.3.22 || >= 21.0.0-next.0, < 21.2.15 || >= 22.0.0-next.0, < 22.0.0-rc.2',
            cve: 'CVE-2026-52725',
            cvssScore: 7.5,
            severity: 'high',
            title: 'Angular Vulnerability 52725',
            fixedVersion: '19.2.23 / 20.3.22 / 21.2.15 / 22.0.0-rc.2',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-52725',
          },
          {
            range: '<= 18.2.14 || >= 19.0.0-next.0, < 19.2.22 || >= 20.0.0-next.0, < 20.3.22 || >= 21.0.0-next.0, < 21.2.15 || >= 22.0.0-next.0, < 22.0.0-rc.2',
            cve: 'CVE-2026-50557',
            cvssScore: 7.5,
            severity: 'high',
            title: 'Angular Vulnerability 50557',
            fixedVersion: '19.2.22 / 20.3.22 / 21.2.15 / 22.0.0-rc.2',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-50557',
          },
          {
            range: '<= 18.2.14 || >= 19.0.0-next.0, < 19.2.19 || >= 20.0.0-next.0, < 20.3.17 || >= 21.0.0-next.0, < 21.1.6 || >= 21.2.0-next.0, < 21.2.0',
            cve: 'CVE-2026-27970',
            cvssScore: 7.5,
            severity: 'high',
            title: 'Angular Vulnerability 27970',
            fixedVersion: '19.2.19 / 20.3.17 / 21.1.6 / 21.2.0',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-27970',
          },
          {
            range: '<= 18.2.14 || >= 19.0.0-next.0, < 19.2.18 || >= 20.0.0-next.0, < 20.3.16 || >= 21.0.0-next.0, < 21.0.7 || >= 21.1.0-next.0, < 21.1.0-rc.0',
            cve: 'CVE-2026-22610',
            cvssScore: 7.5,
            severity: 'high',
            title: 'Angular Vulnerability 22610',
            fixedVersion: '19.2.18 / 20.3.16 / 21.0.7 / 21.1.0-rc.0',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-22610',
          },
          {
            range: '>= 11.0.0-next.0, < 11.0.5 || >= 11.1.0-next.0, < 11.1.0-rc.3',
            cve: 'CVE-2021-4231',
            cvssScore: 5.4,
            severity: 'medium',
            title: 'Angular Vulnerability 4231',
            fixedVersion: '11.0.5 / 11.1.0-rc.3',
            advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-4231',
          },
        ],
      },
    },
  };

  it('Angular 20.3.17 を照合したとき、対象範囲の 6 件がすべて返り、範囲外の 3 件が返らないこと', () => {
    const result = matchOfflineAdvisories('Angular', '20.3.17', angularFixtureDb);
    const matchedIds = result.advisories.map((a) => a.id);

    expect(matchedIds).toEqual(
      expect.arrayContaining([
        'CVE-2026-32635',
        'CVE-2026-88057',
        'CVE-2026-69151',
        'CVE-2026-54267',
        'CVE-2026-52725',
        'CVE-2026-50557',
      ])
    );
    expect(matchedIds).toHaveLength(6);
    expect(matchedIds).not.toContain('CVE-2026-27970');
    expect(matchedIds).not.toContain('CVE-2026-22610');
    expect(matchedIds).not.toContain('CVE-2021-4231');
  });

  it('Angular 18.2.0 が CVE-2026-32635 の第 1 ブランチ (>= 17.0.0-next.0, <= 18.2.14) にヒットすること', () => {
    const result = matchOfflineAdvisories('Angular', '18.2.0', angularFixtureDb);
    const matchedIds = result.advisories.map((a) => a.id);
    expect(matchedIds).toContain('CVE-2026-32635');
  });
});

describe('T01 - T05: JavaScript & CSS バージョン検出と整合性確認', () => {
  const engine = new DetectionEngine();

  it('T01 & T02: JavaScript実行時情報から jQuery 3.6.0 と Bootstrap 4.3.1 を検出すること', () => {
    const dom: DomSignals = {
      url: 'https://example.com/',
      title: 'Test',
      metaTags: [],
      scriptUrls: [],
      linkUrls: [],
      domMarkers: [],
      htmlSnippets: [],
      mixedContent: [],
      cookiesFromDocument: [],
      cssAssets: [],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
      runtimeVersions: {
        jquery: '3.6.0',
        bootstrap4: '4.3.1',
      },
    });

    const jq = results.find((r) => r.technology === 'jQuery');
    expect(jq?.version).toBe('3.6.0');
    expect(jq?.versionSource).toBe('runtime');

    const bs = results.find((r) => r.technology === 'Bootstrap');
    expect(bs?.version).toBe('4.3.1');
    expect(bs?.versionSource).toBe('runtime');
  });

  it('T03 & T04: CSS URLから4.3.1を推定し、JSと一致 (match) と判定すること', () => {
    const dom: DomSignals = {
      url: 'https://example.com/',
      title: 'Test',
      metaTags: [],
      scriptUrls: [],
      linkUrls: [],
      domMarkers: [],
      htmlSnippets: [],
      mixedContent: [],
      cookiesFromDocument: [],
      cssAssets: [
        {
          href: 'https://example.com/lib/bootstrap-4.3.1/css/bootstrap.min.css',
          filename: 'bootstrap.min.css',
          inferredLibrary: 'Bootstrap',
          inferredVersion: '4.3.1',
          evidenceType: 'css-url',
          confidence: 'medium',
        },
      ],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
      runtimeVersions: {
        bootstrap4: '4.3.1',
      },
    });

    const bs = results.find((r) => r.technology === 'Bootstrap');
    expect(bs?.cssVersion).toBe('4.3.1');
    expect(bs?.jsVersion).toBe('4.3.1');
    expect(bs?.versionIntegrity?.status).toBe('match');
  });

  it('T05: CSS(4.3.1) と JS(4.6.2) で異なる場合、要確認 (mismatch) と判定すること', () => {
    const dom: DomSignals = {
      url: 'https://example.com/',
      title: 'Test',
      metaTags: [],
      scriptUrls: [],
      linkUrls: [],
      domMarkers: [],
      htmlSnippets: [],
      mixedContent: [],
      cookiesFromDocument: [],
      cssAssets: [
        {
          href: 'https://example.com/lib/bootstrap-4.3.1/css/bootstrap.min.css',
          filename: 'bootstrap.min.css',
          inferredLibrary: 'Bootstrap',
          inferredVersion: '4.3.1',
          evidenceType: 'css-url',
          confidence: 'medium',
        },
      ],
    };

    const results = engine.detect({
      url: 'https://example.com/',
      dom,
      runtimeVersions: {
        bootstrap4: '4.6.2',
      },
    });

    const bs = results.find((r) => r.technology === 'Bootstrap');
    expect(bs?.versionIntegrity?.status).toBe('mismatch');
  });
});

describe('T06 - T09: EOL & CVE 照合', () => {
  it('T06: Bootstrap 4.3.1 を照合すると EOL と判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', '4.3.1', fixtureDb);
    expect(result.eolInfo.status).toBe('EOL');
    expect(result.eolInfo.eolDate).toBe('2023-01-01');
  });

  it('T07: Bootstrap 4.3.0 を照合すると CVE-2019-8331 (Potentially Affected) と判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', '4.3.0', fixtureDb);
    expect(result.matchStatus).toBe('Potentially Affected');
    expect(result.advisories.some((a) => a.id === 'CVE-2019-8331')).toBe(true);
    expect(result.maxCvss).toBe(6.1);
  });

  it('Bootstrap 4.3.1 (修正済み) を照合すると CVE-2019-8331 には該当しないこと', () => {
    const result = matchOfflineAdvisories('Bootstrap', '4.3.1', fixtureDb);
    expect(result.advisories.some((a) => a.id === 'CVE-2019-8331')).toBe(false);
  });

  it('T08: バージョンが不明な場合は Unknown / Needs Review と判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', null, fixtureDb);
    expect(result.eolInfo.status).toBe('Unknown');
    expect(result.matchStatus).toBe('Needs Review');
  });

  it('T09: 未登録の未知技術の場合は No Data と判定されること', () => {
    const result = matchOfflineAdvisories('UnknownCustomLib', '1.0.0', fixtureDb);
    expect(result.matchStatus).toBe('No Data');
  });
});
