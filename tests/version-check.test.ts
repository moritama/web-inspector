/**
 * Web Technology & Security Inspector
 * Version 1.1 単体テスト (tests/version-check.test.ts)
 * 仕様書13項 (T01〜T18) の検証
 */

import { describe, expect, it } from 'vitest';
import { matchOfflineAdvisories } from '../src/detection/advisory';
import { DetectionEngine } from '../src/detection/engine';
import { compareVersions, satisfiesVersionRange } from '../src/security/version-matcher';
import { DomSignals } from '../src/shared/types';

describe('Version Matcher Utility', () => {
  it('compareVersions が正しく動作すること', () => {
    expect(compareVersions('4.3.1', '4.3.1')).toBe(0);
    expect(compareVersions('4.3.1', '4.6.2')).toBe(-1);
    expect(compareVersions('5.0.0', '4.3.1')).toBe(1);
    expect(compareVersions('3.6.0', '3.5.0')).toBe(1);
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

  it('satisfiesVersionRange は解析できないバージョンに対して常に false を返すこと (SPEC-06)', () => {
    expect(satisfiesVersionRange('abc', '< 3.0.0')).toBe(false);
    expect(satisfiesVersionRange('custom-build', '>= 1.0.0')).toBe(false);
  });

  it("'1.x' サイクルが 10.2.0 に一致しないこと (SPEC-04)", () => {
    // AngularJS のサイクルは '1.x' のみ。10.2.0 はこれに一致してはならず、未知系列として Unknown になる
    const result = matchOfflineAdvisories('AngularJS', '10.2.0');
    expect(result.eolInfo.status).not.toBe('EOL');
    expect(result.eolInfo.status).toBe('Unknown');
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
    const result = matchOfflineAdvisories('Bootstrap', '4.3.1');
    expect(result.eolInfo.status).toBe('EOL');
    expect(result.eolInfo.eolDate).toBe('2023-01-01');
  });

  it('T07: Bootstrap 4.3.0 を照合すると CVE-2019-8331 (Potentially Affected) と判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', '4.3.0');
    expect(result.matchStatus).toBe('Potentially Affected');
    expect(result.advisories.some((a) => a.id === 'CVE-2019-8331')).toBe(true);
    expect(result.maxCvss).toBe(6.1);
  });

  it('Bootstrap 4.3.1 (修正済み) を照合すると CVE-2019-8331 には該当しないこと', () => {
    const result = matchOfflineAdvisories('Bootstrap', '4.3.1');
    expect(result.advisories.some((a) => a.id === 'CVE-2019-8331')).toBe(false);
  });

  it('T08: バージョンが不明な場合は Unknown / Needs Review と判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', null);
    expect(result.eolInfo.status).toBe('Unknown');
    expect(result.matchStatus).toBe('Needs Review');
  });

  it('T09: 未登録の未知技術の場合は No Data と判定されること', () => {
    const result = matchOfflineAdvisories('UnknownCustomLib', '1.0.0');
    expect(result.matchStatus).toBe('No Data');
  });
});
