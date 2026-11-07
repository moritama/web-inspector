/**
 * Web Technology & Security Inspector
 * 調査完全性・エビデンス品質 単体テスト (tests/coverage.test.ts) - IMP-08
 */

import { describe, expect, it } from 'vitest';
import {
  assessInspectionCoverage,
  countDomItems,
  hasDomResourceReferences,
  maskSensitiveData,
} from '../src/shared/coverage';

describe('調査完全性・エビデンス品質テスト (IMP-08)', () => {
  it('全シグナルが正常に収集できた場合、overallStatus: complete と判定されること', () => {
    const coverage = assessInspectionCoverage({
      hasDom: true,
      hasHeaders: true,
      hasCookiesPermission: true,
      cookieCount: 5,
      hasWebRequestPermission: true,
      iframeCount: 0,
      unobservedPreScan: false,
      pageNavigatedDuringScan: false,
    });

    expect(coverage.overallStatus).toBe('complete');
    expect(coverage.dom).toBe('complete');
    expect(coverage.headers).toBe('complete');
    expect(coverage.cookies).toBe('complete');
  });

  it('HTTPヘッダーやCookieの権限が不足している場合、partial と判定され理由が記録されること', () => {
    const coverage = assessInspectionCoverage({
      hasDom: true,
      hasHeaders: false, // 拡張機能起動前の初期通信が未取得
      hasCookiesPermission: false, // Cookie権限不足
      cookieCount: 0,
      hasWebRequestPermission: false,
      unobservedPreScan: true,
    });

    expect(coverage.overallStatus).toBe('partial');
    expect(coverage.headers).toBe('partial');
    expect(coverage.cookies).toBe('unavailable');
    expect(coverage.details?.unobservedPreScan).toBe(true);
  });

  it('URLやヘッダー内の認証トークン・機密パラメータが適切にマスクされること', () => {
    const secretUrl = 'https://example.com/api?token=secret_jwt_xyz123&api_key=ak_9999&id=10';
    const maskedUrl = maskSensitiveData(secretUrl);

    expect(maskedUrl).not.toContain('secret_jwt_xyz123');
    expect(maskedUrl).not.toContain('ak_9999');
    expect(maskedUrl).toContain('id=10'); // 非機密パラメータは維持
    expect(maskedUrl).toContain('token=[REDACTED]');

    const authHeader = 'Authorization: Bearer my_super_secret_bearer_token';
    const maskedHeader = maskSensitiveData(authHeader);
    expect(maskedHeader).not.toContain('my_super_secret_bearer_token');
    expect(maskedHeader).toContain('Bearer [REDACTED]');
  });

  describe('v1.7.1 T06: DOM 収集件数の算出と部分的完全性の判定', () => {
    it('countDomItems が metaTags と scriptUrls だけでなく domMarkers・スタイルシート・クラス名 (htmlSnippets) も合算すること', () => {
      const count = countDomItems({
        metaTags: [{ name: 'generator', content: 'Drupal 10' }],
        scriptUrls: ['https://app.example.test/js/main.js'],
        domMarkers: ['[ng-version]', '_nghost-'],
        linkUrls: [
          { rel: 'stylesheet', href: 'https://app.example.test/css/app.css' },
          { rel: 'icon', href: 'https://app.example.test/favicon.ico' },
        ],
        cssAssets: [
          // linkUrls の stylesheet と同一 URL は重複カウントしない
          {
            href: 'https://app.example.test/css/app.css',
            filename: 'app.css',
            evidenceType: 'css-url',
            confidence: 'low',
          },
          // cssAssets のみに存在するスタイルシートは加算される
          {
            href: 'https://app.example.test/css/theme.css',
            filename: 'theme.css',
            evidenceType: 'css-url',
            confidence: 'low',
          },
        ],
        htmlSnippets: ['container mx-auto', 'btn btn-primary'],
      });

      // metaTags(1) + scriptUrls(1) + domMarkers(2) + stylesheets(2) + htmlSnippets(2) = 8
      expect(count).toBe(8);
    });

    it('DOM にリソースの参照があるのに通信先が 0 件のとき、完全性が partial になり理由が記録されること', () => {
      const domSignals = {
        scriptUrls: ['https://cdn.example.test/app.js'],
        linkUrls: [],
        domResourceUrls: [],
        resourceEntries: [],
      };
      expect(hasDomResourceReferences(domSignals)).toBe(true);

      const coverage = assessInspectionCoverage({
        hasDom: true,
        domItemCount: 3,
        hasHeaders: true,
        headerCount: 5,
        hasCookiesPermission: true,
        cookieCount: 1,
        hasWebRequestPermission: true,
        hasDomResourceReferences: true,
        externalConnectionCount: 0,
      });

      expect(coverage.overallStatus).toBe('partial');
      expect(coverage.network).toBe('partial');
      expect(coverage.details?.partialReasons).toBeDefined();
      expect(coverage.details?.partialReasons?.some((r) => r.includes('通信先が 0 件'))).toBe(
        true
      );
    });

    it('Content Script の収集が途中で失敗したとき、完全性が partial になり理由が記録されること', () => {
      const coverage = assessInspectionCoverage({
        hasDom: true,
        domItemCount: 2,
        domCollectionPartial: true,
        domCollectionErrors: ['link[href] 収集エラー: Mock DOM failure'],
        hasHeaders: true,
        headerCount: 4,
        hasCookiesPermission: true,
        cookieCount: 0,
        hasWebRequestPermission: true,
        hasDomResourceReferences: false,
        externalConnectionCount: 1,
      });

      expect(coverage.overallStatus).toBe('partial');
      expect(coverage.dom).toBe('partial');
      expect(coverage.details?.partialReasons).toBeDefined();
      expect(
        coverage.details?.partialReasons?.some((r) =>
          r.includes('Content Script の DOM シグナル収集が途中で失敗しました')
        )
      ).toBe(true);
    });
  });
});
