/**
 * Web Technology & Security Inspector
 * 調査完全性・エビデンス品質 単体テスト (tests/coverage.test.ts) - IMP-08
 */

import { describe, expect, it } from 'vitest';
import {
  assessInspectionCoverage,
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
});
