/**
 * Web Technology & Security Inspector
 * 診断項目の許容・除外設定 単体テスト (tests/exceptions.test.ts) - IMP-10
 */

import { describe, expect, it } from 'vitest';
import { evaluateExceptionStatus, matchFindingException } from '../src/storage/exceptions';
import { FindingException } from '../src/shared/types';

describe('診断項目の許容・除外設定 (IMP-10)', () => {
  it('有効期限内の例外設定は accepted として判定されること', () => {
    const futureDate = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 1日後
    const ex: FindingException = {
      id: 'ex_1',
      findingId: 'find_12345678_abcdef01',
      status: 'accepted',
      reason: '暫定運用のため許容',
      createdAt: new Date().toISOString(),
      expiresAt: futureDate,
    };

    const status = evaluateExceptionStatus(ex);
    expect(status).toBe('accepted');
  });

  it('有効期限を過ぎた例外設定は自動的に expired として判定されること', () => {
    const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(); // 1日前
    const ex: FindingException = {
      id: 'ex_2',
      findingId: 'find_12345678_abcdef01',
      status: 'accepted',
      reason: '期限切れの許容',
      createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
      expiresAt: pastDate,
    };

    const status = evaluateExceptionStatus(ex);
    expect(status).toBe('expired');
  });

  it('安定ID (findingId) が一致する場合に例外設定が適用されること', () => {
    const exceptions: FindingException[] = [
      {
        id: 'ex_target',
        findingId: 'find_secure_cookie_target',
        status: 'false-positive',
        reason: 'ローカルテスト環境のため除外',
        createdAt: new Date().toISOString(),
      },
    ];

    const match = matchFindingException('find_secure_cookie_target', 'https://example.com/login', exceptions);
    expect(match.status).toBe('false-positive');
    expect(match.exception?.reason).toBe('ローカルテスト環境のため除外');

    // 未登録のID
    const unmatch = matchFindingException('find_other_id', 'https://example.com/login', exceptions);
    expect(unmatch.status).toBe('active');
    expect(unmatch.exception).toBeUndefined();
  });

  it('targetUrl スコープが指定されている場合、対象URLのみに適用されること', () => {
    const exceptions: FindingException[] = [
      {
        id: 'ex_scoped',
        findingId: 'find_scoped_check',
        targetUrl: 'https://staging.example.com/',
        status: 'accepted',
        reason: 'ステージング環境のみ許容',
        createdAt: new Date().toISOString(),
      },
    ];

    // ステージング環境 -> 一致
    const matchStaging = matchFindingException('find_scoped_check', 'https://staging.example.com/mypage', exceptions);
    expect(matchStaging.status).toBe('accepted');

    // 本番環境 -> 不一致 (active)
    const matchProd = matchFindingException('find_scoped_check', 'https://example.com/mypage', exceptions);
    expect(matchProd.status).toBe('active');
  });
});
