/**
 * Web Technology & Security Inspector
 * 診断項目の許容・除外設定 単体テスト (tests/exceptions.test.ts) - IMP-10
 */

import { describe, expect, it } from 'vitest';
import {
  evaluateExceptionStatus,
  matchFindingException,
  migrateFindingException,
} from '../src/storage/exceptions';
import {
  generateFindingIdFromCheck,
  generateLegacyFindingIdFromCheck,
} from '../src/shared/identity';
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

  it('T10 (IMPL-09): クエリだけが違う URL でも許容設定が効き続け、v1.6.6 形式の許容設定が移行後も効くこと', () => {
    const url1 = 'https://example.com/a?token=1#top';
    const url2 = 'https://example.com/a?token=2#bottom';

    // 新形式の ID はクエリやフラグメントが変わっても同一であること
    const newId1 = generateFindingIdFromCheck('SEC-HSTS-01', url1);
    const newId2 = generateFindingIdFromCheck('SEC-HSTS-01', url2);
    expect(newId1).toBe(newId2);

    // v1.6.6 形式で保存されていた許容設定
    const legacyException: FindingException = {
      id: 'ex_legacy_1',
      findingId: generateLegacyFindingIdFromCheck(
        'SEC-HSTS-01',
        url1,
        'HSTS (Strict-Transport-Security)'
      ),
      targetUrl: url1,
      status: 'accepted',
      reason: 'v1.6.6 からの移行テスト',
      createdAt: '2026-10-01T00:00:00Z',
    };

    const { migrated, changed } = migrateFindingException(legacyException);
    expect(changed).toBe(true);
    expect(migrated.findingId).toBe(newId2);
    expect(migrated.targetUrl).toBe('https://example.com/a');

    // 移行後の許容設定が url2 に対して有効であること
    const matchAfterMigrate = matchFindingException(newId2, url2, [migrated]);
    expect(matchAfterMigrate.status).toBe('accepted');

    // 未移行のまま matchFindingException に渡された場合でも移行・照合されること
    const matchDirect = matchFindingException(newId2, url2, [legacyException]);
    expect(matchDirect.status).toBe('accepted');
  });

  it.each([
    {
      checkId: 'SEC-HTTPS-01',
      url: 'http://legacy-http.example.test/login',
      oldName: '暗号化通信未適用 (平文HTTP接続)',
      newName: 'HTTPS暗号化通信',
    },
    {
      checkId: 'SEC-CORS-01',
      url: 'https://legacy-cors.example.test/api',
      oldName: 'CORS設定 (クロスオリジン許可)',
      newName: 'CORS (Cross-Origin Resource Sharing)',
    },
    {
      checkId: 'SEC-CORS-02',
      url: 'https://legacy-cors.example.test/public',
      oldName: 'CORS設定 (クロスオリジン許可)',
      newName: 'CORS (Cross-Origin Resource Sharing)',
    },
    {
      checkId: 'SEC-REF-02',
      url: 'https://legacy-ref.example.test/',
      oldName: 'Referrer-Policy (無効な設定値)',
      newName: 'Referrer-Policy',
    },
    {
      checkId: 'SEC-REF-02',
      url: 'https://legacy-ref.example.test/',
      oldName: 'Referrer-Policy (unsafe-url)',
      newName: 'Referrer-Policy',
    },
    {
      checkId: 'SEC-REF-03',
      url: 'https://legacy-ref.example.test/',
      oldName: 'Referrer-Policy (no-referrer-when-downgrade)',
      newName: 'Referrer-Policy',
    },
  ])(
    'v1.7.1 T11 (R05): 旧い項目名「$oldName」で保存された許容設定が、名前を「$newName」に統一した後も $checkId に効くこと',
    ({ checkId, url, oldName, newName }) => {
      const currentFindingId = generateFindingIdFromCheck(checkId, url);

      // 1. v1.6.6 の旧項目名ハッシュ形式で保存された許容設定
      const legacyHashEx: FindingException = {
        id: `ex_hash_${checkId}`,
        findingId: generateLegacyFindingIdFromCheck(checkId, url, oldName),
        targetUrl: url,
        status: 'accepted',
        reason: '旧項目名での保存データ',
        createdAt: '2026-10-01T00:00:00Z',
      };

      const { migrated, changed } = migrateFindingException(legacyHashEx);
      expect(changed).toBe(true);
      expect(migrated.findingId).toBe(currentFindingId);

      const matchedFromMigrated = matchFindingException(currentFindingId, url, [migrated], {
        checkId,
        name: newName,
      });
      expect(matchedFromMigrated.status).toBe('accepted');

      // 2. 項目名そのもので保存された許容設定でも同じ checkId に効くこと
      const rawNameEx: FindingException = {
        id: `ex_name_${checkId}`,
        findingId: oldName,
        targetUrl: url,
        status: 'accepted',
        reason: '項目名直接指定の保存データ',
        createdAt: '2026-10-01T00:00:00Z',
      };
      const matchedFromRawName = matchFindingException(currentFindingId, url, [rawNameEx], {
        checkId,
        name: newName,
      });
      expect(matchedFromRawName.status).toBe('accepted');
    }
  );
});
