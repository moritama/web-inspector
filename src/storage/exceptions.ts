/**
 * Web Technology & Security Inspector
 * 診断項目の許容・除外設定ストレージ管理 (src/storage/exceptions.ts) - IMP-10
 * 
 * 既知の許容リスクや誤検知に対して、不要な警告を継続表示しないようにする永続化マネージャー。
 * chrome.storage.local に保存し、安定ID (findingId) と期限 (expiresAt) に基づいて管理します。
 */

import { ExceptionStatus, FindingException } from '../shared/types';
import {
  extractOriginForIdentity,
  generateFindingIdFromCheck,
  generateLegacyFindingIdFromCheck,
  normalizeUrlForIdentity,
  stripUrlQueryAndFragment,
} from '../shared/identity';

export const STORAGE_KEY_EXCEPTIONS = 'web_inspector_exceptions';

/**
 * v1.6.6 以前の旧 FindingId から新 FindingId (origin + checkId [+ resourceKey]) へ移行するための既知チェック定義
 */
const KNOWN_SECURITY_CHECK_SPECS: ReadonlyArray<{ checkId: string; names: readonly string[] }> = [
  { checkId: 'SEC-HSTS-00', names: ['HSTS (Strict-Transport-Security)'] },
  { checkId: 'SEC-HSTS-01', names: ['HSTS (Strict-Transport-Security)'] },
  { checkId: 'SEC-HSTS-02', names: ['HSTS (Strict-Transport-Security)'] },
  { checkId: 'SEC-CSP-00', names: ['CSP (Content-Security-Policy)'] },
  { checkId: 'SEC-CSP-01', names: ['CSP (Content-Security-Policy)'] },
  { checkId: 'SEC-CSP-02', names: ['CSP (Content-Security-Policy-Report-Only)'] },
  { checkId: 'SEC-CSP-03', names: ['CSP (Content-Security-Policy)'] },
  { checkId: 'SEC-CSP-META-RO', names: ['CSP (meta Content-Security-Policy-Report-Only)'] },
  {
    checkId: 'SEC-XFO-00',
    names: ['X-Frame-Options', 'クリックジャッキング対策 (frame-ancestors)'],
  },
  { checkId: 'SEC-XFO-01', names: ['X-Frame-Options (クリックジャッキング対策)', 'X-Frame-Options'] },
  { checkId: 'SEC-XFO-02', names: ['X-Frame-Options (無効または非推奨な設定値)', 'X-Frame-Options'] },
  { checkId: 'SEC-XCTO-00', names: ['X-Content-Type-Options'] },
  { checkId: 'SEC-XCTO-01', names: ['X-Content-Type-Options'] },
  { checkId: 'SEC-REF-00', names: ['Referrer-Policy'] },
  { checkId: 'SEC-REF-01', names: ['Referrer-Policy'] },
  {
    checkId: 'SEC-REF-02',
    names: ['Referrer-Policy (無効な設定値)', 'Referrer-Policy (unsafe-url)', 'Referrer-Policy'],
  },
  { checkId: 'SEC-REF-03', names: ['Referrer-Policy (no-referrer-when-downgrade)', 'Referrer-Policy'] },
  { checkId: 'SEC-PERM-01', names: ['Permissions-Policy'] },
  { checkId: 'SEC-CORS-01', names: ['CORS設定 (クロスオリジン許可)'] },
  { checkId: 'SEC-CORS-02', names: ['CORS設定 (クロスオリジン許可)'] },
  { checkId: 'SEC-DISC-01', names: ['Webサーバー詳細バージョン露出'] },
  { checkId: 'SEC-DISC-02', names: ['バックエンド技術情報露出 (X-Powered-By)'] },
  { checkId: 'SEC-DISC-03', names: ['バックエンド技術情報露出 (X-AspNet-Version)'] },
  { checkId: 'SEC-HTTPS-00', names: ['HTTPS暗号化通信'] },
  { checkId: 'SEC-HTTPS-01', names: ['暗号化通信未適用 (平文HTTP接続)'] },
  {
    checkId: 'SEC-MIXED-ACTIVE',
    names: [
      'アクティブ混在コンテンツ / 非暗号化フォーム送信 (Active Mixed Content)',
      'アクティブ混在コンテンツ (Active Mixed Content)',
    ],
  },
  { checkId: 'SEC-MIXED-PASSIVE', names: ['パッシブ混在コンテンツ (Passive Mixed Content)'] },
  { checkId: 'SEC-MIXED-00', names: ['混在コンテンツ (Mixed Content) なし'] },
  { checkId: 'SEC-COOKIE-HTTPONLY', names: ['認証・セッションCookie HttpOnly未設定'] },
  { checkId: 'SEC-COOKIE-SECURE', names: ['認証・セッションCookie Secure未設定'] },
  { checkId: 'SEC-COOKIE-SECURE-CSRF', names: ['CSRFトークン Secure属性未設定'] },
  { checkId: 'SEC-COOKIE-SECURE-GENERAL', names: ['Cookie Secure属性未設定 (一般・解析用)'] },
  { checkId: 'SEC-COOKIE-00', names: ['Cookie属性セキュリティ'] },
];

/**
 * 単一の許容設定を v1.7.0 形式 (origin + checkId [+ resourceKey]) へ移行する (IMPL-09)
 *
 * @param ex 移行対象の許容設定
 * @param fallbackUrl targetUrl が省略されている場合の補助URL
 * @returns 移行後の FindingException と変更有無
 */
export function migrateFindingException(
  ex: FindingException,
  fallbackUrl?: string
): { migrated: FindingException; changed: boolean } {
  const referenceUrl = ex.targetUrl || fallbackUrl || '';
  let changed = false;
  let nextFindingId = ex.findingId;
  let nextCheckId = ex.checkId;
  let nextTargetUrl = ex.targetUrl;

  if (ex.targetUrl) {
    const maskedUrl = stripUrlQueryAndFragment(ex.targetUrl);
    if (maskedUrl && maskedUrl !== ex.targetUrl) {
      nextTargetUrl = maskedUrl;
      changed = true;
    }
  }

  if (referenceUrl) {
    // 1. checkId が明示されている場合、または findingId が SEC-* の直接指定である場合
    const explicitCheckId =
      nextCheckId || (ex.findingId.startsWith('SEC-') ? ex.findingId : undefined);
    if (explicitCheckId) {
      const expectedNewId = generateFindingIdFromCheck(
        explicitCheckId,
        referenceUrl,
        ex.resourceKey || ''
      );
      if (nextFindingId !== expectedNewId || nextCheckId !== explicitCheckId) {
        nextFindingId = expectedNewId;
        nextCheckId = explicitCheckId;
        changed = true;
      }
    } else if (ex.findingId.startsWith('find_')) {
      // 2. v1.6.6 形式のハッシュ (urlStr全体や check.name に依存していた ID) を逆引きして新 ID へ移行
      const candidateUrls = Array.from(
        new Set([ex.targetUrl, nextTargetUrl, fallbackUrl].filter((u): u is string => Boolean(u)))
      );
      let matchedSpecCheckId: string | undefined;

      for (const candUrl of candidateUrls) {
        for (const spec of KNOWN_SECURITY_CHECK_SPECS) {
          // targetKey = checkId のパターン
          const legacyById = generateLegacyFindingIdFromCheck(spec.checkId, candUrl, '');
          if (ex.findingId === legacyById) {
            matchedSpecCheckId = spec.checkId;
            break;
          }
          // targetKey = name のパターン (v1.6.6 service-worker.ts)
          for (const name of spec.names) {
            const legacyByName = generateLegacyFindingIdFromCheck(spec.checkId, candUrl, name);
            if (ex.findingId === legacyByName) {
              matchedSpecCheckId = spec.checkId;
              break;
            }
          }
          if (matchedSpecCheckId) break;
        }
        if (matchedSpecCheckId) break;
      }

      if (matchedSpecCheckId) {
        const expectedNewId = generateFindingIdFromCheck(
          matchedSpecCheckId,
          referenceUrl,
          ex.resourceKey || ''
        );
        if (nextFindingId !== expectedNewId || nextCheckId !== matchedSpecCheckId) {
          nextFindingId = expectedNewId;
          nextCheckId = matchedSpecCheckId;
          changed = true;
        }
      }
    }
  }

  if (!changed) {
    return { migrated: ex, changed: false };
  }

  return {
    migrated: {
      ...ex,
      findingId: nextFindingId,
      ...(nextCheckId ? { checkId: nextCheckId } : {}),
      ...(nextTargetUrl ? { targetUrl: nextTargetUrl } : {}),
    },
    changed: true,
  };
}

/**
 * 許容設定リスト全体を v1.7.0 形式に移行する (IMPL-09)
 */
export function migrateFindingExceptions(
  exceptions: FindingException[],
  fallbackUrl?: string
): { exceptions: FindingException[]; changed: boolean } {
  let anyChanged = false;
  const migratedList = exceptions.map((ex) => {
    const { migrated, changed } = migrateFindingException(ex, fallbackUrl);
    if (changed) anyChanged = true;
    return migrated;
  });
  return { exceptions: migratedList, changed: anyChanged };
}

/**
 * すべての許容・除外設定を取得する（読み込み時に旧形式の ID を自動移行する）
 */
export async function getAllFindingExceptions(): Promise<FindingException[]> {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      const data = await chrome.storage.local.get(STORAGE_KEY_EXCEPTIONS);
      const rawList = (data[STORAGE_KEY_EXCEPTIONS] as FindingException[]) || [];
      const { exceptions: migratedList, changed } = migrateFindingExceptions(rawList);
      if (changed) {
        try {
          await chrome.storage.local.set({ [STORAGE_KEY_EXCEPTIONS]: migratedList });
        } catch {
          // 保存失敗時も移行後のメモリ上のリストを返す
        }
      }
      return migratedList;
    }
  } catch {
    // テスト環境等のフォールバック
  }
  return [];
}

/**
 * 許容・除外設定を保存（追加または更新）する
 */
export async function saveFindingException(exception: FindingException): Promise<void> {
  const { migrated } = migrateFindingException(exception);
  const list = await getAllFindingExceptions();
  const existingIndex = list.findIndex(
    (e) => e.id === migrated.id || e.findingId === migrated.findingId
  );

  let updated: FindingException[];
  if (existingIndex >= 0) {
    updated = [...list];
    updated[existingIndex] = migrated;
  } else {
    updated = [migrated, ...list];
  }

  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    await chrome.storage.local.set({ [STORAGE_KEY_EXCEPTIONS]: updated });
  }
}

/**
 * 指定したIDの許容・除外設定を削除する
 */
export async function deleteFindingException(id: string): Promise<void> {
  const list = await getAllFindingExceptions();
  const filtered = list.filter((e) => e.id !== id && e.findingId !== id);

  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    await chrome.storage.local.set({ [STORAGE_KEY_EXCEPTIONS]: filtered });
  }
}

/**
 * すべての許容設定をクリアする
 */
export async function clearAllFindingExceptions(): Promise<void> {
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    await chrome.storage.local.remove(STORAGE_KEY_EXCEPTIONS);
  }
}

/**
 * 例外設定の有効期限を評価する
 *
 * @param exception 評価対象の例外設定
 * @param nowMs 現在時刻のミリ秒（テスト用）
 * @returns ExceptionStatus ('accepted' | 'false-positive' | 'muted' | 'expired')
 */
export function evaluateExceptionStatus(
  exception: FindingException,
  nowMs = Date.now()
): ExceptionStatus {
  if (exception.expiresAt) {
    const expTime = new Date(exception.expiresAt).getTime();
    if (!isNaN(expTime) && nowMs > expTime) {
      return 'expired';
    }
  }
  return exception.status;
}

export interface FindingCheckContext {
  checkId?: string;
  name?: string;
  resourceKey?: string;
}

/**
 * 指定した findingId と URL に対する例外設定を判定する (Rev.2.1 IMP-10 / v1.7.0 T10 IMPL-09)
 *
 * @param findingId 安定ID
 * @param targetUrl 対象ページのURL
 * @param exceptions 照合用例外リスト（省略時は空配列）
 * @param checkContext 診断項目の補助コンテキスト（旧形式IDからの動的移行照合用）
 * @returns 判定結果
 */
export function matchFindingException(
  findingId: string,
  targetUrl?: string,
  exceptions: FindingException[] = [],
  checkContext?: FindingCheckContext
): {
  status: ExceptionStatus;
  exception?: FindingException;
} {
  const targetOrigin = targetUrl ? extractOriginForIdentity(targetUrl) : '';
  const strippedTarget = targetUrl
    ? normalizeUrlForIdentity(stripUrlQueryAndFragment(targetUrl))
    : '';

  for (const rawEx of exceptions) {
    const { migrated: ex } = migrateFindingException(rawEx, targetUrl);

    // 対象URLのスコープ確認 (オリジン一致 + クエリ・フラグメント除去後のスコープ確認)
    if (rawEx.targetUrl && targetUrl) {
      const exOrigin = extractOriginForIdentity(rawEx.targetUrl);
      if (exOrigin !== targetOrigin) {
        continue;
      }
      const strippedExUrl = normalizeUrlForIdentity(stripUrlQueryAndFragment(rawEx.targetUrl));
      // 同一オリジン内で、パス前方一致または checkId ベースのオリジン単位許容設定であれば対象とする
      const isPrefixMatch = strippedTarget.startsWith(strippedExUrl);
      const isOriginScopedFinding =
        ex.findingId.startsWith('find_') || Boolean(ex.checkId) || Boolean(checkContext?.checkId);
      if (!isPrefixMatch && !isOriginScopedFinding) {
        continue;
      }
    }

    let isMatched = ex.findingId === findingId || rawEx.findingId === findingId;

    // 動的チェック項目（ライブラリ脆弱性・EOL・不一致等）の旧 v1.6.6 ID 照合フォールバック
    if (!isMatched && checkContext?.checkId) {
      const candidateUrls = Array.from(
        new Set([rawEx.targetUrl, ex.targetUrl, targetUrl].filter((u): u is string => Boolean(u)))
      );
      for (const candUrl of candidateUrls) {
        const legacyWithName = generateLegacyFindingIdFromCheck(
          checkContext.checkId,
          candUrl,
          checkContext.name || ''
        );
        const legacyWithId = generateLegacyFindingIdFromCheck(checkContext.checkId, candUrl, '');
        const legacyWithRes = checkContext.resourceKey
          ? generateLegacyFindingIdFromCheck(
              checkContext.checkId,
              candUrl,
              checkContext.resourceKey
            )
          : '';
        if (
          rawEx.findingId === legacyWithName ||
          rawEx.findingId === legacyWithId ||
          (legacyWithRes &&
            (rawEx.findingId === legacyWithRes || rawEx.findingId.startsWith(`${legacyWithRes}_`)))
        ) {
          isMatched = true;
          break;
        }
      }
    }

    // 逆引き（checkContext なしで呼ばれた場合でも、targetUrl から新 ID が findingId と一致するか確認）
    if (!isMatched && ex.checkId && targetUrl) {
      const recomputed = generateFindingIdFromCheck(ex.checkId, targetUrl, ex.resourceKey || '');
      if (recomputed === findingId) {
        isMatched = true;
      }
    }

    if (isMatched) {
      // 呼び出し元のオブジェクトも新 ID へインプレース更新しておく
      if (rawEx.findingId !== findingId && rawEx.findingId.startsWith('find_')) {
        rawEx.findingId = findingId;
      }
      const status = evaluateExceptionStatus(ex);
      return {
        status,
        exception: {
          ...ex,
          findingId,
        },
      };
    }
  }

  return { status: 'active' };
}
