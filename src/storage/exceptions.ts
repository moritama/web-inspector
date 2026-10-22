/**
 * Web Technology & Security Inspector
 * 診断項目の許容・除外設定ストレージ管理 (src/storage/exceptions.ts) - IMP-10
 * 
 * 既知の許容リスクや誤検知に対して、不要な警告を継続表示しないようにする永続化マネージャー。
 * chrome.storage.local に保存し、安定ID (findingId) と期限 (expiresAt) に基づいて管理します。
 */

import { ExceptionStatus, FindingException } from '../shared/types';
import { normalizeUrlForIdentity } from '../shared/identity';

export const STORAGE_KEY_EXCEPTIONS = 'web_inspector_exceptions';

/**
 * すべての許容・除外設定を取得する
 */
export async function getAllFindingExceptions(): Promise<FindingException[]> {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      const data = await chrome.storage.local.get(STORAGE_KEY_EXCEPTIONS);
      return (data[STORAGE_KEY_EXCEPTIONS] as FindingException[]) || [];
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
  const list = await getAllFindingExceptions();
  const existingIndex = list.findIndex((e) => e.id === exception.id || e.findingId === exception.findingId);

  let updated: FindingException[];
  if (existingIndex >= 0) {
    updated = [...list];
    updated[existingIndex] = exception;
  } else {
    updated = [exception, ...list];
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

/**
 * 指定した findingId と URL に対する例外設定を判定する (Rev.2.1 IMP-10 / 9.4)
 *
 * @param findingId 安定ID
 * @param targetUrl 対象ページのURL
 * @param exceptions 照合用例外リスト（省略時はストレージから取得）
 * @returns 判定結果
 */
export function matchFindingException(
  findingId: string,
  targetUrl?: string,
  exceptions: FindingException[] = []
): {
  status: ExceptionStatus;
  exception?: FindingException;
} {
  const normalizedTarget = targetUrl ? normalizeUrlForIdentity(targetUrl) : '';

  for (const ex of exceptions) {
    if (ex.findingId === findingId) {
      // 対象URLのスコープ確認 (URL指定がある場合は前方一致またはホスト一致)
      if (ex.targetUrl && normalizedTarget) {
        const normExUrl = normalizeUrlForIdentity(ex.targetUrl);
        if (!normalizedTarget.startsWith(normExUrl)) {
          continue;
        }
      }

      const status = evaluateExceptionStatus(ex);
      return { status, exception: ex };
    }
  }

  return { status: 'active' };
}
