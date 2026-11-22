/**
 * Cookie の保存先（v1.8.2 T03 / D-3、指示書 §4.5・H13）
 *
 * - 調べるタブが属する保存先を chrome.cookies.getAllCookieStores() で探し、その storeId を
 *   通常の getAll と分割 Cookie（partitionKey 付き）の getAll の両方に渡す
 * - 見つからないとき（タブがどの保存先にも無い、API が無い、例外）は従来どおり storeId を指定しない
 * - 保存先を引く処理（resolveCookieStoreId）は差し替え可能。テストは偽の chrome.cookies を渡す（ネットワークに出ない）
 *
 * 偽の getAll は Chrome の文書どおり「storeId を省略すると実行コンテキストの保存先」を、spanning の
 * 拡張機能の Service Worker の保存先である通常の保存先（"0"）として返す（指示書 §4.5 の 2026-11-19 の確認）。
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  executeInspection,
  getInspectedCookies,
  InspectionDependencies,
  resolveCookieStoreId,
} from '../src/background/service-worker';
import type { DomSignals, InspectedCookieInfo } from '../src/shared/types';

const PAGE_URL = 'https://app.example.test/account';
const NORMAL_STORE = '0';
const INCOGNITO_STORE = '1';
const NORMAL_TAB = 11;
const INCOGNITO_TAB = 27;

interface FakeCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  session: boolean;
  hostOnly: boolean;
  storeId: string;
  partitionKey?: { topLevelSite: string };
}

const fakeCookie = (name: string, storeId: string, extra: Partial<FakeCookie> = {}): FakeCookie => ({
  name,
  value: 'v',
  domain: 'app.example.test',
  path: '/',
  secure: true,
  httpOnly: true,
  sameSite: 'lax',
  session: true,
  hostOnly: true,
  storeId,
  ...extra,
});

/** 保存先ごとの Cookie。分割 Cookie（CHIPS）は partitionKey 付き */
const COOKIES_BY_STORE: Record<string, FakeCookie[]> = {
  [NORMAL_STORE]: [
    fakeCookie('normal_only', NORMAL_STORE),
    fakeCookie('normal_chips', NORMAL_STORE, { partitionKey: { topLevelSite: 'https://example.test' } }),
  ],
  [INCOGNITO_STORE]: [
    fakeCookie('incognito_probe', INCOGNITO_STORE),
    fakeCookie('incognito_chips', INCOGNITO_STORE, { partitionKey: { topLevelSite: 'https://example.test' } }),
  ],
};

type GetAllDetails = { url: string; storeId?: string; partitionKey?: { topLevelSite: string } };

/** Chrome の getAll を模した偽物（storeId を省略すると通常の保存先） */
const createFakeGetAll = () =>
  vi.fn(async (details: GetAllDetails) => {
    const store = details.storeId ?? NORMAL_STORE;
    const all = COOKIES_BY_STORE[store] ?? [];
    return details.partitionKey
      ? all.filter((c) => c.partitionKey?.topLevelSite === details.partitionKey?.topLevelSite)
      : all.filter((c) => !c.partitionKey);
  });

const createFakeStores = (stores = [
  { id: NORMAL_STORE, tabIds: [3, NORMAL_TAB] },
  { id: INCOGNITO_STORE, tabIds: [INCOGNITO_TAB] },
]) => vi.fn(async () => stores);

const installFakeChrome = (cookiesApi: Record<string, unknown>): void => {
  (globalThis as { chrome?: unknown }).chrome = { cookies: cookiesApi };
};

const names = (cookies: InspectedCookieInfo[]): string[] => cookies.map((c) => c.name).sort();

const originalChrome = (globalThis as { chrome?: unknown }).chrome;

afterEach(() => {
  (globalThis as { chrome?: unknown }).chrome = originalChrome;
  vi.restoreAllMocks();
});

describe('v1.8.2 T03 (D-3): resolveCookieStoreId（調べるタブの保存先）', () => {
  it('陽性: シークレットのタブ ID を含む保存先 "1" を返す', async () => {
    await expect(
      resolveCookieStoreId(INCOGNITO_TAB, { getAllCookieStores: createFakeStores() })
    ).resolves.toBe(INCOGNITO_STORE);
  });

  it('陽性: 通常のタブ ID は保存先 "0" を返す', async () => {
    await expect(
      resolveCookieStoreId(NORMAL_TAB, { getAllCookieStores: createFakeStores() })
    ).resolves.toBe(NORMAL_STORE);
  });

  it('陽性: 保存先が 3 つ以上あっても、タブ ID を含む保存先を選ぶ（先頭を選ばない）', async () => {
    const stores = createFakeStores([
      { id: NORMAL_STORE, tabIds: [1, 2] },
      { id: '2', tabIds: [40] },
      { id: INCOGNITO_STORE, tabIds: [5, INCOGNITO_TAB, 9] },
    ]);
    await expect(resolveCookieStoreId(INCOGNITO_TAB, { getAllCookieStores: stores })).resolves.toBe(
      INCOGNITO_STORE
    );
  });

  it('陰性: どの保存先にも無いタブ ID は undefined', async () => {
    await expect(
      resolveCookieStoreId(999, { getAllCookieStores: createFakeStores() })
    ).resolves.toBeUndefined();
  });

  it('陰性: タブ ID が無い・API が無い・例外になるときは undefined（調査を止めない）', async () => {
    await expect(
      resolveCookieStoreId(undefined, { getAllCookieStores: createFakeStores() })
    ).resolves.toBeUndefined();
    await expect(resolveCookieStoreId(INCOGNITO_TAB, {})).resolves.toBeUndefined();
    await expect(
      resolveCookieStoreId(INCOGNITO_TAB, {
        getAllCookieStores: vi.fn(async () => {
          throw new Error('cookie stores unavailable');
        }),
      })
    ).resolves.toBeUndefined();
  });

  it('既定では chrome.cookies.getAllCookieStores を使う（第 2 引数を省略）', async () => {
    const getAllCookieStores = createFakeStores();
    installFakeChrome({ getAll: createFakeGetAll(), getAllCookieStores });
    await expect(resolveCookieStoreId(INCOGNITO_TAB)).resolves.toBe(INCOGNITO_STORE);
    expect(getAllCookieStores).toHaveBeenCalled();
  });
});

describe('v1.8.2 T03 (D-3): getInspectedCookies が調べるタブの保存先から読む', () => {
  it('陽性・陰性: シークレットのタブ（保存先 "1"）では保存先 "1" の Cookie だけが入り、保存先 "0" にしか無い Cookie は入らない', async () => {
    const getAll = createFakeGetAll();
    installFakeChrome({ getAll, getAllCookieStores: createFakeStores() });

    const cookies = await getInspectedCookies(PAGE_URL, INCOGNITO_TAB);

    expect(names(cookies)).toContain('incognito_probe');
    expect(names(cookies)).toContain('incognito_chips');
    expect(names(cookies)).not.toContain('normal_only');
    expect(names(cookies)).not.toContain('normal_chips');
  });

  it('分割 Cookie（partitionKey 付き）の getAll にも同じ storeId が渡る', async () => {
    const getAll = createFakeGetAll();
    installFakeChrome({ getAll, getAllCookieStores: createFakeStores() });

    await getInspectedCookies(PAGE_URL, INCOGNITO_TAB);

    expect(getAll.mock.calls.length).toBeGreaterThanOrEqual(2);
    const calls = getAll.mock.calls.map(([details]) => details);
    // すべての呼び出しに保存先 "1" が渡る
    for (const details of calls) {
      expect(details.storeId).toBe(INCOGNITO_STORE);
      expect(details.url).toBe(PAGE_URL);
    }
    // 通常の取得と、partitionKey 付きの取得の両方がある
    expect(calls.some((d) => !d.partitionKey)).toBe(true);
    const partitioned = calls.find((d) => d.partitionKey);
    expect(partitioned?.partitionKey).toEqual({ topLevelSite: 'https://example.test' });
    expect(partitioned?.storeId).toBe(INCOGNITO_STORE);
  });

  it('陽性・陰性: 通常のタブ（保存先 "0"）では保存先 "0" の Cookie だけが入る', async () => {
    const getAll = createFakeGetAll();
    installFakeChrome({ getAll, getAllCookieStores: createFakeStores() });

    const cookies = await getInspectedCookies(PAGE_URL, NORMAL_TAB);

    expect(names(cookies)).toContain('normal_only');
    expect(names(cookies)).not.toContain('incognito_probe');
    for (const [details] of getAll.mock.calls) {
      expect(details.storeId).toBe(NORMAL_STORE);
    }
  });

  it('保存先が見つからない（タブがどこにも無い）ときは storeId を指定しない（従来どおり）', async () => {
    const getAll = createFakeGetAll();
    installFakeChrome({ getAll, getAllCookieStores: createFakeStores() });

    const cookies = await getInspectedCookies(PAGE_URL, 999);

    expect(getAll).toHaveBeenCalled();
    for (const [details] of getAll.mock.calls) {
      expect('storeId' in details).toBe(false);
    }
    expect(names(cookies)).toContain('normal_only');
  });

  it('getAllCookieStores が無い・例外のときも storeId を指定せずに従来どおり取得する', async () => {
    for (const getAllCookieStores of [
      undefined,
      vi.fn(async () => {
        throw new Error('unavailable');
      }),
    ]) {
      const getAll = createFakeGetAll();
      installFakeChrome(getAllCookieStores ? { getAll, getAllCookieStores } : { getAll });

      const cookies = await getInspectedCookies(PAGE_URL, INCOGNITO_TAB);

      expect(getAll).toHaveBeenCalled();
      for (const [details] of getAll.mock.calls) {
        expect('storeId' in details).toBe(false);
      }
      expect(names(cookies)).toContain('normal_only');
    }
  });

  it('タブ ID を渡さない呼び出し（従来の形）は storeId を指定しない', async () => {
    const getAll = createFakeGetAll();
    const getAllCookieStores = createFakeStores();
    installFakeChrome({ getAll, getAllCookieStores });

    await getInspectedCookies(PAGE_URL);

    for (const [details] of getAll.mock.calls) {
      expect('storeId' in details).toBe(false);
    }
  });
});

describe('v1.8.2 T03 (D-3): executeInspection が調べるタブの ID を Cookie の取得に渡す', () => {
  const dom: DomSignals = {
    url: PAGE_URL,
    title: 'Cookie store fixture',
    metaTags: [],
    scriptUrls: [],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: [],
    cookiesFromDocument: [],
    cssAssets: [],
  };

  const baseDeps = (tabId: number, getCookies: InspectionDependencies['getInspectedCookies']): InspectionDependencies => ({
    tab: { id: tabId, url: PAGE_URL },
    fetchDomSignals: async () => dom,
    fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: async () => ({ url: PAGE_URL, headers: {}, observed: true }),
    getInspectedCookies: getCookies,
    getAllFindingExceptions: async () => [],
    saveReport: async () => {},
    hasWebRequestPermission: true,
  });

  it('getInspectedCookies に (URL, タブ ID) を渡す', async () => {
    const getCookies = vi.fn(async () => [] as InspectedCookieInfo[]);
    await executeInspection(baseDeps(INCOGNITO_TAB, getCookies));
    expect(getCookies).toHaveBeenCalledWith(PAGE_URL, INCOGNITO_TAB);
  });

  it('シークレットのタブの調査結果（report.cookies）に保存先 "1" の Cookie が入り、保存先 "0" だけの Cookie は入らない', async () => {
    installFakeChrome({ getAll: createFakeGetAll(), getAllCookieStores: createFakeStores() });

    const incognitoReport = await executeInspection(
      baseDeps(INCOGNITO_TAB, (url, tabId) => getInspectedCookies(url, tabId))
    );
    const incognitoNames = incognitoReport.cookies.map((c) => c.name);
    expect(incognitoNames).toContain('incognito_probe');
    expect(incognitoNames).not.toContain('normal_only');

    const normalReport = await executeInspection(
      baseDeps(NORMAL_TAB, (url, tabId) => getInspectedCookies(url, tabId))
    );
    const normalNames = normalReport.cookies.map((c) => c.name);
    expect(normalNames).toContain('normal_only');
    expect(normalNames).not.toContain('incognito_probe');
  });
});
