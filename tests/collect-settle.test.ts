/**
 * 一括取得の待ち方（SPA）の単体テスト（v1.8.0 T05）
 *
 * scripts/collect-reports.mjs の「URL が一定時間変わらない」かつ「DOM の変化が一定時間止まっている」
 * まで待つ判定を、ブラウザなしで確かめる。
 * - judgeSettle: 観測の列（時刻・URL・DOM の変化の累計）から、待ち中 / 落ち着いた / 打ち切りを判定する純粋関数
 * - waitForSettle: 観測の関数・時計・待ちの関数を差し替えられる待ちのループ
 * - parseArgs: --settle-ms（既定 1500）と待ちの上限
 * - buildSummary: 上限に達したサイトを _summary.md に「待ち打ち切り」として記録する
 * - test-server: 遅れて #/ に移り、さらに遅れて技術の印を描画するページ（/spa-settle）がある
 */

import path from 'node:path';
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  buildSummary as rawBuildSummary,
  judgeSettle as rawJudgeSettle,
  parseArgs as rawParseArgs,
  waitForSettle as rawWaitForSettle,
  // @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
} from '../scripts/collect-reports.mjs';

type SettleStatus = 'waiting' | 'settled' | 'timeout';

interface SettleSample {
  at: number;
  url: string;
  domMutations: number;
}

interface SettleOptions {
  settleMs: number;
  maxWaitMs: number;
}

interface ProbeResult {
  url: string;
  domMutations: number;
}

interface WaitForSettleOptions extends SettleOptions {
  intervalMs?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

interface WaitForSettleResult {
  status: 'settled' | 'timeout';
  waitedMs: number;
}

interface CollectOptions {
  settleMs: number;
  settleMaxMs: number;
  waitMs: number;
  timeoutMs: number;
  urls: string[];
}

const judgeSettle = rawJudgeSettle as (samples: SettleSample[], opts: SettleOptions) => { status: SettleStatus };
const waitForSettle = rawWaitForSettle as (
  probe: () => Promise<ProbeResult>,
  opts: WaitForSettleOptions
) => Promise<WaitForSettleResult>;
const parseArgs = rawParseArgs as (argv: string[]) => CollectOptions;
const buildSummary = rawBuildSummary as (results: unknown[], meta?: Record<string, unknown>) => string;

const OPTS: SettleOptions = { settleMs: 1500, maxWaitMs: 15000 };
const BASE = 'http://spa.example.test/spa-settle';

/** 偽の時計。sleep で時刻を進める */
function createFakeClock() {
  let t = 0;
  return {
    now: () => t,
    sleep: async (ms: number) => {
      t += ms;
    },
  };
}

describe('T05 judgeSettle: 待ち方の判定（ブラウザなし）', () => {
  it('観測が無いときは待ち中', () => {
    expect(judgeSettle([], OPTS).status).toBe('waiting');
  });

  it('URL も DOM も変わらず settleMs 経てば落ち着いた（境界の settleMs ちょうどを含む）', () => {
    const samples: SettleSample[] = [
      { at: 0, url: BASE, domMutations: 0 },
      { at: 1500, url: BASE, domMutations: 0 },
    ];
    expect(judgeSettle(samples, OPTS).status).toBe('settled');
  });

  it('変化が無くても settleMs 経つ前は待ち中', () => {
    const samples: SettleSample[] = [
      { at: 0, url: BASE, domMutations: 0 },
      { at: 1000, url: BASE, domMutations: 0 },
    ];
    expect(judgeSettle(samples, OPTS).status).toBe('waiting');
  });

  it('URL が変わったら（# 以降だけの変化でも）、そこから settleMs 経つまで待ち中', () => {
    const samples: SettleSample[] = [
      { at: 0, url: BASE, domMutations: 0 },
      { at: 1000, url: `${BASE}#/`, domMutations: 0 },
      { at: 2000, url: `${BASE}#/`, domMutations: 0 },
    ];
    expect(judgeSettle(samples, OPTS).status).toBe('waiting');
    expect(judgeSettle([...samples, { at: 2500, url: `${BASE}#/`, domMutations: 0 }], OPTS).status).toBe('settled');
  });

  it('DOM が変化したら（URL は同じでも）、そこから settleMs 経つまで待ち中', () => {
    const samples: SettleSample[] = [
      { at: 0, url: BASE, domMutations: 0 },
      { at: 1000, url: BASE, domMutations: 7 },
      { at: 2000, url: BASE, domMutations: 7 },
    ];
    expect(judgeSettle(samples, OPTS).status).toBe('waiting');
    expect(judgeSettle([...samples, { at: 2500, url: BASE, domMutations: 7 }], OPTS).status).toBe('settled');
  });

  it('URL が止まっていても DOM が変わり続けていれば落ち着いたとしない（両方が必要）', () => {
    const samples: SettleSample[] = [];
    for (let at = 0; at <= 5000; at += 500) samples.push({ at, url: BASE, domMutations: at });
    expect(judgeSettle(samples, OPTS).status).toBe('waiting');
  });

  it('DOM が止まっていても URL が直前に変わっていれば落ち着いたとしない（両方が必要）', () => {
    const samples: SettleSample[] = [
      { at: 0, url: BASE, domMutations: 3 },
      { at: 3000, url: BASE, domMutations: 3 },
      { at: 4000, url: `${BASE}#/`, domMutations: 3 },
      { at: 5000, url: `${BASE}#/`, domMutations: 3 },
    ];
    expect(judgeSettle(samples, OPTS).status).toBe('waiting');
  });

  it('変わり続けて maxWaitMs に達したら打ち切り', () => {
    const samples: SettleSample[] = [];
    for (let at = 0; at <= 15000; at += 500) samples.push({ at, url: BASE, domMutations: at });
    expect(judgeSettle(samples, OPTS).status).toBe('timeout');
  });

  it('変わり続けていても maxWaitMs に達する前は打ち切りにしない', () => {
    const samples: SettleSample[] = [];
    for (let at = 0; at <= 14000; at += 500) samples.push({ at, url: BASE, domMutations: at });
    expect(judgeSettle(samples, OPTS).status).toBe('waiting');
  });

  it('上限の時刻に落ち着いた条件も満たしていれば、打ち切りではなく落ち着いた', () => {
    const samples: SettleSample[] = [
      { at: 0, url: BASE, domMutations: 0 },
      { at: 13500, url: BASE, domMutations: 9 },
      { at: 15000, url: BASE, domMutations: 9 },
    ];
    expect(judgeSettle(samples, OPTS).status).toBe('settled');
  });

  it('上限は観測の最初の時刻から数える', () => {
    const samples: SettleSample[] = [];
    for (let at = 100000; at <= 110000; at += 500) samples.push({ at, url: BASE, domMutations: at });
    expect(judgeSettle(samples, OPTS).status).toBe('waiting');
  });
});

describe('T05 waitForSettle: 待ちのループ（偽の時計）', () => {
  it('SPA: 300ms 後に #/ に移り、900ms 後に技術の印を描画するページでは、描画のあと settleMs 待ってから終わる', async () => {
    const clock = createFakeClock();
    const probe = async (): Promise<ProbeResult> => {
      const t = clock.now();
      return {
        url: t >= 300 ? `${BASE}#/` : BASE,
        domMutations: t >= 900 ? 12 : t >= 300 ? 5 : 0,
      };
    };
    const result = await waitForSettle(probe, { ...OPTS, intervalMs: 100, now: clock.now, sleep: clock.sleep });
    expect(result.status).toBe('settled');
    expect(result.waitedMs).toBeGreaterThanOrEqual(900 + 1500);
    expect(result.waitedMs).toBeLessThanOrEqual(900 + 1500 + 200);
  });

  it('同じ経過のページを 3 回待つと、3 回とも同じ結果になる', async () => {
    const results: WaitForSettleResult[] = [];
    for (let i = 0; i < 3; i++) {
      const clock = createFakeClock();
      const probe = async (): Promise<ProbeResult> => {
        const t = clock.now();
        return { url: t >= 300 ? `${BASE}#/` : BASE, domMutations: t >= 900 ? 12 : t >= 300 ? 5 : 0 };
      };
      results.push(await waitForSettle(probe, { ...OPTS, intervalMs: 100, now: clock.now, sleep: clock.sleep }));
    }
    expect(results[1]).toEqual(results[0]);
    expect(results[2]).toEqual(results[0]);
  });

  it('変化の無いページは settleMs ほどで終わる（上限まで待たない）', async () => {
    const clock = createFakeClock();
    const probe = async (): Promise<ProbeResult> => ({ url: BASE, domMutations: 0 });
    const result = await waitForSettle(probe, { ...OPTS, intervalMs: 100, now: clock.now, sleep: clock.sleep });
    expect(result.status).toBe('settled');
    expect(result.waitedMs).toBeGreaterThanOrEqual(1500);
    expect(result.waitedMs).toBeLessThanOrEqual(1500 + 200);
  });

  it('DOM が変わり続けるページは上限で打ち切り、上限を大きく超えて待たない', async () => {
    const clock = createFakeClock();
    let n = 0;
    const probe = async (): Promise<ProbeResult> => ({ url: BASE, domMutations: ++n });
    const result = await waitForSettle(probe, { ...OPTS, intervalMs: 100, now: clock.now, sleep: clock.sleep });
    expect(result.status).toBe('timeout');
    expect(result.waitedMs).toBeGreaterThanOrEqual(15000);
    expect(result.waitedMs).toBeLessThanOrEqual(15000 + 200);
  });

  it('URL が変わり続けるページも上限で打ち切る', async () => {
    const clock = createFakeClock();
    let n = 0;
    const probe = async (): Promise<ProbeResult> => ({ url: `${BASE}#/item/${++n}`, domMutations: 0 });
    const result = await waitForSettle(probe, { ...OPTS, intervalMs: 100, now: clock.now, sleep: clock.sleep });
    expect(result.status).toBe('timeout');
  });

  it('観測が例外を投げても（遷移中など）失敗にせず、変化として扱って待ち続ける', async () => {
    const clock = createFakeClock();
    const probe = async (): Promise<ProbeResult> => {
      const t = clock.now();
      if (t >= 500 && t < 1000) throw new Error('Execution context was destroyed');
      return { url: BASE, domMutations: 0 };
    };
    const result = await waitForSettle(probe, { ...OPTS, intervalMs: 100, now: clock.now, sleep: clock.sleep });
    expect(result.status).toBe('settled');
    // 例外の最後（1000ms 直前）から settleMs 以上待っている
    expect(result.waitedMs).toBeGreaterThanOrEqual(900 + 1500);
  });
});

describe('T05 parseArgs: --settle-ms と待ちの上限', () => {
  it('--settle-ms の既定は 1500', () => {
    expect(parseArgs([]).settleMs).toBe(1500);
  });

  it('--settle-ms で値を指定できる。他の引数と URL の解釈は変わらない', () => {
    const opts = parseArgs(['--settle-ms', '3000', '--wait', '500', 'https://spa.example.test/']);
    expect(opts.settleMs).toBe(3000);
    expect(opts.waitMs).toBe(500);
    expect(opts.urls).toEqual(['https://spa.example.test/']);
  });

  it('待ちの上限（settleMaxMs）があり、既定の settleMs より大きい有限の値', () => {
    const opts = parseArgs([]);
    expect(Number.isFinite(opts.settleMaxMs)).toBe(true);
    expect(opts.settleMaxMs).toBeGreaterThan(opts.settleMs);
  });

  it('--settle-ms に負の数・数値でない値・値なしを指定するとエラー', () => {
    expect(() => parseArgs(['--settle-ms', '-1'])).toThrow();
    expect(() => parseArgs(['--settle-ms', 'abc'])).toThrow();
    expect(() => parseArgs(['--settle-ms'])).toThrow();
  });
});

describe('T05 buildSummary: 上限に達したサイトを「待ち打ち切り」として記録する', () => {
  const okBase = {
    ok: true,
    attention: 0,
    techCount: 1,
    notes: [],
    lint: { ok: true, violations: [] },
  };
  const results = [
    {
      ...okBase,
      url: 'https://timeout.example.test/',
      finalUrl: 'https://timeout.example.test/#/',
      file: 'web-inspector-report-timeout.example.test.md',
      settle: { status: 'timeout', waitedMs: 15000 },
    },
    {
      ...okBase,
      url: 'https://settled.example.test/',
      finalUrl: 'https://settled.example.test/#/',
      file: 'web-inspector-report-settled.example.test.md',
      settle: { status: 'settled', waitedMs: 2400 },
    },
    {
      // settle の無い結果（従来の形）
      ...okBase,
      url: 'https://legacy.example.test/',
      finalUrl: 'https://legacy.example.test/',
      file: 'web-inspector-report-legacy.example.test.md',
    },
  ];
  const rowOf = (md: string, url: string): string => {
    const row = md.split('\n').find((l) => l.startsWith(`| ${url} |`));
    expect(row, `${url} の行がありません`).toBeTruthy();
    return row as string;
  };

  it('上限に達したサイトの行に「待ち打ち切り」が出る', () => {
    const md = buildSummary(results, { startedAt: '-', extensionVersion: '-', pendingChecks: [] });
    expect(rowOf(md, 'https://timeout.example.test/')).toContain('待ち打ち切り');
  });

  it('落ち着いたサイトと、settle の無い結果の行には出ない', () => {
    const md = buildSummary(results, { startedAt: '-', extensionVersion: '-', pendingChecks: [] });
    expect(rowOf(md, 'https://settled.example.test/')).not.toContain('待ち打ち切り');
    expect(rowOf(md, 'https://legacy.example.test/')).not.toContain('待ち打ち切り');
  });
});

describe('T05 test-server: SPA の待ち方を確かめるページ', () => {
  it('test-server に /spa-settle のページがある', () => {
    const src = fs.readFileSync(path.resolve(__dirname, '..', 'test-server', 'server.mjs'), 'utf8');
    expect(/['"`]\/spa-settle['"`]/.test(src), 'test-server/server.mjs に /spa-settle がありません').toBe(true);
  });
});
