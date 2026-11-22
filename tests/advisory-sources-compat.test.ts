/**
 * v1.8.2 T06: 古いスキーマ（sources が文字列の配列）と新しいスキーマ（2.4、sources がオブジェクトの配列）の DB を、
 * 拡張機能の側が壊れずに読めること（指示書 §5.3「古いスキーマ（文字列の配列）を読む側が壊れないこと」、K3）
 *
 * - normalizeAdvisoryDbSources(raw) … DB の sources（文字列・オブジェクト・混在・不正）を AdvisoryDbSourceRecord の配列にそろえる
 *   （名前・型は設計メモ docs/dev/v1.8.2/design/T06.md の「実装の方針」）
 * - 照合（matchOfflineAdvisories）は sources の形に依存しない
 * - 固定 DB（tests/fixtures/advisory-db.fixture.json。schema 2.3・文字列の配列）を使う。同梱 DB は読まない
 * - DB の版・件数・日付は直接書かない
 */
import { describe, expect, it } from 'vitest';
import * as advisoryModule from '../src/detection/advisory';
import { AdvisoryDatabase, matchOfflineAdvisories } from '../src/detection/advisory';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

/** 設計メモ「実装の方針」の AdvisoryDbSourceRecord（テストではローカルに型を置く） */
interface SourceRecord {
  name: string;
  url: string | null;
  ecosystem: string | null;
  license: string | null;
  licenseNote?: string;
  retrievedAt: string | null;
  recordCount: number | null;
}
type Normalize = (raw: unknown) => SourceRecord[];

function getNormalize(): Normalize {
  const fn = (advisoryModule as unknown as { normalizeAdvisoryDbSources?: unknown }).normalizeAdvisoryDbSources;
  expect(typeof fn, 'src/detection/advisory.ts が normalizeAdvisoryDbSources を export していません').toBe('function');
  return fn as Normalize;
}

const fixture = rawFixtureDb as unknown as AdvisoryDatabase & { sources: unknown[] };

const STRUCTURED = [
  { name: 'Synthetic NVD', url: 'https://nvd.nist.gov/', ecosystem: null, license: null, licenseNote: '合成の注記', retrievedAt: '2090-01-01T00:00:00.000Z', recordCount: 3 },
  { name: 'Synthetic Ubuntu', url: 'https://github.com/canonical/ubuntu-security-notices', ecosystem: 'Ubuntu', license: 'CC-BY-SA-4.0', retrievedAt: null, recordCount: 0 },
];

describe('T06: normalizeAdvisoryDbSources（古いスキーマとの互換）', () => {
  it('固定 DB は古いスキーマ（sources が文字列の配列）であること（このテストの前提）', () => {
    expect(Array.isArray(fixture.sources) && fixture.sources.length > 0).toBe(true);
    expect(fixture.sources.every((s) => typeof s === 'string')).toBe(true);
  });

  it('文字列の配列（schema 2.3 以前）は、名前だけの出典にそろえ、ライセンス・件数・日時を作らないこと（0 や推測の値にしない）', () => {
    const normalize = getNormalize();
    const out = normalize(fixture.sources);
    expect(out.map((s) => s.name)).toEqual(fixture.sources);
    for (const s of out) {
      expect(s.url).toBeNull();
      expect(s.ecosystem).toBeNull();
      expect(s.license).toBeNull();
      expect(s.licenseNote).toBeUndefined();
      expect(s.retrievedAt).toBeNull();
      expect(s.recordCount).toBeNull();
    }
  });

  it('オブジェクトの配列（schema 2.4）は、値をそのまま保つこと', () => {
    const normalize = getNormalize();
    const out = normalize(structuredClone(STRUCTURED));
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({ name: 'Synthetic NVD', url: 'https://nvd.nist.gov/', ecosystem: null, license: null, licenseNote: '合成の注記', retrievedAt: '2090-01-01T00:00:00.000Z', recordCount: 3 });
    expect(out[1]).toMatchObject({ name: 'Synthetic Ubuntu', ecosystem: 'Ubuntu', license: 'CC-BY-SA-4.0', retrievedAt: null, recordCount: 0 });
    expect(out[1].licenseNote).toBeUndefined();
  });

  it('文字列とオブジェクトが混ざっていても、順番どおりに両方を読むこと（複数の形が混在する場合）', () => {
    const normalize = getNormalize();
    const out = normalize(['Legacy Source', STRUCTURED[1], 'Another Legacy']);
    expect(out.map((s) => s.name)).toEqual(['Legacy Source', 'Synthetic Ubuntu', 'Another Legacy']);
    expect(out[1].license).toBe('CC-BY-SA-4.0');
    expect(out[0].license).toBeNull();
  });

  it('陰性: 配列でない・空の値・名前の無い要素・型の違う要素は捨て、例外を投げないこと', () => {
    const normalize = getNormalize();
    for (const raw of [undefined, null, 'NVD', 42, {}, { name: 'x' }]) {
      expect(() => normalize(raw)).not.toThrow();
      expect(normalize(raw)).toEqual([]);
    }
    const out = normalize(['', '   ', null, 7, { url: 'https://example.test/' }, { name: '' }, { name: 'Kept' }]);
    expect(out.map((s) => s.name)).toEqual(['Kept']);
  });

  it('陰性: https でない url・負の件数・日時でない retrievedAt・空の licenseNote は、値を作らずに null（licenseNote は無し）にすること', () => {
    const normalize = getNormalize();
    const [s] = normalize([
      { name: 'Odd', url: 'javascript:alert(1)', ecosystem: 5, license: 3, licenseNote: '', retrievedAt: 'not-a-date', recordCount: -2 },
    ]);
    expect(s.name).toBe('Odd');
    expect(s.url).toBeNull();
    expect(s.ecosystem).toBeNull();
    expect(s.license).toBeNull();
    expect(s.licenseNote).toBeUndefined();
    expect(s.retrievedAt).toBeNull();
    expect(s.recordCount).toBeNull();
    const [h] = normalize([{ name: 'Plain http', url: 'http://example.test/' }]);
    expect(h.url).toBeNull();
  });
});

describe('T06: 照合は sources の形に依存しない', () => {
  /** 固定 DB の sources だけをオブジェクトの配列（schema 2.4 の形）に替えた DB */
  function structuredDb(): AdvisoryDatabase {
    const db = structuredClone(fixture) as unknown as Record<string, unknown>;
    db.schemaVersion = '2.4';
    db.sources = structuredClone(STRUCTURED);
    return db as unknown as AdvisoryDatabase;
  }

  it.each([
    ['jQuery', '1.12.4'],
    ['jQuery', '3.7.1'],
    ['nginx', 'nginx/1.18.0 (Ubuntu)'],
    ['PHP', '7.4.3-4ubuntu2.19'],
    ['Apache', '2.4.49'],
    ['React', null],
  ])('%s %s: 古いスキーマの固定 DB と同じ照合結果になること', (tech, version) => {
    const legacy = matchOfflineAdvisories(tech, version, structuredClone(fixture) as unknown as AdvisoryDatabase);
    const modern = matchOfflineAdvisories(tech, version, structuredDb());
    const pick = (r: ReturnType<typeof matchOfflineAdvisories>) => ({
      matchStatus: r.matchStatus,
      offlineMatchStatus: r.offlineMatchStatus,
      ids: r.advisories.map((a) => a.id).sort(),
      maxCvss: r.maxCvss,
      eolStatus: r.eolInfo?.status,
      productAdvisoryCount: r.productAdvisoryCount,
      productSources: r.productSources,
      upstreamAdvisoriesCount: r.upstreamAdvisoriesCount,
    });
    expect(pick(modern)).toEqual(pick(legacy));
  });
});
