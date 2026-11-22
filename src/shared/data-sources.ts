/**
 * Web Technology & Security Inspector
 * 同梱データの出典とライセンスの共通定義 (src/shared/data-sources.ts) - v1.8.2 T07 (H9, H11, H12, §5.2, §5.4)
 */

export type BundledDataSourceId = 'nvd' | 'ghsa' | 'ubuntu' | 'debian' | 'endoflife' | 'kev' | 'psl';

/**
 * 同梱データソース情報
 */
export interface BundledDataSource {
  id: BundledDataSourceId;
  /** 出典の名前（DB の sources の name と同じ） */
  name: string;
  /** 出典の URL（https。DB の sources の url と同じ） */
  url: string;
  /** SPDX の ID。ライセンスが無い・明記なしは null */
  license: string | null;
  /** 画面と文書に出すライセンスの表記 */
  licenseLabel: string;
  /** ライセンス（NVD は利用規約）の URL。無ければ null */
  licenseUrl: string | null;
  /** 同梱しているもの */
  contents: string;
  /** 加工の有無 */
  modification: string;
}

/**
 * NVD API利用規定に基づく表示文（指示書 §5.2、NVD Terms of Use）
 */
export const NVD_NOTICE = 'This product uses the NVD API but is not endorsed or certified by the NVD.';

/**
 * NVD利用規約の公式URL
 */
export const NVD_TERMS_URL = 'https://nvd.nist.gov/developers/terms-of-use';

/**
 * ダッシュボードのデータ出典ビューのHTML要素ID
 */
export const DATA_SOURCES_VIEW_ID = 'dataSourcesView';

/**
 * 同梱データソースの一覧（7種類）
 */
export const BUNDLED_DATA_SOURCES: readonly BundledDataSource[] = [
  {
    id: 'nvd',
    name: 'NIST National Vulnerability Database (NVD)',
    url: 'https://nvd.nist.gov/',
    license: null,
    licenseLabel: '公有（米国政府の著作物）。NVD API の利用規約に従います',
    licenseUrl: 'https://nvd.nist.gov/developers/terms-of-use',
    contents: 'CVE の CVSS スコア・ベクトル・参照 URL',
    modification: '必要な項目だけを抜き出して加工しています。加工した内容は NVD が提供したものではなく、NVD による承認・認定も受けていません',
  },
  {
    id: 'ghsa',
    name: 'GitHub Advisory Database (OSV.dev 経由: npm / Packagist)',
    url: 'https://github.com/github/advisory-database',
    license: 'CC-BY-4.0',
    licenseLabel: 'CC BY 4.0',
    licenseUrl: 'https://creativecommons.org/licenses/by/4.0/',
    contents: 'GHSA の ID・影響範囲・タイトル',
    modification: 'OSV.dev 経由で取得し、影響範囲・重大度・タイトルを抜き出して加工しています',
  },
  {
    id: 'ubuntu',
    name: 'OSV.dev (Ubuntu Security Notices)',
    url: 'https://github.com/canonical/ubuntu-security-notices',
    license: 'CC-BY-SA-4.0',
    licenseLabel: 'CC BY-SA 4.0（Ubuntu の部分）',
    licenseUrl: 'https://creativecommons.org/licenses/by-sa/4.0/',
    contents: 'CVE ごとの状態・修正版・USN の ID',
    modification: 'OSV.dev 経由で取得し、状態・修正版を抜き出して加工しています。加工した Ubuntu の部分も CC BY-SA 4.0 です',
  },
  {
    id: 'debian',
    name: 'OSV.dev (Debian Security Tracker)',
    url: 'https://osv.dev/list?ecosystem=Debian',
    license: null,
    licenseLabel: 'ライセンスの明記なし（出典のみ表示）',
    licenseUrl: null,
    contents: 'CVE ごとの状態・修正版',
    modification: 'OSV.dev 経由で取得し、状態・修正版を抜き出して加工しています',
  },
  {
    id: 'endoflife',
    name: 'endoflife.date',
    url: 'https://endoflife.date/',
    license: 'MIT',
    licenseLabel: 'MIT License',
    licenseUrl: 'https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE',
    contents: '製品のサポート期間（サイクルごとのサポート終了日）',
    modification: 'サポート期間だけを抜き出して加工しています（製品の説明文は使っていません）',
  },
  {
    id: 'kev',
    name: 'CISA Known Exploited Vulnerabilities Catalog',
    url: 'https://github.com/cisagov/kev-data',
    license: 'CC0-1.0',
    licenseLabel: 'CC0 1.0',
    licenseUrl: 'https://creativecommons.org/publicdomain/zero/1.0/',
    contents: '悪用が確認された CVE の一覧',
    modification: 'CVE の ID だけを使い、該当する脆弱性に印を付けています',
  },
  {
    id: 'psl',
    name: 'Public Suffix List',
    url: 'https://publicsuffix.org/',
    license: 'MPL-2.0',
    licenseLabel: 'MPL 2.0',
    licenseUrl: 'https://mozilla.org/MPL/2.0/',
    contents: 'ドメインの区切りの規則（src/security/psl-rules.generated.ts）',
    modification: '規則を TypeScript の形に変換しています（生成ファイルの先頭に MPL 2.0 の表示を残しています）',
  },
] as const;
