/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOLスナップショット同期スクリプト (scripts/sync-advisories.mjs)
 * 
 * ビルド時に実行され、主要ライブラリ・ソフトウェアのEOL・既知脆弱性カタログを
 * ミニファイされたスナップショットJSON (src/detection/advisory-db.json) として生成します。
 * 
 * 【重要ポリシー (DB-01 / docs/MAINTENANCE_GUIDE.md 準拠)】
 * - 重大度 (severity) は手書きせず、CVSSスコア (cvssScore) から機械的に導出します。
 * - 全エントリに advisoryUrl, verifiedAt, scoreSource, cvssScore を必須とします。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const OUTPUT_FILE = path.join(ROOT_DIR, 'src', 'detection', 'advisory-db.json');

/**
 * CVSS v3.1 ベーススコアから重大度を機械的に導出する
 * @param {number} score 
 * @returns {'critical' | 'high' | 'medium' | 'low'}
 */
export function deriveSeverity(score) {
  if (typeof score !== 'number' || isNaN(score) || score < 0 || score > 10) {
    throw new Error(`無効なCVSSスコアです: ${score}`);
  }
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

const VERIFIED_DATE = '2026-10-25';
const DEFAULT_SOURCE = 'nvd@nist.gov (Primary)';

// 主要ライブラリ・サーバー・言語のベース脆弱性カタログ (ビルド時スナップショット)
const BASE_LIBRARIES = {
  jquery: {
    aliases: ['jquery'],
    versions: [
      {
        range: '< 3.5.0',
        cve: 'CVE-2020-11022',
        cvssScore: 6.1,
        title: 'Regex in jQuery.htmlPrefilter can result in XSS',
        fixedVersion: '3.5.0',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      },
      {
        range: '< 3.5.0',
        cve: 'CVE-2020-11023',
        cvssScore: 6.1,
        title: 'XSS in jQuery.htmlPrefilter even with sanitizers',
        fixedVersion: '3.5.0',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11023',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE,
        notes: 'CISA KEV 登録 (2025-01-23)'
      },
      {
        range: '< 3.4.0',
        cve: 'CVE-2019-11358',
        cvssScore: 6.1,
        title: 'jQuery prototype pollution via $.extend',
        fixedVersion: '3.4.0',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      },
      {
        range: '< 3.0.0',
        cve: 'CVE-2015-9251',
        cvssScore: 6.1,
        title: 'XSS via cross-domain ajax requests with dataType script',
        fixedVersion: '3.0.0',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2015-9251',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
    ],
    eol: [
      { cycle: '1.x', eolDate: '2016-06-09', status: 'EOL' },
      { cycle: '2.x', eolDate: '2016-06-09', status: 'EOL' },
      { cycle: '3.0 - 3.4', eolDate: '2020-05-04', status: 'EOL' },
      { cycle: '3.5+', eolDate: null, status: 'Supported' }
    ]
  },
  bootstrap: {
    aliases: ['bootstrap', 'twitter-bootstrap'],
    versions: [
      {
        range: '< 3.4.1 || >= 4.0.0, < 4.3.1',
        cve: 'CVE-2019-8331',
        cvssScore: 6.1,
        title: 'XSS in Bootstrap Tooltip and Popover data-template',
        fixedVersion: '3.4.1 / 4.3.1',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2019-8331',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      },
      {
        range: '< 4.1.2',
        cve: 'CVE-2018-14041',
        cvssScore: 6.1,
        title: 'XSS in Bootstrap Collapse plugin data-parent attribute',
        fixedVersion: '4.1.2',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2018-14041',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      },
      {
        range: '< 3.4.0',
        cve: 'CVE-2016-10735',
        cvssScore: 6.1,
        title: 'XSS in data-target attribute for Bootstrap 3',
        fixedVersion: '3.4.0',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2016-10735',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
    ],
    eol: [
      { cycle: '3.x', eolDate: '2019-07-24', status: 'EOL' },
      { cycle: '4.x', eolDate: '2023-01-01', status: 'EOL' },
      { cycle: '5.x', eolDate: null, status: 'Supported' }
    ]
  },
  react: {
    aliases: ['react', 'reactjs'],
    versions: [
      {
        range: '< 16.0.0',
        cve: 'CVE-2018-6341',
        cvssScore: 6.1,
        title: 'Potential XSS when generating attributes in React SSR',
        fixedVersion: '16.0.0',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2018-6341',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
    ],
    eol: [
      { cycle: '16.x', eolDate: '2020-10-20', status: 'EOL' },
      { cycle: '17.x', eolDate: '2022-03-29', status: 'EOL' },
      { cycle: '18.x', eolDate: null, status: 'Supported' },
      { cycle: '19.x', eolDate: null, status: 'Supported' }
    ]
  },
  vue: {
    aliases: ['vue', 'vue.js', 'vuejs'],
    versions: [
      {
        range: '< 2.6.10',
        cve: 'CVE-2020-13426',
        cvssScore: 6.5,
        title: 'ReDoS in vue-template-compiler',
        fixedVersion: '2.6.10',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-13426',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
    ],
    eol: [
      { cycle: '2.x', eolDate: '2023-12-31', status: 'EOL' },
      { cycle: '3.x', eolDate: null, status: 'Supported' }
    ]
  },
  angular: {
    aliases: ['angular', 'angular-core'],
    versions: [],
    eol: [
      { cycle: '2.x - 14.x', eolDate: '2023-11-01', status: 'EOL' },
      { cycle: '15.x', eolDate: '2024-05-01', status: 'EOL' },
      { cycle: '16.x', eolDate: '2024-11-01', status: 'EOL' },
      { cycle: '17.x', eolDate: '2025-05-01', status: 'Maintenance' },
      { cycle: '18.x+', eolDate: null, status: 'Supported' }
    ]
  },
  angularjs: {
    aliases: ['angularjs', 'angular.js'],
    versions: [
      {
        range: '< 1.8.0',
        cve: 'CVE-2020-7676',
        cvssScore: 5.4,
        title: 'Cross-site Scripting (XSS) in AngularJS via regex replacement in jQLite',
        summary: 'AngularJS jQLite improperly modifies HTML tags during regex replacement (such as tags in <select>/<option>), allowing sanitizer bypass and XSS.',
        fixedVersion: '1.8.0',
        advisoryUrl: 'https://github.com/advisories/GHSA-mhp6-pxh8-r675',
        verifiedAt: VERIFIED_DATE,
        scoreSource: 'GitHub Advisory Database (GHSA)'
      },
      {
        range: '<= 1.8.3',
        cve: 'CVE-2022-25869',
        cvssScore: 6.1,
        title: 'Cross-site Scripting (XSS) in AngularJS via page cache and textarea interpolation',
        summary: 'XSS in AngularJS due to improper page caching and <textarea> interpolation in Internet Explorer. All versions up to 1.8.3 are affected with no official patch due to EOL.',
        fixedVersion: null,
        advisoryUrl: 'https://github.com/advisories/GHSA-prc3-vjfx-vhm9',
        verifiedAt: VERIFIED_DATE,
        scoreSource: 'GitHub Advisory Database (GHSA)'
      }
    ],
    eol: [
      { cycle: '1.x', eolDate: '2022-01-01', status: 'EOL' }
    ]
  },
  lodash: {
    aliases: ['lodash'],
    versions: [
      {
        range: '< 4.17.21',
        cve: 'CVE-2021-23337',
        cvssScore: 7.2,
        title: 'Command Injection in lodash.template via variable option',
        summary: 'Command injection in lodash.template when passing unsanitized variable options into the template compiler.',
        fixedVersion: '4.17.21',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      },
      {
        range: '< 4.17.19',
        cve: 'CVE-2020-8203',
        cvssScore: 7.4,
        title: 'Prototype Pollution in lodash.zipObjectDeep',
        summary: 'Prototype pollution in lodash.zipObjectDeep via Object.prototype manipulation.',
        fixedVersion: '4.17.19',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
    ],
    eol: [
      { cycle: '3.x', eolDate: '2016-01-12', status: 'EOL' },
      { cycle: '4.x', eolDate: null, status: 'Supported' }
    ]
  },
  wordpress: {
    aliases: ['wordpress'],
    versions: [
      {
        range: '< 5.8.3',
        cve: 'CVE-2022-21661',
        cvssScore: 7.5,
        title: 'SQL Injection in WP_Query',
        summary: 'Improper input sanitization in WP_Query meta queries allows potential SQL injection via unsafe plugin/theme inputs.',
        fixedVersion: '5.8.3',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-21661',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
      // ※ CVE-2023-32243 は本体ではなくプラグイン (Essential Addons for Elementor) の脆弱性のため除外
    ],
    eol: [
      { cycle: '4.x', eolDate: '2022-12-01', status: 'EOL' },
      { cycle: '5.x', eolDate: '2024-01-01', status: 'EOL' },
      { cycle: '6.x', eolDate: null, status: 'Supported' }
    ]
  },
  php: {
    aliases: ['php'],
    versions: [
      {
        range: '>= 8.1.0, < 8.1.29 || >= 8.2.0, < 8.2.20 || >= 8.3.0, < 8.3.8',
        cve: 'CVE-2024-4577',
        cvssScore: 9.8,
        title: 'PHP CGI Argument Injection vulnerability leading to RCE',
        summary: '該当の可能性あり (条件: Windows OS上でPHP-CGIとして稼働している場合)。Best-fit mapping bypass allows arbitrary command-line arguments.',
        fixedVersion: '8.1.29 / 8.2.20 / 8.3.8',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE,
        notes: 'CISA KEV 登録 (2024-06-12)'
      },
      {
        range: '< 7.4.31 || >= 8.0.0, < 8.0.24 || >= 8.1.0, < 8.1.11',
        cve: 'CVE-2022-31628',
        cvssScore: 5.5,
        title: 'Infinite Loop in phar extension via gzip quine (DoS)',
        summary: 'Uncontrolled recursion in phar gzip uncompressor causes an infinite loop and DoS when handling quine archives.',
        fixedVersion: '7.4.31 / 8.0.24 / 8.1.11',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2022-31628',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
    ],
    eol: [
      { cycle: '5.6', eolDate: '2018-12-31', status: 'EOL' },
      { cycle: '7.0', eolDate: '2018-12-03', status: 'EOL' },
      { cycle: '7.1', eolDate: '2019-12-01', status: 'EOL' },
      { cycle: '7.2', eolDate: '2020-11-30', status: 'EOL' },
      { cycle: '7.3', eolDate: '2021-12-06', status: 'EOL' },
      { cycle: '7.4', eolDate: '2022-11-28', status: 'EOL' },
      { cycle: '8.0', eolDate: '2023-11-26', status: 'EOL' },
      { cycle: '8.1', eolDate: '2025-12-31', status: 'Maintenance' },
      { cycle: '8.2', eolDate: '2026-12-31', status: 'Supported' },
      { cycle: '8.3', eolDate: '2027-12-31', status: 'Supported' }
    ]
  },
  nginx: {
    aliases: ['nginx'],
    versions: [
      {
        range: '< 1.25.0',
        cve: 'CVE-2023-44487',
        cvssScore: 7.5,
        title: 'HTTP/2 Rapid Reset Denial of Service Vulnerability',
        summary: 'Stream reset abuse in HTTP/2 allows distributed denial-of-service (DDoS).',
        fixedVersion: '1.25.3',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE,
        notes: 'CISA KEV 登録 (2023-10-10)'
      },
      {
        range: '< 1.21.0',
        cve: 'CVE-2021-23017',
        cvssScore: 7.7,
        title: '1-byte memory overwrite in resolver',
        summary: '1-byte memory overwrite in DNS resolver when processing malformed responses.',
        fixedVersion: '1.21.0',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
    ],
    eol: [
      { cycle: '1.18', eolDate: '2021-04-13', status: 'EOL' },
      { cycle: '1.20', eolDate: '2022-05-24', status: 'EOL' },
      { cycle: '1.22', eolDate: '2023-05-23', status: 'EOL' },
      { cycle: '1.24', eolDate: '2024-04-16', status: 'EOL' },
      { cycle: '1.26', eolDate: null, status: 'Supported' }
    ]
  },
  apache: {
    aliases: ['apache', 'apache-httpd', 'httpd'],
    versions: [
      {
        range: '< 2.4.52',
        cve: 'CVE-2021-44790',
        cvssScore: 9.8,
        title: 'Buffer overflow in mod_lua multipart parser',
        summary: '該当の可能性あり (条件: mod_lua モジュールが有効化されている場合)。Heap buffer overflow in r:parsebody() in mod_lua.',
        fixedVersion: '2.4.52',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44790',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      },
      {
        range: '= 2.4.49',
        cve: 'CVE-2021-41773',
        cvssScore: 9.8,
        title: 'Path Traversal and File Disclosure in Apache HTTP Server 2.4.49',
        summary: 'Path normalization flaw allows unauthenticated remote attackers to map URLs to files outside the document root. CGI有効時にRCEに至る。',
        fixedVersion: '2.4.50',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE,
        notes: 'CISA-ADP評価: 7.5 (High, 単体ファイル開示)。CISA KEV 登録 (2021-11-03)'
      },
      {
        range: '= 2.4.50',
        cve: 'CVE-2021-42013',
        cvssScore: 9.8,
        title: 'Path Traversal and RCE in Apache HTTP Server 2.4.50',
        summary: 'Incomplete fix for CVE-2021-41773 allows path traversal and RCE when CGI scripts are mapped.',
        fixedVersion: '2.4.51',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE,
        notes: 'CISA KEV 登録 (2021-11-03)'
      }
    ],
    eol: [
      { cycle: '2.2', eolDate: '2017-12-31', status: 'EOL' },
      { cycle: '2.4', eolDate: null, status: 'Supported' }
    ]
  },
  laravel: {
    aliases: ['laravel', 'laravel-framework'],
    versions: [
      {
        range: '< 8.4.3',
        cve: 'CVE-2021-3129',
        cvssScore: 9.8,
        title: 'Ignition RCE vulnerability in Laravel',
        summary: 'Unauthenticated RCE in facade/ignition before 2.5.2 when debug mode is enabled.',
        fixedVersion: '8.4.3',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2021-3129',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE,
        notes: 'CISA KEV 登録 (2023-09-18)'
      },
      {
        range: '< 5.6.30',
        cve: 'CVE-2018-15133',
        cvssScore: 8.1,
        title: 'Deserialization of untrusted data in Laravel Application Key',
        summary: 'RCE via deserialization of untrusted data if APP_KEY is leaked.',
        fixedVersion: '5.6.30',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2018-15133',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE,
        notes: 'CISA KEV 登録 (2024-01-16)'
      }
    ],
    eol: [
      { cycle: '6.x', eolDate: '2022-09-06', status: 'EOL' },
      { cycle: '7.x', eolDate: '2021-03-03', status: 'EOL' },
      { cycle: '8.x', eolDate: '2023-01-24', status: 'EOL' },
      { cycle: '9.x', eolDate: '2024-02-06', status: 'EOL' },
      { cycle: '10.x', eolDate: '2025-02-04', status: 'Maintenance' },
      { cycle: '11.x', eolDate: '2026-03-12', status: 'Supported' }
    ]
  },
  nodejs: {
    aliases: ['node', 'nodejs', 'node.js'],
    versions: [
      {
        range: '>= 20.0.0, < 20.8.1',
        cve: 'CVE-2023-39332',
        cvssScore: 9.8,
        title: 'Path Traversal via Uint8Array in node:fs',
        summary: '該当の可能性あり (条件: --experimental-permission 有効時)。Path traversal in node:fs functions when passing non-Buffer Uint8Array objects.',
        fixedVersion: '20.8.1',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-39332',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      },
      {
        range: '>= 14.0.0, < 14.21.3 || >= 16.0.0, < 16.19.1 || >= 18.0.0, < 18.14.1 || >= 19.0.0, < 19.6.1',
        cve: 'CVE-2023-23918',
        cvssScore: 7.5,
        title: 'Permissions-Policy bypass via process.mainModule.require()',
        summary: '該当の可能性あり (条件: --experimental-policy 有効時)。Policy bypass allowing unauthorized module loading.',
        fixedVersion: '14.21.3 / 16.19.1 / 18.14.1 / 19.6.1',
        advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2023-23918',
        verifiedAt: VERIFIED_DATE,
        scoreSource: DEFAULT_SOURCE
      }
      // ※ CVE-2022-35255 は不正確な記述の排除のため削除
    ],
    eol: [
      { cycle: '14.x', eolDate: '2023-04-30', status: 'EOL' },
      { cycle: '16.x', eolDate: '2023-09-11', status: 'EOL' },
      { cycle: '18.x', eolDate: '2025-04-30', status: 'Maintenance' },
      { cycle: '20.x', eolDate: '2026-04-30', status: 'Supported' },
      { cycle: '22.x', eolDate: '2027-04-30', status: 'Supported' }
    ]
  }
};

/**
 * endoflife.date APIから最新のEOL情報を取得する（失敗時はローカルフォールバック）
 */
async function fetchEolData(product) {
  try {
    const url = `https://endoflife.date/api/${encodeURIComponent(product)}.json`;
    const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!res.ok) return null;
    const cycles = await res.json();
    return cycles.map(c => ({
      cycle: c.cycle,
      eolDate: typeof c.eol === 'string' ? c.eol : (c.eol === true ? 'EOL' : null),
      status: (c.eol === true || (typeof c.eol === 'string' && new Date(c.eol) <= new Date())) ? 'EOL' : 'Supported'
    }));
  } catch (err) {
    return null;
  }
}

async function syncAdvisories() {
  console.log('[sync-advisories] オフライン脆弱性・EOLスナップショットDB (Rev.2.1) を生成中...');
  
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
  
  const db = {
    schemaVersion: '2.1',
    version: '2026.10',
    dataVersion: dateStr,
    generatedAt: now.toISOString(),
    sources: [
      'NIST NVD 2.0 API (Primary: nvd@nist.gov)',
      'GitHub Advisory Database (GHSA)',
      'endoflife.date API',
      'CISA KEV Catalog'
    ],
    coverage: {
      totalAdvisories: 0,
      technologies: Object.keys(BASE_LIBRARIES)
    },
    libraries: {}
  };

  let totalAdvisories = 0;

  for (const [key, lib] of Object.entries(BASE_LIBRARIES)) {
    let eol = lib.eol;
    if (key !== 'angularjs') {
      try {
        const liveEol = await fetchEolData(key);
        if (liveEol && liveEol.length > 0) {
          eol = liveEol;
        }
      } catch {
        // フォールバック
      }
    }

    // 重大度をスコアから機械的導出
    const derivedVersions = lib.versions.map(v => {
      const severity = deriveSeverity(v.cvssScore);
      return {
        ...v,
        severity
      };
    });

    db.libraries[key] = {
      aliases: lib.aliases,
      versions: derivedVersions,
      eol
    };

    totalAdvisories += derivedVersions.length;
  }

  db.coverage.totalAdvisories = totalAdvisories;
  db.syncStatus = 'success';

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(db, null, 2), 'utf-8');
  console.log(`[sync-advisories] 正常に生成完了: ${OUTPUT_FILE}`);
  console.log(`  - schemaVersion: ${db.schemaVersion}`);
  console.log(`  - dataVersion: ${db.dataVersion}`);
  console.log(`  - 登録製品数: ${Object.keys(db.libraries).length}, 登録脆弱性数: ${totalAdvisories}`);
  console.log(`  - 同期ステータス: ${db.syncStatus}`);
}

syncAdvisories().catch(err => {
  console.error('[sync-advisories] エラー:', err);
  process.exit(1);
});
