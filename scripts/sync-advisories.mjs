/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOLスナップショット同期スクリプト (scripts/sync-advisories.mjs)
 * 
 * ビルド時に実行され、主要ライブラリ・ソフトウェアのEOL・既知脆弱性カタログを
 * ミニファイされたスナップショットJSON (src/detection/advisory-db.json) として生成します。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const OUTPUT_FILE = path.join(ROOT_DIR, 'src', 'detection', 'advisory-db.json');

// 主要ライブラリ・サーバー・言語のベース脆弱性カタログ (ビルド時スナップショット)
const BASE_LIBRARIES = {
  jquery: {
    aliases: ['jquery'],
    versions: [
      {
        range: '< 3.5.0',
        cve: 'CVE-2020-11022',
        severity: 'medium',
        title: 'Regex in jQuery.htmlPrefilter can result in XSS',
        fixedVersion: '3.5.0'
      },
      {
        range: '< 3.5.0',
        cve: 'CVE-2020-11023',
        severity: 'medium',
        title: 'XSS in jQuery.htmlPrefilter even with sanitizers',
        fixedVersion: '3.5.0'
      },
      {
        range: '< 3.4.0',
        cve: 'CVE-2019-11358',
        severity: 'medium',
        title: 'jQuery prototype pollution via $.extend',
        fixedVersion: '3.4.0'
      },
      {
        range: '< 3.0.0',
        cve: 'CVE-2015-9251',
        severity: 'medium',
        title: 'XSS via cross-domain ajax requests with dataType script',
        fixedVersion: '3.0.0'
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
        range: '>= 4.0.0, < 4.3.1',
        cve: 'CVE-2019-8331',
        severity: 'medium',
        title: 'XSS in Bootstrap Tooltip and Popover data-template',
        fixedVersion: '4.3.1'
      },
      {
        range: '< 4.1.2',
        cve: 'CVE-2018-14041',
        severity: 'medium',
        title: 'XSS in Bootstrap Collapse plugin data-parent attribute',
        fixedVersion: '4.1.2'
      },
      {
        range: '< 3.4.0',
        cve: 'CVE-2016-10735',
        severity: 'medium',
        title: 'XSS in data-target attribute for Bootstrap 3',
        fixedVersion: '3.4.0'
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
        severity: 'medium',
        title: 'Potential XSS when generating attributes in React SSR',
        fixedVersion: '16.0.0'
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
        severity: 'low',
        title: 'Potential ReDoS in vue template compiler',
        fixedVersion: '2.6.10'
      }
    ],
    eol: [
      { cycle: '2.x', eolDate: '2023-12-31', status: 'EOL' },
      { cycle: '3.x', eolDate: null, status: 'Supported' }
    ]
  },
  angular: {
    aliases: ['angular', 'angularjs'],
    versions: [
      {
        range: '< 1.8.0',
        cve: 'CVE-2020-7676',
        severity: 'high',
        title: 'XSS in AngularJS via universal attribute interpolation',
        fixedVersion: '1.8.0'
      }
    ],
    eol: [
      { cycle: '1.x (AngularJS)', eolDate: '2022-01-01', status: 'EOL' },
      { cycle: '2.x - 14.x', eolDate: '2023-11-01', status: 'EOL' },
      { cycle: '17.x+', eolDate: null, status: 'Supported' }
    ]
  },
  lodash: {
    aliases: ['lodash'],
    versions: [
      {
        range: '< 4.17.21',
        cve: 'CVE-2021-23337',
        severity: 'high',
        title: 'Prototype Pollution in lodash.template',
        fixedVersion: '4.17.21'
      },
      {
        range: '< 4.17.19',
        cve: 'CVE-2020-8203',
        severity: 'high',
        title: 'Prototype Pollution in lodash.zipObjectDeep',
        fixedVersion: '4.17.19'
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
        range: '< 6.2.2',
        cve: 'CVE-2023-32243',
        severity: 'critical',
        title: 'WordPress Shortcode API Directory Traversal / RCE',
        fixedVersion: '6.2.2'
      },
      {
        range: '< 5.8.3',
        cve: 'CVE-2022-21661',
        severity: 'high',
        title: 'SQL Injection in WP_Query',
        fixedVersion: '5.8.3'
      }
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
        range: '< 8.1.29',
        cve: 'CVE-2024-4577',
        severity: 'critical',
        title: 'PHP CGI Argument Injection vulnerability leading to RCE',
        fixedVersion: '8.1.29'
      },
      {
        range: '< 7.4.33',
        cve: 'CVE-2022-31628',
        severity: 'high',
        title: 'Phar deserialization vulnerability',
        fixedVersion: '7.4.33'
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
        severity: 'high',
        title: 'HTTP/2 Rapid Reset Denial of Service Vulnerability',
        fixedVersion: '1.25.3'
      },
      {
        range: '< 1.21.0',
        cve: 'CVE-2021-23017',
        severity: 'high',
        title: '1-byte memory overwrite in resolver',
        fixedVersion: '1.21.0'
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
        severity: 'critical',
        title: 'Buffer overflow in mod_lua multipart parser',
        fixedVersion: '2.4.52'
      },
      {
        range: '= 2.4.49',
        cve: 'CVE-2021-41773',
        severity: 'critical',
        title: 'Path Traversal and File Disclosure in Apache HTTP Server 2.4.49',
        fixedVersion: '2.4.50'
      },
      {
        range: '= 2.4.50',
        cve: 'CVE-2021-42013',
        severity: 'critical',
        title: 'Path Traversal and RCE in Apache HTTP Server 2.4.50',
        fixedVersion: '2.4.51'
      }
    ],
    eol: [
      { cycle: '2.2', eolDate: '2017-12-31', status: 'EOL' },
      { cycle: '2.4', eolDate: null, status: 'Supported' }
    ]
  }
};

/**
 * endoflife.date APIから最新のEOL情報を取得する（失敗時はローカルフォールバック）
 */
async function fetchOnlineEolData(product) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000); // 3秒タイムアウト
    const res = await fetch(`https://endoflife.date/api/${product}.json`, {
      signal: controller.signal,
      headers: { 'Accept': 'application/json', 'User-Agent': 'Web-Inspector-Builder' }
    });
    clearTimeout(timeout);

    if (!res.ok) return null;
    const data = await res.json();
    if (!Array.isArray(data)) return null;

    const today = new Date().toISOString().slice(0, 10);
    return data.map((item) => {
      const eolVal = typeof item.eol === 'string' ? item.eol : (item.eol === true ? 'EOL' : null);
      let status = 'Supported';
      if (item.eol === true || (typeof item.eol === 'string' && item.eol <= today)) {
        status = 'EOL';
      } else if (item.support && typeof item.support === 'string' && item.support <= today) {
        status = 'Maintenance';
      }

      return {
        cycle: String(item.cycle),
        eolDate: typeof item.eol === 'string' ? item.eol : (status === 'EOL' ? 'Past' : null),
        status
      };
    });
  } catch {
    return null;
  }
}

async function main() {
  console.log('[sync-advisories] オフライン脆弱性・EOLスナップショットDBを生成中...');

  const db = {
    version: '2026.10',
    generatedAt: new Date().toISOString(),
    libraries: {}
  };

  for (const [key, lib] of Object.entries(BASE_LIBRARIES)) {
    let eolList = lib.eol;

    // 外部APIからの動的補完（PHP, Nginx等で可能な場合）
    const onlineEol = await fetchOnlineEolData(key);
    if (onlineEol && onlineEol.length > 0) {
      eolList = onlineEol;
    }

    db.libraries[key] = {
      aliases: lib.aliases,
      versions: lib.versions,
      eol: eolList
    };
  }

  // ディレクトリ作成確認
  const outDir = path.dirname(OUTPUT_FILE);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  // JSONファイル書き出し
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(db, null, 2), 'utf-8');
  console.log(`[sync-advisories] 正常に生成完了: ${OUTPUT_FILE} (登録技術数: ${Object.keys(db.libraries).length})`);
}

main().catch((err) => {
  console.error('[sync-advisories] 生成エラー:', err);
  process.exit(1);
});
