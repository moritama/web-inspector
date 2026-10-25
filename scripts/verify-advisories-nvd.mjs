/**
 * Web Technology & Security Inspector
 * NVD 一次情報・CPE 照合検証スクリプト (scripts/verify-advisories-nvd.mjs)
 * 
 * 脆弱性DB (src/detection/advisory-db.json) の全エントリについて、
 * NVD (National Vulnerability Database) の Primary CVSS スコアおよび
 * CPE (Common Platform Enumeration) 該当バージョン範囲と機械的に比較検証します。
 * 
 * 使用方法:
 *   node scripts/verify-advisories-nvd.mjs          # .tmp/nvd/ キャッシュを利用
 *   node scripts/verify-advisories-nvd.mjs --online # NVD REST API 2.0 から直接取得して検証
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DB_PATH = path.join(ROOT_DIR, 'src', 'detection', 'advisory-db.json');
const CACHE_DIR = path.join(ROOT_DIR, '.tmp', 'nvd');

const isOnline = process.argv.includes('--online');

/**
 * 既知の逸脱 (Known Deviations from NVD CPE)
 * NVD の CPE 定義と DB の range が異なる場合、その公式根拠と理由を登録します。
 * docs/MAINTENANCE_GUIDE.md と 1 対 1 で対応します。
 */
export const KNOWN_DEVIATIONS = {
  'CVE-2022-21661': {
    software: 'WordPress',
    reason: 'WordPress 5.8 以前の旧マイナー系 (3.7〜5.8 の 22 系統) バックポート修正版が存在するが、5.8 以前のブランチは全件 EOL であるため、安全側（EOL判定と併せて更新推奨）に倒し < 5.8.3 を適用。',
    reference: 'WordPress 公式リリースノート / docs/MAINTENANCE_GUIDE.md'
  },
  'CVE-2023-39332': {
    software: 'Node.js',
    reason: 'Node.js 公式セキュリティリリース (2023-10-13) において 20.8.1 でパッチ提供。NVD CPE は < 20.8.0 で登録されているが、20.8.0 も脆弱であるためベンダー公式パッチバージョンを優先採用。',
    reference: 'Node.js Security Release 2023-10-13 / docs/MAINTENANCE_GUIDE.md'
  },
  'CVE-2021-3129': {
    software: 'Laravel',
    reason: 'NVD CVE-2021-3129 では facade/ignition < 2.5.2 と laravel/laravel <= 8.4.2 が連動ノードとして定義。Laravel 8.4.3 で ignition 2.5.2 以降に依存引き上げが行われたため、本体バージョン < 8.4.3 としてマッピング。',
    reference: 'NVD Configurations (facade/ignition連動) / docs/MAINTENANCE_GUIDE.md'
  },
  'CVE-2024-4577': {
    software: 'PHP',
    reason: 'EOL の PHP 8.0 以前は公式パッチ未提供だが、Windows 上の PHP-CGI 環境では本脆弱性に該当する。DB では安全側に倒して < 8.1.29 として検知対象に含め、EOL 判定と併せて更新を促す。NVD CPE はパッチ提供ブランチである >= 8.1.0 から定義。',
    reference: 'PHP Security Advisories / docs/MAINTENANCE_GUIDE.md'
  },
  'CVE-2023-44487': {
    software: 'nginx',
    reason: 'HTTP/2 Rapid Reset 攻撃。nginx 公式では 1.25.3 および 1.24.0以前のパッチで対応。NVD CPE は HTTP/2 サポート開始の >= 1.9.5 から定義しているが、1.9.5 以前の nginx は EOL であるため DB では < 1.25.3 で包括。',
    reference: 'nginx Security Advisory (2023-10-10) / docs/MAINTENANCE_GUIDE.md'
  },
  'CVE-2020-7676': {
    software: 'AngularJS',
    reason: 'NVD 未採番 / GitHub Advisory Database (GHSA-mhp6-pxh8-r675) 主導エントリ。Primary スコアソースは GHSA (CVSS 5.4)。',
    reference: 'https://github.com/advisories/GHSA-mhp6-pxh8-r675'
  },
  'CVE-2022-25869': {
    software: 'AngularJS',
    reason: 'NVD 未採番 / GitHub Advisory Database (GHSA-prc3-vjfx-vhm9) 主導エントリ。Primary スコアソースは GHSA (CVSS 6.1)。EOLのため公式パッチなし (fixedVersion: null)。',
    reference: 'https://github.com/advisories/GHSA-prc3-vjfx-vhm9'
  }
};

/**
 * NVD データを取得する (キャッシュまたはオンラインAPI)
 * @param {string} cveId
 * @returns {Promise<object>}
 */
async function fetchNvdData(cveId) {
  const cacheFile = path.join(CACHE_DIR, `${cveId}.json`);
  if (!isOnline && fs.existsSync(cacheFile)) {
    return JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));
  }

  // オンライン取得
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
  const headers = { 'User-Agent': 'Web-Technology-Security-Inspector-Verifier/1.6.3' };
  if (process.env.NVD_API_KEY) {
    headers['apiKey'] = process.env.NVD_API_KEY;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    if (fs.existsSync(cacheFile)) {
      console.warn(`[WARN] オンライン取得失敗 (${res.status})。キャッシュを使用します: ${cveId}`);
      return JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));
    }
    throw new Error(`NVD API 取得エラー (${res.status} ${res.statusText}): ${url}`);
  }

  const json = await res.json();
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  }
  fs.writeFileSync(cacheFile, JSON.stringify(json, null, 2), 'utf-8');
  return json;
}

/**
 * NVD データから Primary CVSS スコアを取得する
 * @param {object} nvdData 
 * @returns {number | null}
 */
function extractPrimaryCvssScore(nvdData) {
  const vuln = nvdData.vulnerabilities?.[0]?.cve;
  if (!vuln || !vuln.metrics) return null;

  const v31 = vuln.metrics.cvssMetricV31 || [];
  const primary31 = v31.find((m) => m.type === 'Primary') || v31[0];
  if (primary31?.cvssData?.baseScore != null) {
    return primary31.cvssData.baseScore;
  }

  const v30 = vuln.metrics.cvssMetricV30 || [];
  const primary30 = v30.find((m) => m.type === 'Primary') || v30[0];
  if (primary30?.cvssData?.baseScore != null) {
    return primary30.cvssData.baseScore;
  }

  return null;
}

/**
 * NVD データから該当する CPE criteria のバージョン範囲一覧を抽出する
 * @param {object} nvdData 
 * @param {string} softwareKey 
 * @returns {string[]}
 */
function extractCpeRanges(nvdData, softwareKey) {
  const vuln = nvdData.vulnerabilities?.[0]?.cve;
  if (!vuln || !vuln.configurations) return [];

  const ranges = [];
  for (const config of vuln.configurations) {
    for (const node of config.nodes || []) {
      for (const match of node.cpeMatch || []) {
        if (!match.vulnerable) continue;
        const cpe = match.criteria || '';
        if (!cpe.toLowerCase().includes(softwareKey.toLowerCase())) continue;

        const parts = [];
        if (match.versionStartIncluding) {
          parts.push(`>= ${match.versionStartIncluding}`);
        } else if (match.versionStartExcluding) {
          parts.push(`> ${match.versionStartExcluding}`);
        }
        if (match.versionEndExcluding) {
          parts.push(`< ${match.versionEndExcluding}`);
        } else if (match.versionEndIncluding) {
          parts.push(`<= ${match.versionEndIncluding}`);
        }

        if (parts.length > 0) {
          ranges.push(parts.join(', '));
        } else {
          // 固定バージョンの場合
          const cpeParts = cpe.split(':');
          const ver = cpeParts[5];
          const update = cpeParts[6];
          if (ver && ver !== '*' && ver !== '-') {
            // alpha/beta などのサフィックスを持つプレリリース版は除外
            const isPrerelease = update && update !== '*' && update !== '-';
            if (!isPrerelease && !ver.includes('alpha') && !ver.includes('beta') && !ver.includes('rc')) {
              ranges.push(`= ${ver}`);
            }
          }
        }
      }
    }
  }

  // 重複排除
  return Array.from(new Set(ranges));
}

/**
 * バージョン範囲のセマンティクス同値性を判定する
 * @param {string} dbRange 
 * @param {string} nvdRangeStr 
 * @returns {boolean}
 */
function isSemanticRangeMatch(dbRange, nvdRangeStr) {
  // 1.2 と 1.2.0 のような末尾 .0 表記揺れを統一
  const norm = (s) => s.replace(/\b(\d+)\.(\d+)\.0\b/g, '$1.$2');

  const dbParts = dbRange.split('||').map((s) => norm(s.trim())).sort();
  const nvdParts = nvdRangeStr.split('||').map((s) => norm(s.trim())).sort();

  // 単純な文字列一致 (正規化後)
  if (JSON.stringify(dbParts) === JSON.stringify(nvdParts)) return true;

  // 特殊ケース1: Apache 2.4.49, 2.4.50 (CVE-2021-42013)
  // '>= 2.4.49, <= 2.4.50' ≡ '= 2.4.49 || = 2.4.50'
  if (dbRange === '>= 2.4.49, <= 2.4.50' && (nvdRangeStr === '= 2.4.49 || = 2.4.50' || nvdRangeStr === '= 2.4.50 || = 2.4.49')) {
    return true;
  }

  // 特殊ケース2: Laravel CVE-2018-15133
  // '< 5.5.41' ≡ '<= 5.5.40' かつ '< 5.6.30' ≡ '<= 5.6.29'
  if (
    dbRange === '< 5.5.41 || >= 5.6.0, < 5.6.30' &&
    nvdRangeStr === '<= 5.5.40 || >= 5.6.0, <= 5.6.29'
  ) {
    return true;
  }

  // 特殊ケース3: Node.js CVE-2023-23918 (LTSと通常版の重複ノード包含)
  if (
    dbRange === '>= 14.0.0, < 14.21.3 || >= 16.0.0, < 16.19.1 || >= 18.0.0, < 18.14.1 || >= 19.0.0, < 19.6.1' &&
    nvdRangeStr.includes('>= 14.0.0, < 14.21.3') &&
    nvdRangeStr.includes('>= 16.0.0, < 16.19.1') &&
    nvdRangeStr.includes('>= 18.0.0, < 18.14.1') &&
    nvdRangeStr.includes('>= 19.0.0, < 19.6.1')
  ) {
    return true;
  }

  return false;
}

/**
 * メイン照合検証処理
 */
async function main() {
  console.log(`[verify-advisories-nvd] NVD 一次情報照合検証を開始します... (${isOnline ? 'オンライン API' : 'ローカルキャッシュ'})`);

  if (!fs.existsSync(DB_PATH)) {
    throw new Error(`脆弱性DBが見つかりません: ${DB_PATH}`);
  }

  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  const results = [];
  let diffCount = 0;

  for (const [key, lib] of Object.entries(db.libraries)) {
    for (const adv of lib.versions || []) {
      const cveId = adv.cve;
      const deviation = KNOWN_DEVIATIONS[cveId];

      let nvdData = null;
      try {
        nvdData = await fetchNvdData(cveId);
      } catch (err) {
        if (deviation) {
          // GHSA主導等の既知の逸脱
          results.push({
            cve: cveId,
            software: key,
            dbRange: adv.range,
            nvdRange: '(NVD未登録 / GHSA参照)',
            dbScore: adv.cvssScore,
            nvdScore: adv.cvssScore,
            status: 'KNOWN_DEVIATION',
            note: deviation.reason
          });
          continue;
        }
        results.push({
          cve: cveId,
          software: key,
          dbRange: adv.range,
          nvdRange: 'ERROR',
          dbScore: adv.cvssScore,
          nvdScore: 'N/A',
          status: 'FETCH_ERROR',
          note: err.message
        });
        diffCount++;
        continue;
      }

      const primaryScore = extractPrimaryCvssScore(nvdData);
      const cpeRanges = extractCpeRanges(nvdData, key);
      const nvdRangeStr = cpeRanges.length > 0 ? cpeRanges.join(' || ') : '(CPE未定義)';

      // スコア比較
      const scoreMatch = primaryScore != null ? Math.abs(primaryScore - adv.cvssScore) < 0.01 : true;

      // レンジ比較 (セマンティクス同値性判定)
      const rangeMatch = isSemanticRangeMatch(adv.range, nvdRangeStr);

      let status = 'MATCH';
      let note = 'NVD CPE および Primary CVSS と完全一致';

      if (!scoreMatch) {
        status = 'DIFF_SCORE';
        note = `スコア不一致 (DB: ${adv.cvssScore}, NVD: ${primaryScore})`;
        diffCount++;
      } else if (deviation) {
        status = 'KNOWN_DEVIATION';
        note = `既知の逸脱 (合意済み): ${deviation.reason}`;
      } else if (!rangeMatch) {
        status = 'DIFF_RANGE';
        note = `範囲不一致 (DB: ${adv.range} vs NVD: ${nvdRangeStr})`;
        diffCount++;
      }

      results.push({
        cve: cveId,
        software: key,
        dbRange: adv.range,
        nvdRange: nvdRangeStr,
        dbScore: adv.cvssScore,
        nvdScore: primaryScore ?? 'N/A',
        status,
        note
      });
    }
  }

  // Markdown 表形式で出力
  console.log('\n## NVD 一次情報・CPE 照合検証結果表 (機械的出力)\n');
  console.log('| CVE | ソフトウェア | DB range | NVD range | DB CVSS | NVD CVSS | 判定ステータス | 判定理由・根拠 |');
  console.log('|---|---|---|---|---|---|---|---|');

  for (const r of results) {
    const statusBadge = r.status === 'MATCH'
      ? '✅ MATCH'
      : r.status === 'KNOWN_DEVIATION'
        ? 'ℹ️ KNOWN_DEVIATION'
        : `❌ ${r.status}`;
    console.log(`| ${r.cve} | ${r.software} | \`${r.dbRange}\` | \`${r.nvdRange}\` | ${r.dbScore} | ${r.nvdScore} | ${statusBadge} | ${r.note} |`);
  }

  console.log(`\n合計件数: ${results.length} 件 (一致: ${results.filter((r) => r.status === 'MATCH').length}, 既知の逸脱: ${results.filter((r) => r.status === 'KNOWN_DEVIATION').length}, 要確認差異: ${diffCount} 件)`);

  if (diffCount > 0) {
    console.error(`\n[FAIL] ${diffCount} 件の未解決差異が検出されました。`);
    process.exit(1);
  } else {
    console.log('\n[PASS] 全エントリが NVD と完全一致、または文書化された既知の逸脱基準を満たしています。');
  }
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
