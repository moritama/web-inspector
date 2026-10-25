/**
 * NVD API 一次情報取得 & 脆弱性差異分析スクリプト (scripts/fetch-nvd-advisories.mjs)
 */
import fs from 'node:fs';
import path from 'node:path';

const ROOT_DIR = process.cwd();
const CVE_LIST_FILE = path.join(ROOT_DIR, '.tmp', 'cves-1.3.3.txt');
const NVD_CACHE_DIR = path.join(ROOT_DIR, '.tmp', 'nvd');
const ADVISORY_DB_FILE = path.join(ROOT_DIR, 'src', 'detection', 'advisory-db.json');

if (!fs.existsSync(NVD_CACHE_DIR)) {
  fs.mkdirSync(NVD_CACHE_DIR, { recursive: true });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchCveFromNvd(cveId) {
  const cachePath = path.join(NVD_CACHE_DIR, `${cveId}.json`);
  if (fs.existsSync(cachePath)) {
    console.log(`[Cache Hit] ${cveId}`);
    return JSON.parse(fs.readFileSync(cachePath, 'utf8'));
  }

  console.log(`[Fetching NVD API] ${cveId}...`);
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
  
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'WebInspector-SecurityAuditor/1.6.0'
      }
    });

    if (!res.ok) {
      console.error(`[Error] HTTP ${res.status} for ${cveId}`);
      return null;
    }

    const data = await res.json();
    fs.writeFileSync(cachePath, JSON.stringify(data, null, 2), 'utf8');
    // NVD APIのレート制限（30秒間に5回 = 6秒以上の待機が必要）
    await sleep(7000);
    return data;
  } catch (err) {
    console.error(`[Fetch Failed] ${cveId}: ${err.message}`);
    return null;
  }
}

async function main() {
  const cveLines = fs.readFileSync(CVE_LIST_FILE, 'utf8')
    .split('\n')
    .map(s => s.trim())
    .filter(Boolean);

  console.log(`合計 ${cveLines.length} 件の CVE 一次情報を取得・照合します...`);

  const currentDb = JSON.parse(fs.readFileSync(ADVISORY_DB_FILE, 'utf8'));
  const currentCveMap = new Map();

  for (const [libName, lib] of Object.entries(currentDb.libraries)) {
    for (const v of lib.versions) {
      if (v.cve) {
        currentCveMap.set(v.cve, { libName, ...v });
      }
    }
  }

  const results = [];

  for (const cveId of cveLines) {
    const nvdData = await fetchCveFromNvd(cveId);
    if (!nvdData || !nvdData.vulnerabilities || nvdData.vulnerabilities.length === 0) {
      results.push({
        cveId,
        error: 'NVDデータ未取得または空'
      });
      continue;
    }

    const vuln = nvdData.vulnerabilities[0].cve;
    const descObj = vuln.descriptions?.find(d => d.lang === 'en');
    const description = descObj ? descObj.value : 'No description';

    // CVSS Metrics 抽出
    let primaryMetric = null;
    let secondaryMetric = null;

    if (vuln.metrics?.cvssMetricV31) {
      for (const m of vuln.metrics.cvssMetricV31) {
        if (m.type === 'Primary') primaryMetric = m;
        else if (!secondaryMetric) secondaryMetric = m;
      }
    }
    // v3.1がなければv3.0をチェック
    if (!primaryMetric && vuln.metrics?.cvssMetricV30) {
      for (const m of vuln.metrics.cvssMetricV30) {
        if (m.type === 'Primary') primaryMetric = m;
        else if (!secondaryMetric) secondaryMetric = m;
      }
    }
    // v3がなければv2をチェック
    if (!primaryMetric && vuln.metrics?.cvssMetricV2) {
      for (const m of vuln.metrics.cvssMetricV2) {
        if (m.type === 'Primary') primaryMetric = m;
        else if (!secondaryMetric) secondaryMetric = m;
      }
    }

    const primaryScore = primaryMetric?.cvssData?.baseScore ?? 'N/A';
    const primarySeverity = primaryMetric?.cvssData?.baseSeverity ?? primaryMetric?.baseSeverity ?? 'N/A';
    const primaryVector = primaryMetric?.cvssData?.vectorString ?? 'N/A';
    const primarySource = primaryMetric?.source ?? 'N/A';

    const secondaryScore = secondaryMetric?.cvssData?.baseScore ?? 'None';
    const secondarySeverity = secondaryMetric?.cvssData?.baseSeverity ?? secondaryMetric?.baseSeverity ?? 'None';
    const secondarySource = secondaryMetric?.source ?? 'None';

    const cisaKev = vuln.cisaExploitAdd ? `Yes (${vuln.cisaExploitAdd})` : 'No';

    const localEntry = currentCveMap.get(cveId);

    results.push({
      cveId,
      description,
      primaryScore,
      primarySeverity,
      primaryVector,
      primarySource,
      secondaryScore,
      secondarySeverity,
      secondarySource,
      cisaKev,
      localEntry
    });
  }

  // 結果JSONを保存
  fs.writeFileSync(path.join(ROOT_DIR, '.tmp', 'cve_audit_results.json'), JSON.stringify(results, null, 2), 'utf8');

  // Markdown差異表を出力
  console.log('\n======================================================');
  console.log(' v1.3.3 公開中 CVE vs NVD 一次情報 差異照合結果');
  console.log('======================================================\n');

  console.log('| CVE ID | ライブラリ | NVD Primary CVSS | 重大度 (Primary) | Secondary (CISA等) | CISA KEV | 現行DBの重大度 | 差異・判定 |');
  console.log('|---|---|:---:|:---:|:---:|:---:|:---:|---|');

  for (const r of results) {
    if (r.error) {
      console.log(`| **${r.cveId}** | - | - | - | - | - | - | ❌ ${r.error} |`);
      continue;
    }
    const localLib = r.localEntry?.libName ?? '非登録/削除済';
    const localSev = r.localEntry?.severity ?? 'N/A';
    const nvdSev = r.primarySeverity.toLowerCase();
    
    let diff = '✅ 一致';
    if (!r.localEntry) {
      diff = '⚠️ 現行DBに未登録';
    } else if (localSev !== nvdSev) {
      diff = `❌ 重大度不一致 (DB: ${localSev} vs NVD: ${nvdSev})`;
    }

    const sec = r.secondaryScore !== 'None' ? `${r.secondaryScore} (${r.secondarySeverity})` : '-';
    console.log(`| **${r.cveId}** | ${localLib} | **${r.primaryScore}** | **${r.primarySeverity}** | ${sec} | ${r.cisaKev} | \`${localSev}\` | ${diff} |`);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
