/**
 * Web Technology & Security Inspector
 * CVSS v3.x ベーススコア計算・重大度導出 (scripts/advisories/lib/cvss.mjs)
 *
 * OSV/GHSA はベクター文字列のみを提供するため、FIRST CVSS v3.1 仕様書 (Section 7.1 / Appendix A)
 * の計算式に従ってベーススコアを機械的に算出する。手書きスコアは使用しない (MAINTENANCE_GUIDE 2.2 準拠)。
 */

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

function prWeight(pr, scopeChanged) {
  if (pr === 'N') return 0.85;
  if (pr === 'L') return scopeChanged ? 0.68 : 0.62;
  if (pr === 'H') return scopeChanged ? 0.5 : 0.27;
  return undefined;
}

/** CVSS v3.1 の Roundup (浮動小数点誤差対策版, 仕様書 Appendix A) */
function roundUp31(value) {
  const intInput = Math.round(value * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** CVSS v3.0 の Roundup (小数第1位への切り上げ) */
function roundUp30(value) {
  return Math.ceil(value * 10) / 10;
}

/**
 * CVSS v3.0 / v3.1 ベクター文字列からベーススコアを計算する
 * @param {string} vector 例: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 * @returns {{ score: number, version: '3.0' | '3.1' } | null} 不正なベクターは null
 */
export function computeCvss3BaseScore(vector) {
  if (!vector || typeof vector !== 'string') return null;
  const m = vector.trim().match(/^CVSS:(3\.[01])\/(.+)$/);
  if (!m) return null;
  const version = m[1];
  const metrics = {};
  for (const part of m[2].split('/')) {
    const [k, v] = part.split(':');
    if (k && v) metrics[k] = v;
  }

  const scopeChanged = metrics.S === 'C';
  if (metrics.S !== 'U' && metrics.S !== 'C') return null;

  const av = WEIGHTS.AV[metrics.AV];
  const ac = WEIGHTS.AC[metrics.AC];
  const ui = WEIGHTS.UI[metrics.UI];
  const pr = prWeight(metrics.PR, scopeChanged);
  const c = WEIGHTS.CIA[metrics.C];
  const i = WEIGHTS.CIA[metrics.I];
  const a = WEIGHTS.CIA[metrics.A];
  if ([av, ac, ui, pr, c, i, a].some((w) => w === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) return { score: 0, version };

  const roundUp = version === '3.1' ? roundUp31 : roundUp30;
  const raw = scopeChanged ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return { score: roundUp(raw), version };
}

/**
 * CVSSスコアから重大度を機械的に導出する (MAINTENANCE_GUIDE 2.2 ② 準拠)
 * @param {number} score
 * @returns {'critical' | 'high' | 'medium' | 'low'}
 */
export function deriveSeverity(score) {
  if (typeof score !== 'number' || Number.isNaN(score) || score < 0 || score > 10) {
    throw new Error(`無効なCVSSスコアです: ${score}`);
  }
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}
