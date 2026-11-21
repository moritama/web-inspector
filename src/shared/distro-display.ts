/**
 * ディストリビューションおよび OS リリースの表示用フォーマッタ (v1.8.1 T06)
 */
import type { DetectedTechnology, DistroCveStatus, DistroInferenceConfidence } from './types';

/**
 * 'ubuntu:20.04' → 'Ubuntu 20.04'（lts が真なら末尾に ' LTS'）
 * 未知の系統は '<family> <cycle>'、':' が無ければそのまま返す
 */
export function formatDistroReleaseName(release: string, options?: { lts?: boolean }): string {
  if (!release || typeof release !== 'string') return '';
  const colonIndex = release.indexOf(':');
  if (colonIndex === -1) {
    return release;
  }

  const rawFamily = release.slice(0, colonIndex).toLowerCase();
  const cycle = release.slice(colonIndex + 1);

  let familyDisplay: string;
  switch (rawFamily) {
    case 'ubuntu':
      familyDisplay = 'Ubuntu';
      break;
    case 'debian':
      familyDisplay = 'Debian';
      break;
    case 'rhel':
      familyDisplay = 'Red Hat Enterprise Linux';
      break;
    case 'centos':
      familyDisplay = 'CentOS';
      break;
    case 'almalinux':
      familyDisplay = 'AlmaLinux';
      break;
    case 'rocky':
      familyDisplay = 'Rocky Linux';
      break;
    default:
      familyDisplay = release.slice(0, colonIndex);
      break;
  }

  const ltsSuffix = options?.lts ? ' LTS' : '';
  return `${familyDisplay} ${cycle}${ltsSuffix}`;
}

/**
 * 確信度の日本語表記を取得する
 * high → '高', medium → '中', low → '低', none → 'なし'
 */
export function formatDistroConfidenceJp(confidence: DistroInferenceConfidence): string {
  switch (confidence) {
    case 'high':
      return '高';
    case 'medium':
      return '中';
    case 'low':
      return '低';
    case 'none':
      return 'なし';
    default:
      return String(confidence);
  }
}

/** OS のライフサイクルで判定した EOL の印 (T03 judgeDistroEol) */
const OS_LIFECYCLE_SOURCE = 'endoflife.date（OS のライフサイクル）';

/**
 * リリース欄の表示（解釈 7 の順序）。distroInference が無ければ ''
 * (1) inf.release があればその表示名
 * (2) 候補が 1 件以上なら候補の表示名を ' / ' で連結
 * (3) それ以外（第三者・バックポート・none）は '推定なし'
 */
export function formatDistroReleaseDisplay(tech: Pick<DetectedTechnology, 'distroInference' | 'eolInfo'>): string {
  const inf = tech.distroInference;
  if (!inf) return '';

  // (1) inf.release があればその表示名
  if (inf.release) {
    return formatDistroReleaseName(inf.release);
  }

  // (2) 候補が 1 件以上なら候補の表示名を ' / ' で連結
  if (inf.candidates && inf.candidates.length > 0) {
    return inf.candidates.map((c) => formatDistroReleaseName(c)).join(' / ');
  }

  // (3) それ以外（第三者・バックポート・none）は '推定なし'
  return '推定なし';
}

/**
 * リリース名に確信度を 1 回だけ付ける（指摘文用。例: 'Ubuntu 18.04 LTS（推定・確信度 高）'）
 * 推定が無い（第三者・バックポート・候補なし・none）は formatDistroReleaseDisplay と同じ（'推定なし'）。distroInference が無ければ ''
 */
export function formatDistroReleaseWithConfidence(
  tech: Pick<DetectedTechnology, 'distroInference' | 'eolInfo'>
): string {
  const inf = tech.distroInference;
  if (!inf) return '';

  const display = formatDistroReleaseDisplay(tech);
  if (inf.thirdParty || !inf.candidates || inf.candidates.length === 0 || inf.confidence === 'none') {
    return display;
  }

  // 名前の部分: eolInfo.label があり、確信度を含まなければ label（LTS 付きなど）、それ以外は display
  let name = display;
  if (tech.eolInfo?.source === OS_LIFECYCLE_SOURCE && tech.eolInfo.label && !tech.eolInfo.label.includes('確信度')) {
    name = tech.eolInfo.label;
  }

  return `${name}（推定・確信度 ${formatDistroConfidenceJp(inf.confidence)}）`;
}

/**
 * 区分の表示: '<日本語>（<区分>）'
 * 例: '修正版より古い（not-fixed）'
 */
export function formatDistroCveStatusLabel(status: DistroCveStatus): string {
  switch (status) {
    case 'not-fixed':
      return '修正版より古い（not-fixed）';
    case 'open':
      return 'ディストリで未修正（open）';
    case 'unknown-revision':
      return 'パッケージ版が不明（unknown-revision）';
    case 'no-data':
      return 'ディストリのデータに無い（no-data）';
    case 'fixed':
      return 'ディストリで修正済みの可能性が高い（fixed）';
    case 'not-affected':
      return 'ディストリは影響なしと判断（not-affected）';
    default:
      return status;
  }
}
