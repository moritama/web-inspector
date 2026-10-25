/**
 * Web Technology & Security Inspector
 * 検出ルール統合定義 (src/detection/rules/index.ts)
 */

import { ImplicationType, RuntimeStatus, TechnologyCategory } from '../../shared/types';
import serverRules from './server.json';
import languageRules from './language.json';
import backendRules from './backend.json';
import cmsRules from './cms.json';
import frontendRules from './frontend.json';
import servicesRules from './services.json';
import cdnWafRules from './cdn-waf.json';

/**
 * 技術間の連動・推論関係定義 (Rev.1.2 IMP-17)
 */
export interface RuleImplication {
  id: string;
  relation: ImplicationType;
  runtimeStatus?: RuntimeStatus;
  confidenceFactor?: number;
}

/**
 * 個別の検出シグナル仕様
 */
export interface RuleSignal {
  type: 'header' | 'cookie' | 'url' | 'meta' | 'script' | 'link' | 'dom' | 'css';
  target: string;
  pattern?: string;
  versionRegex?: string;
  weight: number;
  /** エビデンス表示用の詳細説明（未指定時は自動生成） */
  detail?: string;
}

/**
 * 技術検出ルール
 */
export interface TechnologyRule {
  id: string;
  name: string;
  category: TechnologyCategory;
  website?: string;
  description?: string;
  signals: RuleSignal[];
  /** この技術が一定確信度以上で検出された場合に連動検出（含意）する技術ID一覧または詳細定義 */
  implies?: Array<string | RuleImplication>;
}

/**
 * 統合ルールセット (v1.6.0)
 */
export const ALL_TECHNOLOGY_RULES: TechnologyRule[] = [
  ...(serverRules as unknown as TechnologyRule[]),
  ...(languageRules as unknown as TechnologyRule[]),
  ...(backendRules as unknown as TechnologyRule[]),
  ...(cmsRules as unknown as TechnologyRule[]),
  ...(frontendRules as unknown as TechnologyRule[]),
  ...(servicesRules as unknown as TechnologyRule[]),
  ...(cdnWafRules as unknown as TechnologyRule[]),
];

export const RULES_VERSION = '1.6.4';
