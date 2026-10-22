/**
 * Web Technology & Security Inspector
 * 検出ルール統合定義 (src/detection/rules/index.ts)
 */

import { TechnologyCategory } from '../../shared/types';
import serverRules from './server.json';
import languageRules from './language.json';
import cmsRules from './cms.json';
import frontendRules from './frontend.json';
import cdnWafRules from './cdn-waf.json';

/**
 * 個別の検出シグナル仕様
 */
export interface RuleSignal {
  type: 'header' | 'cookie' | 'url' | 'meta' | 'script' | 'link' | 'dom' | 'css';
  target: string;
  pattern?: string;
  versionRegex?: string;
  weight: number;
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
}

/**
 * 統合ルールセット
 */
export const ALL_TECHNOLOGY_RULES: TechnologyRule[] = [
  ...(serverRules as unknown as TechnologyRule[]),
  ...(languageRules as unknown as TechnologyRule[]),
  ...(cmsRules as unknown as TechnologyRule[]),
  ...(frontendRules as unknown as TechnologyRule[]),
  ...(cdnWafRules as unknown as TechnologyRule[]),
];

export const RULES_VERSION = '1.0.0';
