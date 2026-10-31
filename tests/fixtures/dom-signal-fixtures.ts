/**
 * Web Technology & Security Inspector
 * DOMシグナル検証用 最小HTMLフィクスチャ定義 (tests/fixtures/dom-signal-fixtures.ts)
 * 
 * ALL_TECHNOLOGY_RULES のすべての type: 'dom' シグナルに対応する最小HTMLを定義します (T06 / DOC-01)
 */

export interface DomSignalHtmlFixture {
  html: string;
  title?: string;
  headHtml?: string;
}

/**
 * ルールID (または "ruleId::target") をキーとするフィクスチャマップ
 */
export const DOM_SIGNAL_FIXTURES: Record<string, DomSignalHtmlFixture> = {
  'spring-boot': {
    html: '<h1>Whitelabel Error Page</h1>',
  },
  'fastapi': {
    html: '',
    title: 'FastAPI - Swagger UI',
  },
  'spring-security': {
    html: '<form><input name="_csrf" value="csrf_token_value"></form>',
  },
  'react': {
    html: '<div data-reactroot=""></div>',
  },
  'nextjs': {
    html: '<script id="__NEXT_DATA__" type="application/json">{}</script>',
  },
  'vue': {
    html: '<div data-v-app=""></div>',
  },
  'vue::__nuxt': {
    html: '<div id="__nuxt"></div>',
  },
  'nuxtjs': {
    html: '<div id="__nuxt"></div>',
  },
  'angular': {
    html: '<div ng-version="17.0.0"></div>',
  },
  'angularjs': {
    html: '<div ng-app="myApp"></div>',
  },
  'svelte': {
    html: '<div class="svelte-1abcde"></div>',
  },
  'bootstrap': {
    html: '<div class="container"></div>',
  },
  'alpine': {
    html: '<div x-data="{ count: 0 }"></div>',
  },
  'htmx': {
    html: '<button hx-get="/api/items">Click</button>',
  },
  'datatables': {
    html: '<table class="dataTable"></table>',
  },
  'tinymce': {
    html: '<div class="tox-tinymce"></div>',
  },
  'ckeditor': {
    html: '<div class="ck-editor"></div>',
  },
  'fontawesome': {
    html: '<i class="fa-solid fa-user"></i>',
  },
  'material-ui': {
    html: '<button class="MuiButton-root"></button>',
  },
  'astro': {
    html: '<astro-island></astro-island>',
  },
  'sveltekit': {
    html: '<div id="svelte"></div>',
  },
  'python-django': {
    html: '<input name="csrfmiddlewaretoken" value="dummy_csrf_token">',
  },
  'ruby-on-rails': {
    html: '<meta name="csrf-param" content="authenticity_token">',
  },
  'google-tag-manager': {
    html: '<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX"></iframe></noscript>',
  },
  'recaptcha': {
    html: '<div class="g-recaptcha"></div>',
  },
  'hcaptcha': {
    html: '<div class="h-captcha"></div>',
  },
};

/**
 * ルールIDとtargetから対応するフィクスチャを取得するヘルパー関数
 */
export function getDomSignalFixture(ruleId: string, target: string): DomSignalHtmlFixture | undefined {
  const specificKey = `${ruleId}::${target}`;
  if (DOM_SIGNAL_FIXTURES[specificKey]) {
    return DOM_SIGNAL_FIXTURES[specificKey];
  }
  return DOM_SIGNAL_FIXTURES[ruleId];
}
