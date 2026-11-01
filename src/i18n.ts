// Languages, UI strings and path helpers for the English/Turkish site.
// English lives at the root ("/posts/x"), Turkish under "/tr" ("/tr/posts/x").

export const languages = {
  en: 'EN',
  tr: 'TR',
} as const

export type Lang = keyof typeof languages

export const defaultLang: Lang = 'en'

// Languages shown on the site. Turkish is still a draft, so it is left out
// everywhere (no /tr pages, no language switch). To review the draft locally,
// run `npm run dev:drafts`. To publish Turkish, add 'tr' here.
const publishedLangs: Lang[] = ['en']

export const activeLangs: Lang[] =
  import.meta.env.MODE === 'drafts' ? (Object.keys(languages) as Lang[]) : publishedLangs

export function isLangActive(lang: Lang): boolean {
  return activeLangs.includes(lang)
}

const ui = {
  en: {
    'site.description': 'Balpars Cyber Journey is a blog mainly about Cyber Security.',
    'nav.home': 'Home',
    'nav.about': 'About',
    'nav.archive': 'Posts',
    'home.latestPosts': 'Latest Posts',
    'home.series': 'Series',
    'home.tags': 'Tags',
    'post.read': 'Read',
    'post.continue': 'Continue',
    'post.next': 'Next',
    'post.morePosts': 'More Posts',
    'post.comments': 'Comments',
    'post.seriesSuffix': 'Series',
    'post.minRead': 'min read',
    'post.toc': 'Table of Contents',
    'pagination.previous': 'Previous',
    'pagination.next': 'Next',
    'pagination.newer': 'Newer Posts',
    'pagination.older': 'Older Posts',
    'pagination.page': 'Page',
    'archive.title': 'Posts',
    'archive.description': 'All posts',
    'tag.title': 'Tag',
    'tag.description': 'All posts tagged with {name}',
    'series.title': 'Series',
    'series.description': 'All posts in the {name} series',
    'header.search': 'Open Search',
    'header.theme': 'Select Theme',
    'header.language': 'Language',
    'footer.poweredBy': 'Powered by',
    'side.journal': 'Recent posts',
  },
  tr: {
    'site.description': 'Balpars Cyber Journey, çoğunlukla siber güvenlik üzerine yazdığım bir blog.',
    'nav.home': 'Ana Sayfa',
    'nav.about': 'Hakkımda',
    'nav.archive': 'Yazılar',
    'home.latestPosts': 'Son Yazılar',
    'home.series': 'Seriler',
    'home.tags': 'Etiketler',
    'post.read': 'Oku',
    'post.continue': 'Devam et',
    'post.next': 'Sonraki',
    'post.morePosts': 'Diğer Yazılar',
    'post.comments': 'Yorumlar',
    'post.seriesSuffix': 'Serisi',
    'post.minRead': 'dk okuma',
    'post.toc': 'İçindekiler',
    'pagination.previous': 'Önceki',
    'pagination.next': 'Sonraki',
    'pagination.newer': 'Yeni Yazılar',
    'pagination.older': 'Eski Yazılar',
    'pagination.page': 'Sayfa',
    'archive.title': 'Yazılar',
    'archive.description': 'Tüm yazılar',
    'tag.title': 'Etiket',
    'tag.description': '{name} etiketli tüm yazılar',
    'series.title': 'Seri',
    'series.description': '{name} serisindeki tüm yazılar',
    'header.search': 'Aramayı aç',
    'header.theme': 'Tema seç',
    'header.language': 'Dil',
    'footer.poweredBy': 'Altyapı:',
    'side.journal': 'Son yazılar',
  },
} as const

export type UiKey = keyof (typeof ui)['en']

export function t(lang: Lang, key: UiKey, vars: Record<string, string> = {}): string {
  const text: string = ui[lang][key] ?? ui[defaultLang][key]
  // Fill placeholders like {name}, so each language can put them where it reads best
  return text.replace(/\{(\w+)\}/g, (match, name) => vars[name] ?? match)
}

// Tags and series stay as the English keys in every post's front matter, so both
// languages group posts identically. These maps only change the label readers see.
// Add a line here when you introduce a new tag or series.
const tagLabels: Record<string, Partial<Record<Lang, string>>> = {
  cryptography: { tr: 'kriptografi' },
  ctf: { tr: 'ctf' },
  distributed_inference: { tr: 'dağıtık_çıkarım' },
  local_llm: { tr: 'yerel_llm' },
  malware_analysis: { tr: 'zararlı_yazılım_analizi' },
  reverse_engineering: { tr: 'tersine_mühendislik' },
}

const seriesLabels: Record<string, Partial<Record<Lang, string>>> = {
  'Cryptography Basics': { tr: 'Kriptografi Temelleri' },
  'Local LLMs': { tr: "Yerel LLM'ler" },
  'Malware Analysis': { tr: 'Zararlı Yazılım Analizi' },
  'Reverse Engineering': { tr: 'Tersine Mühendislik' },
}

export function tagLabel(tag: string, lang: Lang): string {
  return tagLabels[tag.trim()]?.[lang] ?? tag
}

export function seriesLabel(series: string, lang: Lang): string {
  return seriesLabels[series.trim()]?.[lang] ?? series
}

export function getLangFromUrl(url: URL): Lang {
  const [, first] = url.pathname.split('/')
  return first === 'tr' ? 'tr' : defaultLang
}

// "/tr/posts/x" -> "/posts/x"
export function unlocalizePath(path: string): string {
  const stripped = path.replace(/^\/tr(?=\/|$)/, '')
  return stripped === '' ? '/' : stripped
}

// "/posts/x" -> "/tr/posts/x" for Turkish, unchanged for English
export function localizePath(path: string, lang: Lang): string {
  const base = unlocalizePath(path)
  if (lang === defaultLang) return base
  return base === '/' ? `/${lang}` : `/${lang}${base}`
}

export function readingTimeText(minutes: number, lang: Lang): string {
  return `${Math.max(1, Math.ceil(minutes))} ${t(lang, 'post.minRead')}`
}
