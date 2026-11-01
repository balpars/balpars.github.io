// getStaticPaths builders shared by the English pages and their Turkish wrappers
// in src/pages/[lang], so both languages generate exactly the same set of pages.
// A language that isn't active (see activeLangs in src/i18n.ts) gets no pages.
import type { PaginateFunction } from 'astro'
import siteConfig from '~/site.config'
import { defaultLang, isLangActive, type Lang } from '~/i18n'
import {
  SeriesGroup,
  TagsGroup,
  getPostSequenceContext,
  getSortedPosts,
  postSlug,
} from '~/utils'

// Turkish pages live under src/pages/[lang], so they need the lang param
function langParam(lang: Lang) {
  return lang === defaultLang ? {} : { lang }
}

// For language home pages like /tr: one page while the language is active, none otherwise
export function langPaths(lang: Lang) {
  return isLangActive(lang) && lang !== defaultLang ? [{ params: { lang } }] : []
}

export async function postPaths(lang: Lang) {
  if (!isLangActive(lang)) return []
  const posts = await getSortedPosts(lang)
  return posts.map((post) => {
    // Get sequence context for the post
    const { prev, next } = getPostSequenceContext(post, posts)
    return {
      params: { ...langParam(lang), slug: postSlug(post) },
      props: { post, prev, next },
    }
  })
}

// Note: Pagination like '/', '/2', '/3' only works with spread param like [...page]
export async function archivePaths(paginate: PaginateFunction, lang: Lang) {
  if (!isLangActive(lang)) return []
  const sortedPosts = await getSortedPosts(lang)
  return paginate(sortedPosts.reverse(), {
    params: langParam(lang),
    pageSize: siteConfig.pageSize,
  })
}

export async function tagPaths(paginate: PaginateFunction, lang: Lang) {
  if (!isLangActive(lang)) return []
  const tagsGroup = await TagsGroup.build(undefined, lang)
  return tagsGroup.collations.flatMap((tags) => {
    // Use flatMap to lift the posts for each tag into a single array
    return paginate(tags.entries.reverse(), {
      props: { tagTitle: tags.title },
      params: { ...langParam(lang), tag: tags.titleSlug },
      pageSize: siteConfig.pageSize,
    })
  })
}

export async function seriesPaths(lang: Lang) {
  if (!isLangActive(lang)) return []
  const seriesGroup = await SeriesGroup.build(undefined, lang)
  return seriesGroup.collations.map((series) => {
    return {
      params: { ...langParam(lang), slug: series.titleSlug },
      props: { posts: series.entries, seriesTitle: series.title },
    }
  })
}
