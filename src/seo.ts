// Structured data (schema.org JSON-LD) so search engines understand the site:
// who writes it, that posts are blog posts, and where each page sits.
import siteConfig from '~/site.config'

type Schema = Record<string, unknown>

const homeUrl = new URL('/', siteConfig.site).href

export function personSchema(): Schema {
  const profiles = Object.values(siteConfig.socialLinks || {}).filter(
    (value): value is string => typeof value === 'string' && value.startsWith('http'),
  )
  return {
    '@type': 'Person',
    name: siteConfig.author,
    url: new URL('/about/', siteConfig.site).href,
    sameAs: profiles,
  }
}

export function websiteSchema(description: string, lang: string): Schema {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: siteConfig.title,
    url: homeUrl,
    description,
    inLanguage: lang,
    author: personSchema(),
    publisher: personSchema(),
  }
}

export function blogPostingSchema(post: {
  url: string
  title: string
  description?: string
  published: Date
  image: string
  tags?: string[]
  lang: string
}): Schema {
  return {
    '@context': 'https://schema.org',
    '@type': 'BlogPosting',
    headline: post.title,
    description: post.description,
    datePublished: post.published.toISOString(),
    dateModified: post.published.toISOString(),
    author: personSchema(),
    publisher: personSchema(),
    image: post.image,
    url: post.url,
    mainEntityOfPage: post.url,
    keywords: post.tags?.join(', '),
    inLanguage: post.lang,
    isPartOf: { '@type': 'Blog', name: siteConfig.title, url: homeUrl },
  }
}

export function breadcrumbSchema(items: { name: string; url: string }[]): Schema {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((item, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: item.name,
      item: item.url,
    })),
  }
}

// Meta descriptions read best under ~155 characters
export function truncate(text: string, max = 155): string {
  if (text.length <= max) return text
  return text.slice(0, max - 1).replace(/[\s,;:]+\S*$/, '') + '…'
}
