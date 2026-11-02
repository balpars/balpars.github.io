// Dates for the sitemap's <lastmod>, read straight from the posts' front matter.
// (astro.config can't use content collections, so this reads the markdown files.)
import fs from 'node:fs'
import path from 'node:path'

const postsDir = path.resolve('./src/content/posts')

function markdownFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) return markdownFiles(full)
    // English posts only; drafts in other languages (name.tr.md) aren't published
    return /\.mdx?$/.test(entry.name) && !/\.\w{2}\.mdx?$/.test(entry.name) ? [full] : []
  })
}

function readPost(file) {
  const text = fs.readFileSync(file, 'utf8')
  const frontMatter = text.match(/^---\r?\n([\s\S]*?)\r?\n---/)?.[1] ?? ''
  const field = (name) => frontMatter.match(new RegExp(`^${name}:\\s*['"]?([^'"\\r\\n]+)`, 'm'))?.[1]?.trim()
  if (field('draft') === 'true') return null
  const slug = field('slug') ?? path.basename(file).replace(/\.mdx?$/, '')
  const date = field('updated') ?? field('published')
  return date ? { slug, date: new Date(date) } : null
}

const posts = markdownFiles(postsDir).map(readPost).filter(Boolean)
const newest = posts.length ? new Date(Math.max(...posts.map((post) => post.date.getTime()))) : null

// "/posts/x/" -> that post's date; home and the posts list -> the newest post's date
export function postLastModified(pathname) {
  const slug = pathname.match(/^\/posts\/([^/]+)\/?$/)?.[1]
  if (slug && !/^\d+$/.test(slug)) return posts.find((post) => post.slug === slug)?.date.toISOString()
  if (pathname === '/' || /^\/posts\/?$/.test(pathname)) return newest?.toISOString()
  return undefined
}
