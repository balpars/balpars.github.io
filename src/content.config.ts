import { defineCollection, z } from 'astro:content'
import { glob } from 'astro/loaders'

const postsCollection = defineCollection({
  loader: glob({
    pattern: ['**/*.md', '**/*.mdx'],
    base: './src/content/posts',
    // English posts keep their usual id; a Turkish translation next to it
    // (name.tr.md) gets the same id under "tr/" so the two never collide.
    generateId: ({ entry, data }) => {
      const id =
        typeof data.slug === 'string' && data.slug
          ? data.slug
          : entry.replace(/\.(tr\.)?mdx?$/, '')
      return /\.tr\.mdx?$/.test(entry) ? `tr/${id}` : id
    },
  }),
  schema: ({ image }) =>
    z.object({
      title: z.string(),
      published: z.coerce.date(),
      // updated: z.coerce.date().optional(),
      draft: z.boolean().optional().default(false),
      description: z.string().optional(),
      author: z.string().optional(),
      series: z.string().optional(),
      tags: z.array(z.string()).optional().default([]),
      coverImage: z
        .strictObject({
          src: image(),
          alt: z.string(),
        })
        .optional(),
      toc: z.boolean().optional().default(true),
    }),
})

const homeCollection = defineCollection({
  loader: glob({
    pattern: ['home.md', 'home.mdx', 'home.tr.md', 'home.tr.mdx'],
    base: './src/content',
    // One entry per language, with the language as its id
    generateId: ({ entry }) => (/\.tr\.mdx?$/.test(entry) ? 'tr' : 'en'),
  }),
  schema: ({ image }) =>
    z.object({
      avatarImage: z
        .object({
          src: image(),
          alt: z.string().optional().default('My avatar'),
        })
        .optional(),
      githubCalendar: z.string().optional(), // GitHub username for calendar
    }),
})

const addendumCollection = defineCollection({
  loader: glob({
    pattern: ['addendum.md', 'addendum.mdx', 'addendum.tr.md', 'addendum.tr.mdx'],
    base: './src/content',
    // One entry per language, with the language as its id
    generateId: ({ entry }) => (/\.tr\.mdx?$/.test(entry) ? 'tr' : 'en'),
  }),
  schema: ({ image }) =>
    z.object({
      avatarImage: z
        .object({
          src: image(),
          alt: z.string().optional().default('My avatar'),
        })
        .optional(),
    }),
})

export const collections = {
  posts: postsCollection,
  home: homeCollection,
  addendum: addendumCollection,
}
