import type { Root, Element } from 'hast'
import { visit } from 'unist-util-visit'

// The page already shows the title as its only <h1>. Posts that use "#" for
// their sections would add more <h1>s, so in those documents every heading
// moves down one level (h1 -> h2, h2 -> h3, ...). The markdown stays as written.
export default function rehypeDemoteHeadings() {
  return (tree: Root) => {
    const headings: Element[] = []
    visit(tree, 'element', (node) => {
      if (/^h[1-6]$/.test(node.tagName)) headings.push(node)
    })
    if (!headings.some((node) => node.tagName === 'h1')) return
    for (const node of headings) {
      const level = Number(node.tagName[1])
      node.tagName = `h${Math.min(level + 1, 6)}`
    }
  }
}
