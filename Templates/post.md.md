<%*
let title = await tp.system.prompt("Post title", tp.file.title);
let slug = title.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
await tp.file.rename(slug);
tR += `---\n`;
tR += `title: ${title}\n`;
tR += `author: balpars\n`;
tR += `published: ${tp.date.now("YYYY-MM-DD")}\n`;
tR += `draft: true\n`;
tR += `vault: true\n`;
tR += `tags: ['test']\n`;
tR += `description: ""\n`;
tR += `toc: true\n`;
tR += `series: 'test'\n`;
tR += `---\n\n`;
tR += `## \n\n`;
-%>