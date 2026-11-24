import { promises as fs } from "fs";
import path from "path";

const KB_ROOT = path.resolve(process.env.KB_DIR ?? "./kb");

export async function readKbArticle(slug: string) {
  const full = path.resolve(KB_ROOT, `${slug}.md`);
  if (!full.startsWith(KB_ROOT + path.sep)) throw new Error("outside knowledge base");
  return fs.readFile(full, "utf8");
}

export async function exportReport(outputPath: string, rows: unknown[]) {
  await fs.writeFile(outputPath, JSON.stringify(rows, null, 2));
  return `saved ${rows.length} rows to ${outputPath}`;
}
