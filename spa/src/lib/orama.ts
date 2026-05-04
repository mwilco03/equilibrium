// Loads the prebuilt Orama index that scripts/build-search-index.mjs writes
// to public/search-index.json at build time. Loaded lazily so the matrix
// page does not pay the index-load cost up front.

import { create, insertMultiple, search, type AnyOrama } from "@orama/orama";

export interface SearchHit {
  id: string;
  score: number;
  document: SearchDoc;
}

export interface SearchDoc {
  id: string;
  technique_id: string;
  title: string;
  description: string;
  tactic: string;
  ms_tactic: string;
  ms_name: string;
  vendors: string[];
  data_components: string[];
  query_blob: string;
}

let dbPromise: Promise<AnyOrama> | null = null;

const SEARCH_INDEX_URL = `${import.meta.env.BASE_URL}search-index.json`;

async function getDb(): Promise<AnyOrama> {
  if (dbPromise) return dbPromise;
  dbPromise = (async () => {
    const docs: SearchDoc[] = await fetch(SEARCH_INDEX_URL).then((r) => r.json());
    const db = create({
      schema: {
        id: "string",
        technique_id: "string",
        title: "string",
        description: "string",
        tactic: "string",
        ms_tactic: "string",
        ms_name: "string",
        vendors: "string[]",
        data_components: "string[]",
        query_blob: "string",
      },
    });
    await insertMultiple(db, docs);
    return db;
  })();
  return dbPromise;
}

export async function runSearch(term: string): Promise<SearchHit[]> {
  if (!term.trim()) return [];
  const db = await getDb();
  const result = await search(db, {
    term,
    properties: [
      "title",
      "description",
      "ms_name",
      "data_components",
      "query_blob",
    ],
    limit: 50,
  });
  return result.hits.map((h) => ({
    id: h.id as string,
    score: h.score,
    document: h.document as unknown as SearchDoc,
  }));
}
