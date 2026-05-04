import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { runSearch, type SearchHit } from "@/lib/orama";
import { Search } from "lucide-react";

export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const initial = params.get("q") ?? "";
  const [term, setTerm] = useState(initial);
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!term.trim()) {
      setHits([]);
      return;
    }
    setLoading(true);
    runSearch(term)
      .then((r) => {
        if (!cancelled) setHits(r);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [term]);

  return (
    <div className="mx-auto flex max-w-screen-xl flex-col gap-4 p-4 sm:p-6">
      <div className="flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900 px-3 py-2">
        <Search className="h-4 w-4 text-zinc-400" aria-hidden />
        <input
          autoFocus
          value={term}
          onChange={(e) => {
            setTerm(e.target.value);
            setParams(e.target.value ? { q: e.target.value } : {}, { replace: true });
          }}
          placeholder="Search techniques, queries, data components..."
          className="w-full bg-transparent outline-none"
        />
      </div>

      {error ? <div className="text-red-400">{error}</div> : null}
      {loading ? <div className="text-zinc-400">Searching...</div> : null}

      <ul className="flex flex-col gap-2">
        {hits.map((h) => (
          <li
            key={h.id}
            className="rounded border border-zinc-800 bg-zinc-900/60 p-3 hover:border-cyan-500"
          >
            <Link to={`/techniques/${h.document.technique_id}`} className="block">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-zinc-400">
                  {h.document.technique_id}
                </span>
                <span className="font-medium">{h.document.title}</span>
                <span className="ml-auto text-xs text-zinc-500">
                  score {h.score.toFixed(2)}
                </span>
              </div>
              <div className="mt-1 line-clamp-2 text-sm text-zinc-400">
                {h.document.description}
              </div>
            </Link>
          </li>
        ))}
        {!loading && term.trim() && hits.length === 0 ? (
          <li className="text-zinc-500">No results.</li>
        ) : null}
      </ul>
    </div>
  );
}
