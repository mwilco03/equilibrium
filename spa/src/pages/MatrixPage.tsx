import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { TECHNIQUES } from "@/lib/data";
import { FilterPanel } from "@/components/FilterPanel";
import { MatrixGrid } from "@/components/MatrixGrid";
import type { Vendor } from "@/types/equilibrium";

export function MatrixPage() {
  const [vendorFilter, setVendorFilter] = useState<Set<Vendor>>(new Set());
  const [dataComponentFilter, setDataComponentFilter] = useState("");
  const [mobileFiltersOpen, setMobileFiltersOpen] = useState(false);

  const filtered = useMemo(() => {
    return TECHNIQUES.filter((t) => {
      if (vendorFilter.size > 0) {
        const has = (t.vendor_detections ?? []).some((vd) => vendorFilter.has(vd.vendor));
        if (!has) return false;
      }
      if (dataComponentFilter.trim()) {
        const needle = dataComponentFilter.toLowerCase();
        const has = t.data_components.some((dc) =>
          dc.name.toLowerCase().includes(needle),
        );
        if (!has) return false;
      }
      return true;
    });
  }, [vendorFilter, dataComponentFilter]);

  const ChevronIcon = mobileFiltersOpen ? ChevronDown : ChevronRight;

  return (
    <div className="flex h-full flex-col md:flex-row">
      <button
        type="button"
        onClick={() => setMobileFiltersOpen((v) => !v)}
        className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900/60 px-4 py-3 text-sm md:hidden"
        aria-expanded={mobileFiltersOpen}
        aria-controls="filter-panel"
      >
        <ChevronIcon className="h-4 w-4" aria-hidden />
        Filters
        <span className="ml-2 text-zinc-500">
          {filtered.length} / {TECHNIQUES.length}
        </span>
      </button>

      <div
        id="filter-panel"
        className={(mobileFiltersOpen ? "block" : "hidden") + " md:block"}
      >
        <FilterPanel
          vendorFilter={vendorFilter}
          onToggleVendor={(v) => {
            const next = new Set(vendorFilter);
            if (next.has(v)) next.delete(v);
            else next.add(v);
            setVendorFilter(next);
          }}
          dataComponentFilter={dataComponentFilter}
          onDataComponentChange={setDataComponentFilter}
        />
      </div>

      <div className="flex-1 overflow-auto">
        <div className="hidden px-4 pt-4 text-sm text-zinc-400 md:block">
          {filtered.length} / {TECHNIQUES.length} techniques
        </div>
        <MatrixGrid techniques={filtered} />
      </div>
    </div>
  );
}
