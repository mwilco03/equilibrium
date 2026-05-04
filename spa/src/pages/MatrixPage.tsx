import { useMemo, useState } from "react";
import { TECHNIQUES } from "@/lib/data";
import { FilterPanel } from "@/components/FilterPanel";
import { MatrixGrid } from "@/components/MatrixGrid";
import type { Vendor } from "@/types/equilibrium";

export function MatrixPage() {
  const [vendorFilter, setVendorFilter] = useState<Set<Vendor>>(new Set());
  const [dataComponentFilter, setDataComponentFilter] = useState("");

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

  return (
    <div className="flex h-full flex-col md:flex-row">
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
      <div className="flex-1 overflow-auto">
        <div className="px-4 pt-4 text-sm text-zinc-400">
          {filtered.length} / {TECHNIQUES.length} techniques
        </div>
        <MatrixGrid techniques={filtered} />
      </div>
    </div>
  );
}
