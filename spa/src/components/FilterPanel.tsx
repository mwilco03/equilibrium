import { VENDORS, type Vendor } from "@/types/equilibrium";
import { Filter } from "lucide-react";

interface Props {
  vendorFilter: Set<Vendor>;
  onToggleVendor: (v: Vendor) => void;
  dataComponentFilter: string;
  onDataComponentChange: (s: string) => void;
}

export function FilterPanel({
  vendorFilter,
  onToggleVendor,
  dataComponentFilter,
  onDataComponentChange,
}: Props) {
  return (
    <aside className="flex flex-col gap-6 border-r border-zinc-800 bg-zinc-900/40 p-4 text-sm md:w-72">
      <div className="flex items-center gap-2 text-zinc-400">
        <Filter className="h-4 w-4" aria-hidden />
        <span>Filters</span>
      </div>

      <div>
        <label
          htmlFor="dc-filter"
          className="mb-1 block text-xs uppercase tracking-wide text-zinc-500"
        >
          Data component contains
        </label>
        <input
          id="dc-filter"
          type="text"
          value={dataComponentFilter}
          onChange={(e) => onDataComponentChange(e.target.value)}
          placeholder="e.g. Application Log"
          className="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 outline-none focus:border-cyan-500"
        />
      </div>

      <div>
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Vendor</div>
        <ul className="flex flex-col gap-1">
          {VENDORS.map((v) => (
            <li key={v}>
              <label className="flex cursor-pointer items-center gap-2 text-zinc-300 hover:text-zinc-100">
                <input
                  type="checkbox"
                  checked={vendorFilter.has(v)}
                  onChange={() => onToggleVendor(v)}
                  className="accent-cyan-500"
                />
                {v}
              </label>
            </li>
          ))}
        </ul>
      </div>
    </aside>
  );
}
