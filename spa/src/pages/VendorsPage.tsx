import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { TECHNIQUES } from "@/lib/data";
import { VENDORS, type Vendor, type TechniqueRecord, type VendorDetection } from "@/types/equilibrium";

interface PerVendor {
  vendor: Vendor;
  detections: { t: TechniqueRecord; vd: VendorDetection }[];
}

function aggregate(): PerVendor[] {
  return VENDORS.map((vendor) => {
    const detections: PerVendor["detections"] = [];
    for (const t of TECHNIQUES) {
      for (const vd of t.vendor_detections ?? []) {
        if (vd.vendor === vendor) detections.push({ t, vd });
      }
    }
    return { vendor, detections };
  });
}

export function VendorsPage() {
  const rows = aggregate();
  const total = rows.reduce((s, r) => s + r.detections.length, 0);

  return (
    <div className="mx-auto flex max-w-screen-xl flex-col gap-4 p-4 sm:p-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-xl font-semibold sm:text-2xl">Vendors</h1>
        <p className="text-sm text-zinc-400">
          Vendor coverage across the equilibrium corpus. {total} detections across{" "}
          {VENDORS.length} vendor enum entries. A vendor with zero detections shows
          where the matrix has documented gaps.
        </p>
      </header>

      <div className="grid gap-3 md:grid-cols-2">
        {rows.map((r) => (
          <article
            key={r.vendor}
            className="flex flex-col gap-2 rounded border border-zinc-800 bg-zinc-900/60 p-3"
          >
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-400" aria-hidden />
              <span className="font-mono text-sm uppercase">{r.vendor}</span>
              <span className="ml-auto text-xs text-zinc-500">
                {r.detections.length} detection
                {r.detections.length === 1 ? "" : "s"}
              </span>
            </div>
            {r.detections.length === 0 ? (
              <div className="rounded border border-dashed border-zinc-800 p-3 text-xs text-zinc-500">
                No detections yet. Open an "Add vendor detection" issue to contribute one.
              </div>
            ) : (
              <ul className="flex flex-col gap-1 text-sm">
                {r.detections.map(({ t, vd }, i) => (
                  <li key={`${t.id}-${i}`}>
                    <Link
                      to={`/techniques/${t.id}`}
                      className="flex flex-col rounded px-2 py-1 hover:bg-zinc-800"
                    >
                      <span className="font-mono text-xs text-zinc-500">
                        {t.microsoft_k8s_matrix.id ?? t.id}
                        {t.mitre_attack ? ` · ${t.mitre_attack.technique_id}` : ""}
                      </span>
                      <span>{vd.title}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </article>
        ))}
      </div>
    </div>
  );
}
