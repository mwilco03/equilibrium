import type { VendorDetection } from "@/types/equilibrium";
import { ShieldCheck, AlertTriangle } from "lucide-react";

const CONFIDENCE_TONE: Record<VendorDetection["confidence"], string> = {
  low: "bg-amber-900/40 text-amber-300",
  medium: "bg-cyan-900/40 text-cyan-300",
  high: "bg-emerald-900/40 text-emerald-300",
};

export function VendorDetectionBlock({ vd }: { vd: VendorDetection }) {
  return (
    <details className="rounded border border-zinc-800 bg-zinc-900/40">
      <summary className="flex cursor-pointer items-center gap-3 p-3 hover:bg-zinc-900">
        <ShieldCheck className="h-4 w-4 text-cyan-400" aria-hidden />
        <span className="font-mono text-xs uppercase text-zinc-400">{vd.vendor}</span>
        <span className="font-medium">{vd.title}</span>
        <span
          className={`ml-auto rounded px-2 py-0.5 text-xs ${CONFIDENCE_TONE[vd.confidence]}`}
        >
          {vd.confidence}
        </span>
      </summary>
      <div className="flex flex-col gap-3 border-t border-zinc-800 p-3">
        <div className="text-sm text-zinc-300">{vd.intent}</div>

        <pre className="overflow-x-auto rounded bg-zinc-950 p-3 text-xs">
          <code>{vd.query}</code>
        </pre>

        <div className="grid grid-cols-1 gap-3 text-sm md:grid-cols-2">
          <FieldList label="Required telemetry" items={vd.required_telemetry} />
          <FieldList label="Mapped data components" items={vd.mapped_data_components} />
        </div>

        {vd.false_positive_considerations ? (
          <Note tone="warn" label="False-positive considerations">
            {vd.false_positive_considerations}
          </Note>
        ) : null}
        {vd.limitations ? (
          <Note tone="warn" label="Limitations">{vd.limitations}</Note>
        ) : null}

        {vd.references && vd.references.length > 0 ? (
          <div>
            <div className="text-xs uppercase tracking-wide text-zinc-500">References</div>
            <ul className="mt-1 flex flex-col gap-1 text-sm">
              {vd.references.map((url) => (
                <li key={url}>
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="break-all text-cyan-400 hover:underline"
                  >
                    {url}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </details>
  );
}

function FieldList({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-zinc-500">{label}</div>
      <ul className="mt-1 list-disc pl-5 text-zinc-200">
        {items.map((it) => (
          <li key={it}>{it}</li>
        ))}
      </ul>
    </div>
  );
}

function Note({
  tone,
  label,
  children,
}: {
  tone: "warn" | "info";
  label: string;
  children: React.ReactNode;
}) {
  const Icon = tone === "warn" ? AlertTriangle : ShieldCheck;
  return (
    <div className="flex items-start gap-2 rounded border border-zinc-800 bg-zinc-950 p-2 text-sm text-zinc-300">
      <Icon className="mt-0.5 h-4 w-4 text-amber-400" aria-hidden />
      <div>
        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-400">
          {label}
        </div>
        <div>{children}</div>
      </div>
    </div>
  );
}
