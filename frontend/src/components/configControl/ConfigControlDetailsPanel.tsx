import type { ConfigSnapshot } from "./types";

type ConfigControlDetailsPanelProps = {
  snapshot: ConfigSnapshot;
};

export default function ConfigControlDetailsPanel({
  snapshot,
}: ConfigControlDetailsPanelProps) {
  console.log(snapshot);

  return (
    <section className="bg-[#161616] border border-[#262626] mt-4">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[#262626]">
        <span className="text-[12px] tracking-[0.22em] uppercase">
          Snapshot Details
        </span>
        <span className="text-[10px] text-[#4a4a4a] tracking-[0.12em]">
          {snapshot.id}
        </span>
      </div>

      <div className="p-5 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
        <div className="bg-[#111] border border-[#262626] px-3 py-2.5">
          <div className="text-[10px] text-[#4a4a4a] tracking-[0.16em] uppercase">
            Version
          </div>
          <div className="text-base font-mono mt-1">
            v{snapshot.versionNumber}
          </div>
        </div>

        <div className="bg-[#111] border border-[#262626] px-3 py-2.5">
          <div className="text-[10px] text-[#4a4a4a] tracking-[0.16em] uppercase">
            snapshotType
          </div>
          <div className="text-base font-mono mt-1">
            {snapshot.snapshotType}
          </div>
        </div>

        <div className="bg-[#111] border border-[#262626] px-3 py-2.5">
          <div className="text-[10px] text-[#4a4a4a] tracking-[0.16em] uppercase">
            isActive
          </div>
          <div className="text-base font-mono mt-1">
            {snapshot.isActive ? "true" : "false"}
          </div>
        </div>

        <div className="bg-[#111] border border-[#262626] px-3 py-2.5">
          <div className="text-[10px] text-[#4a4a4a] tracking-[0.16em] uppercase">
            createdAt
          </div>
          <div className="text-base font-mono mt-1 truncate">
            {snapshot.createdAt}
          </div>
        </div>

        <div className="bg-[#111] border border-[#262626] px-3 py-2.5 md:col-span-2 xl:col-span-4">
          <div className="text-[10px] text-[#4a4a4a] tracking-[0.16em] uppercase">
            changeSummary
          </div>
          <div className="text-base font-mono mt-1 text-[#8a8a8a]">
            {snapshot.changeSummary ?? "null"}
          </div>
        </div>
      </div>

      <div className="px-5 pb-5">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] text-[#4a4a4a] tracking-[0.16em] uppercase">
            payloadJson
          </span>
          <button
            type="button"
            className="border border-[#262626] text-[#8a8a8a] px-2.5 py-1 text-[10px] uppercase tracking-[0.14em] hover:text-[#f5f5f5] hover:border-[#8a8a8a] transition"
          >
            Copy
          </button>
        </div>

        <pre className="bg-[#0e0e0e] border border-[#262626] p-3 text-[11px] leading-5 text-[#b2c0c5] max-h-72 overflow-auto whitespace-pre-wrap">
          {JSON.stringify(snapshot.payloadJson, null, 2)}
        </pre>
      </div>
    </section>
  );
}
