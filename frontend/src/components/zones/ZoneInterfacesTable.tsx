import type { ZoneInterface } from "../../types/zones/ZoneInterface";

type ZoneInterfacesTableProps = {
  zoneInterfaces: ZoneInterface[];
  onEdit: (zoneInterface: ZoneInterface) => void;
};

const TABLE_HEADERS = [
  "Status",
  "Interface",
  "Zone",
  "VLAN",
  "Addresses",
  "ID",
  "Observed",
  "Actions",
];

function shortId(id: string) {
  return id.length > 8 ? id.slice(0, 8) + "…" : id;
}

function fmtDate(iso: string) {
  return new Date(iso).toISOString().split("T")[0];
}

function statusColor(status: ZoneInterface["status"]) {
  if (status === "active") return "text-[#10b981]";
  if (status === "missing") return "text-[#f43f5e]";
  if (status === "unknown") return "text-[#f59e0b]";

  return "text-[#8a8a8a]";
}

function statusDotColor(status: ZoneInterface["status"]) {
  if (status === "active") return "bg-[#10b981] shadow-[0_0_8px_rgba(16,185,129,0.85)]";
  if (status === "missing") return "bg-[#f43f5e] shadow-[0_0_8px_rgba(244,63,94,0.75)]";
  if (status === "unknown") return "bg-[#f59e0b]";

  return "bg-[#4a4a4a]";
}

function EmptyState() {
  return (
    <tr>
      <td colSpan={8} className="px-4 py-16 text-center">
        <div className="text-[#4a4a4a] text-sm tracking-[0.25em] uppercase mb-2">
          No matching interfaces
        </div>
        <div className="text-[#3a3a3a] text-xs">
          Adjust filter or sync state
        </div>
      </td>
    </tr>
  );
}

export default function ZoneInterfacesTable({
  zoneInterfaces,
  onEdit,
}: ZoneInterfacesTableProps) {
  return (
    <div className="bg-[#101010] border border-[#262626] overflow-x-auto">
      <table className="w-full min-w-[920px]">
        <thead>
          <tr className="bg-[#161616] border-b border-[#262626]">
            {TABLE_HEADERS.map((header) => (
              <th
                key={header}
                className="text-left p-4 text-xs text-[#8a8a8a] uppercase tracking-[0.2em] font-medium whitespace-nowrap"
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {zoneInterfaces.length === 0 && <EmptyState />}

          {zoneInterfaces.map((zoneInterface) => (
            <tr
              key={zoneInterface.id}
              className="border-b border-[#262626] last:border-b-0 hover:bg-[#1b1b1b] transition-colors"
            >
              <td className="p-4">
                <span
                  className={`inline-flex items-center gap-2 text-[10px] uppercase tracking-[0.14em] ${statusColor(zoneInterface.status)}`}
                >
                  <span
                    className={`w-2 h-2 rounded-full ${statusDotColor(zoneInterface.status)}`}
                  />
                  {zoneInterface.status}
                </span>
              </td>
              <td className="p-4">
                <div className="text-[#f5f5f5] text-sm font-bold">
                  {zoneInterface.interfaceName}
                </div>
                <div className="text-[#4a4a4a] text-[10px] mt-1">
                  {zoneInterface.zoneId}
                </div>
              </td>
              <td className="p-4">
                <span className="inline-flex min-w-24 border border-[#06b6d4]/25 bg-[#06b6d4]/5 px-2 py-1 text-xs text-[#f5f5f5]">
                  {zoneInterface.zoneId}
                </span>
              </td>
              <td className="p-4">
                <span
                  className={`text-xs ${zoneInterface.vlanId === null ? "text-[#4a4a4a]" : "text-[#06b6d4]"}`}
                >
                  {zoneInterface.vlanId === null
                    ? "untagged"
                    : `VLAN ${zoneInterface.vlanId}`}
                </span>
              </td>
              <td className="p-4">
                <div className="flex flex-wrap gap-1.5 max-w-[340px]">
                  {zoneInterface.addresses.length === 0 ? (
                    <span className="border border-[#06b6d4]/25 bg-[#06b6d4]/5 px-2 py-1 text-[10px] text-[#8a8a8a]">
                      no address
                    </span>
                  ) : (
                    zoneInterface.addresses.map((address) => (
                      <span
                        key={address}
                        className="border border-[#06b6d4]/25 bg-[#06b6d4]/5 px-2 py-1 text-[10px] text-[#8a8a8a]"
                      >
                        {address}
                      </span>
                    ))
                  )}
                </div>
              </td>
              <td className="p-4">
                <span
                  className="inline-flex border border-[#06b6d4]/25 bg-[#06b6d4]/5 px-2 py-1 text-[10px] text-[#8a8a8a]"
                  title={zoneInterface.id}
                >
                  {shortId(zoneInterface.id)}
                </span>
              </td>
              <td className="p-4">
                <span className="text-[#4a4a4a] text-xs">
                  {fmtDate(zoneInterface.createdAt)}
                </span>
              </td>
              <td className="p-4">
                <button
                  type="button"
                  onClick={() => onEdit(zoneInterface)}
                  className="px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-[#8a8a8a] border border-[#262626] hover:text-[#f5f5f5] hover:border-[#4a4a4a] transition-colors"
                >
                  Edit
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
