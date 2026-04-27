const seedSnapshots = [
  {
    id: "5f4e635f-d6d5-4ce4-a8ff-bf8d7184db11",
    versionNumber: 27,
    snapshotType: "manual_import",
    checksum:
      "0374c1e803e24d736cf3794e75a78aa994c10e269f54b07e405f4d52600f12fc",
    isActive: true,
    payloadJson: {
      bundle: {
        rules: { items: [{ id: "rule-1" }, { id: "rule-2" }] },
        zones: { items: [{ id: "zone-wan" }, { id: "zone-lan" }] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [{ id: "pair-wan-lan" }] },
        nat_rules: { items: [{ id: "nat-1" }] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [{ id: "ssl-1" }] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [{ id: "cert-1" }] },
        tls_inspection_policy: {
          block_ech_no_sni: true,
          block_all_ech: false,
          strip_ech_dns: true,
          log_ech_attempts: true,
          known_pinned_domains: [],
        },
        users: { items: [{ id: "user-1" }, { id: "user-2" }] },
      },
    },
    changeSummary: "Imported baseline config from staging",
    createdAt: "2026-04-23T12:03:40Z",
    createdBy: "bf80373d-7e8a-4648-b02f-2fcc7d7d7674",
  },
  {
    id: "2ad0f406-cd66-4f94-9e3f-bcbc9af2f62f",
    versionNumber: 26,
    snapshotType: "rollback_point",
    checksum:
      "e5309542d4a8bbbf0fb98d89b8a3c791e8ee2ca41357f91650a73f6df90b0ece",
    isActive: false,
    payloadJson: {
      bundle: {
        rules: { items: [{ id: "rule-1" }] },
        zones: { items: [{ id: "zone-wan" }, { id: "zone-lan" }] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [{ id: "pair-wan-lan" }] },
        nat_rules: { items: [{ id: "nat-legacy" }] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [{ id: "cert-1" }] },
        tls_inspection_policy: {
          block_ech_no_sni: true,
          block_all_ech: false,
          strip_ech_dns: false,
          log_ech_attempts: true,
          known_pinned_domains: ["bank.example"],
        },
        users: { items: [{ id: "user-1" }] },
      },
    },
    changeSummary: "Rollback point before policy engine update",
    createdAt: "2026-04-22T22:15:12Z",
    createdBy: "25dc46e4-c0c8-4306-86c6-f7a9c7f54857",
  },
  {
    id: "87498e5b-e6ad-4ef7-b1d9-f6439ff6ec96",
    versionNumber: 25,
    snapshotType: "auto_save",
    checksum:
      "704f7598ca45f8f6099fcf57fd7ef0e4f13c4a1648f44f0ee6bf7106fd7bc4ff",
    isActive: false,
    payloadJson: {
      bundle: {
        rules: { items: [{ id: "rule-1" }] },
        zones: { items: [{ id: "zone-wan" }] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [] },
        nat_rules: { items: [] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [] },
        tls_inspection_policy: {
          block_ech_no_sni: true,
          block_all_ech: false,
          strip_ech_dns: true,
          log_ech_attempts: true,
          known_pinned_domains: [],
        },
        users: { items: [{ id: "user-1" }] },
      },
    },
    changeSummary: "Auto save from nightly maintenance",
    createdAt: "2026-04-22T02:10:01Z",
    createdBy: "8a644f16-0b5f-4ec8-9f79-30a1d0e0f942",
  },
];

let snapshots = [...seedSnapshots].sort((a, b) => b.versionNumber - a.versionNumber);

const state = {
  tab: "apply",
  filter: "all",
  search: "",
  selectedId: snapshots[0]?.id ?? null,
};

const historyRows = document.getElementById("historyRows");
const historySearch = document.getElementById("historySearch");
const activeVersion = document.getElementById("activeVersion");
const snapshotCount = document.getElementById("snapshotCount");
const lastUpdate = document.getElementById("lastUpdate");
const selectedSnapshotId = document.getElementById("selectedSnapshotId");
const detailVersion = document.getElementById("detailVersion");
const detailType = document.getElementById("detailType");
const detailActive = document.getElementById("detailActive");
const detailCreatedAt = document.getElementById("detailCreatedAt");
const detailSummary = document.getElementById("detailSummary");
const payloadPreview = document.getElementById("payloadPreview");
const applyPanel = document.getElementById("applyPanel");
const applySnapshotType = document.getElementById("applySnapshotType");
const applyIsActive = document.getElementById("applyIsActive");
const applyChangeSummary = document.getElementById("applyChangeSummary");
const applyPreview = document.getElementById("applyPreview");
const importPanel = document.getElementById("importPanel");
const importPayload = document.getElementById("importPayload");
const importValidation = document.getElementById("importValidation");
const fillFromSelected = document.getElementById("fillFromSelected");
const exportPreview = document.getElementById("exportPreview");
const refreshExport = document.getElementById("refreshExport");
const copyExport = document.getElementById("copyExport");
const rollbackPanel = document.getElementById("rollbackPanel");
const rollbackId = document.getElementById("rollbackId");
const rollbackSummary = document.getElementById("rollbackSummary");
const copyPayload = document.getElementById("copyPayload");
const toast = document.getElementById("toast");

function makeId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (char) => {
    const random = (Math.random() * 16) | 0;
    const value = char === "x" ? random : (random & 0x3) | 0x8;
    return value.toString(16);
  });
}

function makeChecksum() {
  const hex = "0123456789abcdef";
  let out = "";

  for (let index = 0; index < 64; index += 1) {
    out += hex[Math.floor(Math.random() * hex.length)];
  }

  return out;
}

function toPrettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function toShortId(value) {
  if (!value || value.length < 10) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function toShortChecksum(value) {
  if (!value || value.length < 18) return value;
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function toHumanDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString("pl-PL", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function getActiveSnapshot() {
  return snapshots.find((snapshot) => snapshot.isActive) ?? null;
}

function getSelectedSnapshot() {
  return snapshots.find((snapshot) => snapshot.id === state.selectedId) ?? null;
}

function getFilteredSnapshots() {
  const query = state.search.trim().toLowerCase();

  return snapshots.filter((snapshot) => {
    if (state.filter !== "all" && snapshot.snapshotType !== state.filter) return false;
    if (!query) return true;

    const text = [
      snapshot.id,
      snapshot.checksum,
      snapshot.createdBy,
      snapshot.changeSummary ?? "",
      String(snapshot.versionNumber),
    ]
      .join(" ")
      .toLowerCase();

    return text.includes(query);
  });
}

function showToast(message, type) {
  toast.textContent = message;
  toast.className = `toast show ${type}`;

  window.setTimeout(() => {
    toast.className = "toast";
  }, 1700);
}

function updateStatusBar() {
  const active = getActiveSnapshot();

  activeVersion.textContent = active ? `v${active.versionNumber}` : "-";
  snapshotCount.textContent = String(snapshots.length);
  lastUpdate.textContent = snapshots.length > 0 ? toHumanDate(snapshots[0].createdAt) : "-";
}

function renderHistory() {
  const filtered = getFilteredSnapshots();

  if (filtered.length === 0) {
    historyRows.innerHTML = "";
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="6" class="mono">No snapshots for current filter</td>`;
    historyRows.appendChild(row);
    return;
  }

  historyRows.innerHTML = "";

  filtered.forEach((snapshot) => {
    const row = document.createElement("tr");
    if (snapshot.id === state.selectedId) row.classList.add("is-active");

    row.innerHTML = `
      <td class="version mono">v${snapshot.versionNumber}</td>
      <td><span class="badge ${snapshot.snapshotType}">${snapshot.snapshotType}</span></td>
      <td class="mono" title="${snapshot.checksum}">${toShortChecksum(snapshot.checksum)}</td>
      <td>
        <span class="state ${snapshot.isActive ? "active" : "inactive"}">
          <span class="core"></span>
          ${snapshot.isActive ? "active" : "inactive"}
        </span>
      </td>
      <td class="mono">${toHumanDate(snapshot.createdAt)}</td>
      <td class="mono" title="${snapshot.createdBy}">${toShortId(snapshot.createdBy)}</td>
    `;

    row.addEventListener("click", () => {
      state.selectedId = snapshot.id;
      renderAll();
    });

    historyRows.appendChild(row);
  });
}

function renderDetails() {
  const selected = getSelectedSnapshot();

  if (!selected) {
    selectedSnapshotId.textContent = "No snapshot selected";
    detailVersion.textContent = "-";
    detailType.textContent = "-";
    detailActive.textContent = "-";
    detailCreatedAt.textContent = "-";
    detailSummary.textContent = "-";
    payloadPreview.textContent = "{}";
    return;
  }

  selectedSnapshotId.textContent = selected.id;
  detailVersion.textContent = `v${selected.versionNumber}`;
  detailType.textContent = selected.snapshotType;
  detailActive.textContent = selected.isActive ? "true" : "false";
  detailCreatedAt.textContent = selected.createdAt;
  detailSummary.textContent = selected.changeSummary || "null";
  payloadPreview.textContent = toPrettyJson(selected.payloadJson);
}

function renderApplyPreview() {
  const payload = {
    snapshotType: applySnapshotType.value,
    isActive: applyIsActive.checked,
    changeSummary: applyChangeSummary.value.trim() || null,
  };

  applyPreview.textContent = toPrettyJson(payload);
}

function renderRollbackSelect() {
  rollbackId.innerHTML = "";

  snapshots.forEach((snapshot) => {
    const option = document.createElement("option");
    option.value = snapshot.id;
    option.textContent = `v${snapshot.versionNumber} | ${snapshot.snapshotType} | ${toShortId(snapshot.id)}`;
    rollbackId.appendChild(option);
  });

  if (state.selectedId && snapshots.some((snapshot) => snapshot.id === state.selectedId)) {
    rollbackId.value = state.selectedId;
  }
}

function renderExportPreview() {
  const active = getActiveSnapshot();

  if (!active) {
    exportPreview.textContent = "No active snapshot available.";
    return;
  }

  const exportPayload = {
    id: active.id,
    versionNumber: active.versionNumber,
    snapshotType: active.snapshotType,
    checksum: active.checksum,
    isActive: active.isActive,
    payloadJson: active.payloadJson,
    changeSummary: active.changeSummary,
    createdAt: active.createdAt,
    createdBy: active.createdBy,
  };

  exportPreview.textContent = toPrettyJson(exportPayload);
}

function renderAll() {
  snapshots = [...snapshots].sort((a, b) => b.versionNumber - a.versionNumber);

  if (!state.selectedId || !snapshots.some((snapshot) => snapshot.id === state.selectedId)) {
    state.selectedId = snapshots[0]?.id ?? null;
  }

  updateStatusBar();
  renderHistory();
  renderDetails();
  renderRollbackSelect();
  renderExportPreview();
}

function writeToClipboard(text, onSuccessLabel) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard
      .writeText(text)
      .then(() => showToast(onSuccessLabel, "success"))
      .catch(() => showToast("Clipboard access denied", "error"));
    return;
  }

  const temp = document.createElement("textarea");
  temp.value = text;
  document.body.appendChild(temp);
  temp.select();
  document.execCommand("copy");
  document.body.removeChild(temp);
  showToast(onSuccessLabel, "success");
}

function validateImportSnapshot(payload) {
  const required = [
    "id",
    "versionNumber",
    "snapshotType",
    "checksum",
    "isActive",
    "payloadJson",
    "createdAt",
    "createdBy",
  ];

  for (const key of required) {
    if (!(key in payload)) {
      return `Missing required field: ${key}`;
    }
  }

  if (!["manual_import", "rollback_point", "auto_save"].includes(payload.snapshotType)) {
    return "snapshotType must be one of: manual_import, rollback_point, auto_save";
  }

  if (typeof payload.versionNumber !== "number" || !Number.isFinite(payload.versionNumber)) {
    return "versionNumber must be a number";
  }

  if (typeof payload.isActive !== "boolean") {
    return "isActive must be a boolean";
  }

  if (typeof payload.payloadJson !== "object" || payload.payloadJson === null) {
    return "payloadJson must be a JSON object";
  }

  if (typeof payload.id !== "string" || typeof payload.createdBy !== "string") {
    return "id and createdBy must be strings";
  }

  if (typeof payload.checksum !== "string") {
    return "checksum must be a string";
  }

  return null;
}

function seedImportPayload() {
  const selected = getSelectedSnapshot() || getActiveSnapshot();
  if (!selected) {
    importPayload.value = "{}";
    return;
  }

  const data = {
    id: selected.id,
    versionNumber: selected.versionNumber,
    snapshotType: selected.snapshotType,
    checksum: selected.checksum,
    isActive: selected.isActive,
    payloadJson: selected.payloadJson,
    changeSummary: selected.changeSummary,
    createdAt: selected.createdAt,
    createdBy: selected.createdBy,
  };

  importPayload.value = toPrettyJson(data);
}

function switchTab(tab) {
  state.tab = tab;

  document.querySelectorAll(".op-tab").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.tab === tab);
  });

  document.querySelectorAll(".op-panel").forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.panel === tab);
  });
}

document.querySelectorAll(".op-tab").forEach((button) => {
  button.addEventListener("click", () => switchTab(button.dataset.tab));
});

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    state.filter = chip.dataset.filter;
    document.querySelectorAll(".chip").forEach((item) => {
      item.classList.toggle("is-active", item.dataset.filter === state.filter);
    });
    renderHistory();
  });
});

historySearch.addEventListener("input", (event) => {
  state.search = event.target.value;
  renderHistory();
});

applySnapshotType.addEventListener("change", renderApplyPreview);
applyIsActive.addEventListener("change", renderApplyPreview);
applyChangeSummary.addEventListener("input", renderApplyPreview);

applyPanel.addEventListener("submit", (event) => {
  event.preventDefault();

  const payload = {
    snapshotType: applySnapshotType.value,
    isActive: applyIsActive.checked,
    changeSummary: applyChangeSummary.value.trim() || null,
  };

  const maxVersion = snapshots.reduce((max, snapshot) => Math.max(max, snapshot.versionNumber), 0);
  const active = getActiveSnapshot();

  if (payload.isActive) {
    snapshots = snapshots.map((snapshot) => ({ ...snapshot, isActive: false }));
  }

  const newSnapshot = {
    id: makeId(),
    versionNumber: maxVersion + 1,
    snapshotType: payload.snapshotType,
    checksum: makeChecksum(),
    isActive: payload.isActive,
    payloadJson: active ? active.payloadJson : { bundle: {} },
    changeSummary: payload.changeSummary,
    createdAt: new Date().toISOString(),
    createdBy: "e9fcb7d9-f7c1-4fe4-a5af-7f95402017f5",
  };

  snapshots.unshift(newSnapshot);
  state.selectedId = newSnapshot.id;
  rollbackSummary.value = "";

  renderApplyPreview();
  renderAll();
  showToast("Snapshot applied", "success");
});

fillFromSelected.addEventListener("click", () => {
  seedImportPayload();
  importValidation.textContent = "Loaded snapshot structure";
  importValidation.className = "hint";
});

importPanel.addEventListener("submit", (event) => {
  event.preventDefault();

  let parsed;

  try {
    parsed = JSON.parse(importPayload.value);
  } catch {
    importValidation.textContent = "Invalid JSON format";
    importValidation.className = "hint error";
    return;
  }

  const validationError = validateImportSnapshot(parsed);
  if (validationError) {
    importValidation.textContent = validationError;
    importValidation.className = "hint error";
    return;
  }

  const maxVersion = snapshots.reduce((max, snapshot) => Math.max(max, snapshot.versionNumber), 0);

  if (parsed.isActive) {
    snapshots = snapshots.map((snapshot) => ({ ...snapshot, isActive: false }));
  }

  const importedSnapshot = {
    id: makeId(),
    versionNumber: maxVersion + 1,
    snapshotType: parsed.snapshotType,
    checksum: parsed.checksum || makeChecksum(),
    isActive: parsed.isActive,
    payloadJson: parsed.payloadJson,
    changeSummary: parsed.changeSummary || "Imported config via API",
    createdAt: new Date().toISOString(),
    createdBy: "e9fcb7d9-f7c1-4fe4-a5af-7f95402017f5",
  };

  snapshots.unshift(importedSnapshot);
  state.selectedId = importedSnapshot.id;
  importValidation.textContent = "Snapshot imported";
  importValidation.className = "hint success";

  renderAll();
  showToast("Snapshot imported", "success");
});

refreshExport.addEventListener("click", () => {
  renderExportPreview();
  showToast("Export refreshed", "success");
});

copyExport.addEventListener("click", () => {
  writeToClipboard(exportPreview.textContent, "Export copied");
});

rollbackPanel.addEventListener("submit", (event) => {
  event.preventDefault();

  const targetId = rollbackId.value;
  const target = snapshots.find((snapshot) => snapshot.id === targetId);

  if (!target) {
    showToast("Snapshot not found", "error");
    return;
  }

  snapshots = snapshots.map((snapshot) => ({
    ...snapshot,
    isActive: snapshot.id === targetId,
  }));

  if (rollbackSummary.value.trim()) {
    target.changeSummary = rollbackSummary.value.trim();
  }

  state.selectedId = targetId;

  renderAll();
  showToast("Rollback executed", "success");
});

copyPayload.addEventListener("click", () => {
  writeToClipboard(payloadPreview.textContent, "Payload copied");
});

seedImportPayload();
renderApplyPreview();
renderAll();
