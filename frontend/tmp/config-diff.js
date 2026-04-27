const snapshots = [
  {
    id: "5f4e635f-d6d5-4ce4-a8ff-bf8d7184db11",
    versionNumber: 27,
    checksum: "0374c1e803e24d736cf3794e75a78aa994c10e269f54b07e405f4d52600f12fc",
    createdAt: "2026-04-23T12:03:40Z",
  },
  {
    id: "2ad0f406-cd66-4f94-9e3f-bcbc9af2f62f",
    versionNumber: 26,
    checksum: "e5309542d4a8bbbf0fb98d89b8a3c791e8ee2ca41357f91650a73f6df90b0ece",
    createdAt: "2026-04-22T22:15:12Z",
  },
  {
    id: "87498e5b-e6ad-4ef7-b1d9-f6439ff6ec96",
    versionNumber: 25,
    checksum: "704f7598ca45f8f6099fcf57fd7ef0e4f13c4a1648f44f0ee6bf7106fd7bc4ff",
    createdAt: "2026-04-22T02:10:01Z",
  },
];

const diffFixtures = {
  "2ad0f406-cd66-4f94-9e3f-bcbc9af2f62f:5f4e635f-d6d5-4ce4-a8ff-bf8d7184db11": [
    {
      type: "added",
      section: "rules",
      path: "bundle.rules.items.rule-2",
      entityId: "rule-2",
      after: {
        id: "rule-2",
        name: "allow-dns-inspection",
        action: "allow",
        priority: 120,
        sourceZoneId: "zone-lan",
        destinationZoneId: "zone-wan",
      },
    },
    {
      type: "modified",
      section: "nat_rules",
      path: "bundle.nat_rules.items.nat-1.translatedAddress",
      entityId: "nat-1",
      before: "10.10.20.15",
      after: "10.10.20.25",
    },
    {
      type: "modified",
      section: "tls_inspection_policy",
      path: "bundle.tls_inspection_policy.strip_ech_dns",
      before: false,
      after: true,
    },
    {
      type: "removed",
      section: "ssl_bypass_list",
      path: "bundle.ssl_bypass_list.items.ssl-legacy-bank",
      entityId: "ssl-legacy-bank",
      before: {
        id: "ssl-legacy-bank",
        domain: "bank.example",
        reason: "temporary bypass",
      },
    },
    {
      type: "added",
      section: "users",
      path: "bundle.users.items.user-2",
      entityId: "user-2",
      after: {
        id: "user-2",
        username: "security.operator",
        role: "operator",
      },
    },
    {
      type: "modified",
      section: "firewall_certificates",
      path: "bundle.firewall_certificates.items.cert-1.expiresAt",
      entityId: "cert-1",
      before: "2026-05-01T00:00:00Z",
      after: "2027-05-01T00:00:00Z",
    },
  ],
  "87498e5b-e6ad-4ef7-b1d9-f6439ff6ec96:5f4e635f-d6d5-4ce4-a8ff-bf8d7184db11": [
    {
      type: "added",
      section: "zones",
      path: "bundle.zones.items.zone-lan",
      entityId: "zone-lan",
      after: { id: "zone-lan", name: "LAN", type: "trusted" },
    },
    {
      type: "added",
      section: "zone_pairs",
      path: "bundle.zone_pairs.items.pair-wan-lan",
      entityId: "pair-wan-lan",
      after: { id: "pair-wan-lan", sourceZoneId: "zone-lan", destinationZoneId: "zone-wan" },
    },
    {
      type: "added",
      section: "nat_rules",
      path: "bundle.nat_rules.items.nat-1",
      entityId: "nat-1",
      after: { id: "nat-1", name: "egress-snat", translatedAddress: "10.10.20.25" },
    },
    {
      type: "modified",
      section: "rules",
      path: "bundle.rules.items.rule-1.priority",
      entityId: "rule-1",
      before: 200,
      after: 100,
    },
    {
      type: "added",
      section: "ssl_bypass_list",
      path: "bundle.ssl_bypass_list.items.ssl-1",
      entityId: "ssl-1",
      after: { id: "ssl-1", domain: "updates.vendor.example", reason: "pinned client" },
    },
  ],
};

const state = {
  baseId: snapshots[1].id,
  targetId: snapshots[0].id,
  type: "modified",
  section: "all",
  search: "",
  selectedIndex: 0,
};

const elements = {
  baseSnapshot: document.getElementById("baseSnapshot"),
  targetSnapshot: document.getElementById("targetSnapshot"),
  endpointPreview: document.getElementById("endpointPreview"),
  statusBase: document.getElementById("statusBase"),
  statusTarget: document.getElementById("statusTarget"),
  baseId: document.getElementById("baseId"),
  baseVersion: document.getElementById("baseVersion"),
  baseCreated: document.getElementById("baseCreated"),
  baseChecksum: document.getElementById("baseChecksum"),
  targetId: document.getElementById("targetId"),
  targetVersion: document.getElementById("targetVersion"),
  targetCreated: document.getElementById("targetCreated"),
  targetChecksum: document.getElementById("targetChecksum"),
  addedCount: document.getElementById("addedCount"),
  modifiedCount: document.getElementById("modifiedCount"),
  removedCount: document.getElementById("removedCount"),
  sectionList: document.getElementById("sectionList"),
  changeRows: document.getElementById("changeRows"),
  changeCount: document.getElementById("changeCount"),
  changeSearch: document.getElementById("changeSearch"),
  selectedPath: document.getElementById("selectedPath"),
  detailType: document.getElementById("detailType"),
  detailSection: document.getElementById("detailSection"),
  detailEntity: document.getElementById("detailEntity"),
  unifiedDiff: document.getElementById("unifiedDiff"),
};

function toShortId(value) {
  if (!value || value.length < 14) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function toShortChecksum(value) {
  if (!value || value.length < 20) return value;
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function toHumanDate(value) {
  return new Date(value).toLocaleString("pl-PL", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function toJson(value) {
  if (value === undefined) return "No value";
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function createDiffLine(type, marker, content) {
  const emptyClass = content === "No value" ? " empty" : "";
  return `
    <div class="diff-line ${type}${emptyClass}">
      <span class="diff-gutter">${marker}</span>
      <code class="diff-code">${escapeHtml(content)}</code>
    </div>
  `;
}

function buildUnifiedDiff(change) {
  const beforeLines = change.before === undefined ? [] : toJson(change.before).split("\n");
  const afterLines = change.after === undefined ? [] : toJson(change.after).split("\n");

  if (change.type === "added") {
    return afterLines.map((line) => createDiffLine("added", "+", line)).join("");
  }

  if (change.type === "removed") {
    return beforeLines.map((line) => createDiffLine("removed", "-", line)).join("");
  }

  const rows = [];
  const maxLength = Math.max(beforeLines.length, afterLines.length);

  for (let index = 0; index < maxLength; index += 1) {
    const beforeLine = beforeLines[index];
    const afterLine = afterLines[index];

    if (beforeLine === afterLine) {
      rows.push(createDiffLine("context", "", beforeLine ?? ""));
      continue;
    }

    if (beforeLine !== undefined) {
      rows.push(createDiffLine("removed", "-", beforeLine));
    }

    if (afterLine !== undefined) {
      rows.push(createDiffLine("added", "+", afterLine));
    }
  }

  return rows.join("");
}

function getSnapshot(id) {
  return snapshots.find((snapshot) => snapshot.id === id) ?? snapshots[0];
}

function getChanges() {
  const key = `${state.baseId}:${state.targetId}`;
  const reverseKey = `${state.targetId}:${state.baseId}`;

  if (diffFixtures[key]) return diffFixtures[key];
  if (!diffFixtures[reverseKey]) return [];

  return diffFixtures[reverseKey].map((change) => ({
    ...change,
    type: change.type === "added" ? "removed" : change.type === "removed" ? "added" : "modified",
    before: change.after,
    after: change.before,
  }));
}

function buildSummary(changes) {
  const summary = {
    added: 0,
    removed: 0,
    modified: 0,
    bySection: {},
  };

  changes.forEach((change) => {
    summary[change.type] += 1;
    summary.bySection[change.section] ??= { added: 0, removed: 0, modified: 0 };
    summary.bySection[change.section][change.type] += 1;
  });

  return summary;
}

function getFilteredChanges() {
  const search = state.search.trim().toLowerCase();

  return getChanges().filter((change) => {
    if (state.type !== "all" && change.type !== state.type) return false;
    if (state.section !== "all" && change.section !== state.section) return false;
    if (!search) return true;

    return [change.type, change.section, change.path, change.entityId ?? ""]
      .join(" ")
      .toLowerCase()
      .includes(search);
  });
}

function fillSnapshotSelects() {
  [elements.baseSnapshot, elements.targetSnapshot].forEach((select) => {
    select.innerHTML = "";

    snapshots.forEach((snapshot) => {
      const option = document.createElement("option");
      option.value = snapshot.id;
      option.textContent = `v${snapshot.versionNumber} | ${toShortId(snapshot.id)}`;
      select.appendChild(option);
    });
  });

  elements.baseSnapshot.value = state.baseId;
  elements.targetSnapshot.value = state.targetId;
}

function renderSnapshotMeta() {
  const base = getSnapshot(state.baseId);
  const target = getSnapshot(state.targetId);

  elements.statusBase.textContent = `v${base.versionNumber}`;
  elements.statusTarget.textContent = `v${target.versionNumber}`;
  elements.endpointPreview.textContent = `/config/diff?baseId=${base.id}&targetId=${target.id}`;

  elements.baseId.textContent = toShortId(base.id);
  elements.baseVersion.textContent = `v${base.versionNumber}`;
  elements.baseCreated.textContent = toHumanDate(base.createdAt);
  elements.baseChecksum.textContent = toShortChecksum(base.checksum);
  elements.baseChecksum.title = base.checksum;

  elements.targetId.textContent = toShortId(target.id);
  elements.targetVersion.textContent = `v${target.versionNumber}`;
  elements.targetCreated.textContent = toHumanDate(target.createdAt);
  elements.targetChecksum.textContent = toShortChecksum(target.checksum);
  elements.targetChecksum.title = target.checksum;
}

function renderSummary() {
  const summary = buildSummary(getChanges());
  elements.addedCount.textContent = String(summary.added);
  elements.modifiedCount.textContent = String(summary.modified);
  elements.removedCount.textContent = String(summary.removed);

  document.querySelectorAll(".total-card").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.type === state.type);
  });

  elements.sectionList.innerHTML = "";

  const allButton = document.createElement("button");
  allButton.type = "button";
  allButton.className = `section-row ${state.section === "all" ? "is-active" : ""}`;
  allButton.dataset.section = "all";
  allButton.innerHTML = `
    <strong>All sections</strong>
    <span>${getChanges().length} total</span>
  `;
  elements.sectionList.appendChild(allButton);

  Object.entries(summary.bySection)
    .sort(([left], [right]) => left.localeCompare(right))
    .forEach(([section, counts]) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = `section-row ${state.section === section ? "is-active" : ""}`;
      row.dataset.section = section;
      row.innerHTML = `
        <strong>${section}</strong>
        <div class="section-counts">
          <span class="pill added">+${counts.added}</span>
          <span class="pill modified">~${counts.modified}</span>
          <span class="pill removed">-${counts.removed}</span>
        </div>
      `;
      elements.sectionList.appendChild(row);
    });
}

function renderRows() {
  const filtered = getFilteredChanges();
  elements.changeCount.textContent = `${filtered.length} rows`;
  elements.changeRows.innerHTML = "";

  if (filtered.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="4" class="mono">No changes for current filter</td>`;
    elements.changeRows.appendChild(row);
    renderDetail(null);
    return;
  }

  if (state.selectedIndex >= filtered.length) {
    state.selectedIndex = 0;
  }

  filtered.forEach((change, index) => {
    const row = document.createElement("tr");
    row.className = index === state.selectedIndex ? "is-active" : "";
    row.innerHTML = `
      <td><span class="badge ${change.type}">${change.type}</span></td>
      <td class="mono">${change.section}</td>
      <td class="mono">${change.entityId ?? "-"}</td>
      <td class="mono path-cell" title="${change.path}">${change.path}</td>
    `;
    row.addEventListener("click", () => {
      state.selectedIndex = index;
      renderRows();
    });
    elements.changeRows.appendChild(row);
  });

  renderDetail(filtered[state.selectedIndex]);
}

function renderDetail(change) {
  if (!change) {
    elements.selectedPath.textContent = "No change selected";
    elements.detailType.textContent = "-";
    elements.detailSection.textContent = "-";
    elements.detailEntity.textContent = "-";
    elements.unifiedDiff.innerHTML = createDiffLine("context", "", "No value");
    return;
  }

  elements.selectedPath.textContent = change.path;
  elements.detailType.textContent = change.type;
  elements.detailSection.textContent = change.section;
  elements.detailEntity.textContent = change.entityId ?? "-";
  elements.unifiedDiff.innerHTML = buildUnifiedDiff(change);
}

function render() {
  renderSnapshotMeta();
  renderSummary();
  renderRows();

  document.querySelectorAll("[data-filter-type]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.filterType === state.type);
  });
}

elements.baseSnapshot.addEventListener("change", (event) => {
  state.baseId = event.target.value;
  state.selectedIndex = 0;
  render();
});

elements.targetSnapshot.addEventListener("change", (event) => {
  state.targetId = event.target.value;
  state.selectedIndex = 0;
  render();
});

elements.changeSearch.addEventListener("input", (event) => {
  state.search = event.target.value;
  state.selectedIndex = 0;
  renderRows();
});

document.querySelectorAll("[data-filter-type]").forEach((button) => {
  button.addEventListener("click", () => {
    state.type = button.dataset.filterType;
    state.selectedIndex = 0;
    render();
  });
});

document.querySelectorAll(".total-card").forEach((button) => {
  button.addEventListener("click", () => {
    state.type = button.dataset.type;
    state.selectedIndex = 0;
    render();
  });
});

elements.sectionList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-section]");
  if (!button) return;

  state.section = button.dataset.section;
  state.selectedIndex = 0;
  render();
});

fillSnapshotSelects();
render();
