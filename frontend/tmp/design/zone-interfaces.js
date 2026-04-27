const zones = [
  { id: "zone-core", name: "Core" },
  { id: "zone-dmz", name: "DMZ" },
  { id: "zone-users", name: "Users" },
  { id: "zone-guest", name: "Guest" },
  { id: "zone-admin", name: "Admin" },
  { id: "zone-lab", name: "Lab" },
  { id: "zone-iot", name: "IoT" },
];

const zoneInterfaces = [
  {
    id: "9f3a4a41-5932-42dd-91e1-f2f8100d1d1a",
    zoneId: "zone-core",
    zoneName: "Core",
    interfaceName: "bond0.20",
    vlanId: 20,
    status: "active",
    addresses: ["10.20.0.1/24", "fd20::1/64"],
    observedAt: "14:32:08",
  },
  {
    id: "07de09d4-ff4a-426f-9d0c-4a85cf148617",
    zoneId: "zone-dmz",
    zoneName: "DMZ",
    interfaceName: "ens192.40",
    vlanId: 40,
    status: "active",
    addresses: ["172.16.40.1/24"],
    observedAt: "14:32:07",
  },
  {
    id: "529d8980-77c4-43d1-86e9-372791f34a8e",
    zoneId: "zone-users",
    zoneName: "Users",
    interfaceName: "ens224.70",
    vlanId: 70,
    status: "active",
    addresses: ["10.70.0.1/23"],
    observedAt: "14:32:07",
  },
  {
    id: "d77bca1b-2e28-4186-84a8-777a7a6c4b79",
    zoneId: "zone-guest",
    zoneName: "Guest",
    interfaceName: "wlan0.90",
    vlanId: 90,
    status: "inactive",
    addresses: [],
    observedAt: "14:31:58",
  },
  {
    id: "5f8b9425-d57f-4c92-bd44-9a5ed7a50e16",
    zoneId: "zone-admin",
    zoneName: "Admin",
    interfaceName: "mgmt0",
    vlanId: null,
    status: "active",
    addresses: ["192.168.10.1/24"],
    observedAt: "14:32:08",
  },
  {
    id: "631dbd7f-7d5d-41d7-bde3-2f8e020b9125",
    zoneId: "zone-lab",
    zoneName: "Lab",
    interfaceName: "ens256.120",
    vlanId: 120,
    status: "missing",
    addresses: ["10.120.0.1/24"],
    observedAt: "14:29:42",
  },
  {
    id: "f91272c8-3414-4fb5-8dcf-44824d9f9b27",
    zoneId: "zone-iot",
    zoneName: "IoT",
    interfaceName: "ens224.110",
    vlanId: 110,
    status: "unknown",
    addresses: ["10.110.0.1/24"],
    observedAt: "14:30:11",
  },
];

const state = {
  filter: "all",
  search: "",
  editingId: null,
  editActive: true,
};

const body = document.querySelector("#interfacesBody");
const emptyTemplate = document.querySelector("#emptyTemplate");
const signalRail = document.querySelector("#signalRail");
const search = document.querySelector("#interfaceSearch");
const segments = document.querySelectorAll(".segment");
const refreshButton = document.querySelector("#refreshButton");
const drawer = document.querySelector("#editDrawer");
const backdrop = document.querySelector("#editBackdrop");
const drawerClose = document.querySelector("#drawerClose");
const cancelEdit = document.querySelector("#cancelEdit");
const form = document.querySelector("#interfaceForm");
const zoneSelect = document.querySelector("#zoneSelect");
const vlanInput = document.querySelector("#vlanInput");
const ipInput = document.querySelector("#ipInput");
const maskInput = document.querySelector("#maskInput");
const activeToggle = document.querySelector("#activeToggle");

function shortId(id) {
  return id.length > 8 ? `${id.slice(0, 8)}...` : id;
}

function statusClass(status) {
  if (status === "active" || status === "missing" || status === "unknown") {
    return status;
  }

  return "inactive";
}

function matchesFilter(item) {
  if (state.filter !== "all" && item.status !== state.filter) return false;

  const term = state.search.trim().toLowerCase();
  if (!term) return true;

  return [
    item.interfaceName,
    item.zoneName,
    item.zoneId,
    item.status,
    String(item.vlanId ?? "untagged"),
    ...item.addresses,
  ].some((value) => value.toLowerCase().includes(term));
}

function makeAddressList(addresses) {
  if (addresses.length === 0) {
    return '<span class="address-chip">no address</span>';
  }

  return addresses
    .map((address) => `<span class="address-chip">${address}</span>`)
    .join("");
}

function splitAddress(addresses) {
  const first = addresses[0] ?? "";
  const [ip = "", mask = ""] = first.split("/");

  return { ip, mask };
}

function addressFromFields() {
  const ip = ipInput.value.trim();
  const mask = maskInput.value.trim();

  if (!ip || !mask) return [];

  return [`${ip}/${mask}`];
}

function findZone(zoneId) {
  return zones.find((zone) => zone.id === zoneId) ?? zones[0];
}

function setActiveToggle(active) {
  state.editActive = active;
  activeToggle.classList.toggle("active", active);
  activeToggle.setAttribute("aria-pressed", String(active));
}

function updatePreview() {
  const item = zoneInterfaces.find((entry) => entry.id === state.editingId);
  const zone = findZone(zoneSelect.value);
  const addresses = addressFromFields();
  const active = state.editActive;

  document.querySelector("#previewInterface").textContent =
    item?.interfaceName ?? "--";
  document.querySelector("#previewStatus").textContent = active
    ? "ACTIVE"
    : "INACTIVE";
  document.querySelector("#previewStatus").style.color = active
    ? "var(--green)"
    : "var(--dim)";
  document.querySelector("#previewZone").textContent = zone.name;
  document.querySelector("#previewAddress").textContent =
    addresses[0] ?? "no address";
}

function openEditor(id) {
  const item = zoneInterfaces.find((entry) => entry.id === id);
  if (!item) return;

  const { ip, mask } = splitAddress(item.addresses);

  state.editingId = id;
  zoneSelect.value = item.zoneId;
  vlanInput.value = item.vlanId === null ? "" : String(item.vlanId);
  ipInput.value = ip;
  maskInput.value = mask;
  setActiveToggle(item.status === "active");
  document.querySelector("#drawerSubtitle").textContent =
    `${item.interfaceName} / ${shortId(item.id)}`;
  updatePreview();

  drawer.classList.add("open");
  backdrop.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
}

function closeEditor() {
  state.editingId = null;
  drawer.classList.remove("open");
  backdrop.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
}

function renderTable(items) {
  body.replaceChildren();

  if (items.length === 0) {
    body.append(emptyTemplate.content.cloneNode(true));
    return;
  }

  const rows = items.map((item) => {
    const tr = document.createElement("tr");
    const klass = statusClass(item.status);

    tr.innerHTML = `
      <td>
        <span class="status-pill">
          <span class="status-dot ${klass}"></span>
          <span class="status-text ${klass}">${item.status}</span>
        </span>
      </td>
      <td>
        <div class="interface-name">${item.interfaceName}</div>
        <div class="interface-id">${item.zoneId}</div>
      </td>
      <td><span class="zone-chip">${item.zoneName}</span></td>
      <td><span class="vlan ${item.vlanId === null ? "none" : ""}">${item.vlanId === null ? "untagged" : `VLAN ${item.vlanId}`}</span></td>
      <td><div class="address-list">${makeAddressList(item.addresses)}</div></td>
      <td><span class="id-chip" title="${item.id}">${shortId(item.id)}</span></td>
      <td><span class="observed">${item.observedAt}</span></td>
      <td>
        <button type="button" class="row-action" data-edit-id="${item.id}" aria-label="Edit ${item.interfaceName}" title="Edit interface">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 20h9"></path>
            <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"></path>
          </svg>
        </button>
      </td>
    `;

    return tr;
  });

  body.append(...rows);
}

function renderZoneSelect() {
  zoneSelect.replaceChildren();

  zones.forEach((zone) => {
    const option = document.createElement("option");
    option.value = zone.id;
    option.textContent = zone.name;
    zoneSelect.append(option);
  });
}

function renderRail(items) {
  signalRail.replaceChildren();

  zoneInterfaces.forEach((item) => {
    const visible = items.includes(item);
    const row = document.createElement("div");
    row.className = "rail-item";
    row.style.opacity = visible ? "1" : "0.28";

    row.innerHTML = `
      <span class="rail-led ${statusClass(item.status)}"></span>
      <span>${item.interfaceName}</span>
      <span class="rail-zone">${item.zoneName}</span>
    `;

    signalRail.append(row);
  });
}

function renderMetrics(items) {
  const total = zoneInterfaces.length;
  const active = zoneInterfaces.filter((item) => item.status === "active").length;
  const missing = zoneInterfaces.filter((item) => item.status === "missing").length;
  const addressed = zoneInterfaces.filter((item) => item.addresses.length > 0).length;
  const vlans = zoneInterfaces
    .map((item) => item.vlanId)
    .filter((vlanId) => vlanId !== null);
  const activeRatio = Math.round((active / total) * 100);
  const addressedRatio = Math.round((addressed / total) * 100);

  document.querySelector("#totalCount").textContent = total;
  document.querySelector("#activeCount").textContent = active;
  document.querySelector("#missingCount").textContent = missing;
  document.querySelector("#filteredCount").textContent = items.length;
  document.querySelector("#linkRatio").textContent = activeRatio;
  document.querySelector("#addressedCount").textContent = addressed;
  document.querySelector("#vlanCount").textContent = vlans.length;
  document.querySelector("#linkMeter").style.width = `${activeRatio}%`;
  document.querySelector("#addressedMeter").style.width = `${addressedRatio}%`;

  const vlanStack = document.querySelector("#vlanStack");
  vlanStack.replaceChildren();
  [...new Set(vlans)].forEach((vlanId) => {
    const chip = document.createElement("span");
    chip.className = "vlan-chip";
    chip.textContent = vlanId;
    vlanStack.append(chip);
  });
}

function render() {
  const visible = zoneInterfaces.filter(matchesFilter);

  renderMetrics(visible);
  renderTable(visible);
  renderRail(visible);
}

function syncClock() {
  document.querySelector("#lastSync").textContent = new Date().toLocaleTimeString(
    "en-GB",
    { hour12: false },
  );
}

segments.forEach((segment) => {
  segment.addEventListener("click", () => {
    segments.forEach((item) => item.classList.remove("active"));
    segment.classList.add("active");
    state.filter = segment.dataset.filter;
    render();
  });
});

search.addEventListener("input", () => {
  state.search = search.value;
  render();
});

body.addEventListener("click", (event) => {
  const button = event.target.closest("[data-edit-id]");
  if (!button) return;

  openEditor(button.dataset.editId);
});

activeToggle.addEventListener("click", () => {
  setActiveToggle(!state.editActive);
  updatePreview();
});

[zoneSelect, vlanInput, ipInput, maskInput].forEach((field) => {
  field.addEventListener("input", updatePreview);
  field.addEventListener("change", updatePreview);
});

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const item = zoneInterfaces.find((entry) => entry.id === state.editingId);
  if (!item) return;

  const zone = findZone(zoneSelect.value);
  const vlan = vlanInput.value.trim();

  item.zoneId = zone.id;
  item.zoneName = zone.name;
  item.vlanId = vlan === "" ? null : Number(vlan);
  item.addresses = addressFromFields();
  item.status = state.editActive ? "active" : "inactive";
  item.observedAt = new Date().toLocaleTimeString("en-GB", { hour12: false });

  syncClock();
  closeEditor();
  render();
});

[drawerClose, cancelEdit, backdrop].forEach((element) => {
  element.addEventListener("click", closeEditor);
});

refreshButton.addEventListener("click", () => {
  refreshButton.classList.add("syncing");
  syncClock();
  window.setTimeout(() => refreshButton.classList.remove("syncing"), 700);
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
  });
});

renderZoneSelect();
syncClock();
render();
