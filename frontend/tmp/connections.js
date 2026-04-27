const apiResponse = {
  statusCode: 200,
  message: "TCP sessions retrieved",
  data: {
    tcpSessions: [
      {
        endpointA: { ip: "10.0.0.5", port: 52341 },
        endpointB: { ip: "8.8.8.8", port: 443 },
        state: "established",
      },
      {
        endpointA: { ip: "10.0.0.8", port: 48201 },
        endpointB: { ip: "1.1.1.1", port: 80 },
        state: "established",
      },
      {
        endpointA: { ip: "172.16.20.14", port: 60144 },
        endpointB: { ip: "10.0.12.4", port: 5432 },
        state: "syn_sent",
      },
      {
        endpointA: { ip: "192.168.1.100", port: 22 },
        endpointB: { ip: "10.0.0.5", port: 22 },
        state: "ack_fin_sent",
      },
      {
        endpointA: { ip: "10.0.0.9", port: 55014 },
        endpointB: { ip: "151.101.1.69", port: 443 },
        state: "time_wait",
      },
      {
        endpointA: { ip: "10.0.3.18", port: 33910 },
        endpointB: { ip: "172.217.16.206", port: 443 },
        state: "syn_ack_received",
      },
      {
        endpointA: { ip: "10.0.2.45", port: 61420 },
        endpointB: { ip: "10.0.1.22", port: 8443 },
        state: "fin_sent",
      },
      {
        endpointA: { ip: "10.0.7.77", port: 49152 },
        endpointB: { ip: "198.51.100.20", port: 25 },
        state: "closed",
      },
    ],
  },
};

const sessions = apiResponse.data.tcpSessions;

const stateLabels = {
  unspecified: "UNSPECIFIED",
  syn_sent: "SYN SENT",
  syn_ack_received: "SYN ACK",
  established: "ESTABLISHED",
  fin_sent: "FIN SENT",
  ack_sent: "ACK SENT",
  ack_fin_sent: "ACK FIN",
  time_wait: "TIME WAIT",
  closed: "CLOSED",
  unknown: "UNKNOWN",
};

const rows = document.querySelector("#sessionRows");
const stateFilter = document.querySelector("#stateFilter");
const searchInput = document.querySelector("#searchInput");
const toast = document.querySelector("#toast");
const refreshButton = document.querySelector("#refreshButton");
const exportButton = document.querySelector("#exportButton");

let selectedIndex = 0;

function getFilteredSessions() {
  const state = stateFilter.value;
  const search = searchInput.value.trim().toLowerCase();

  return sessions.filter((session) => {
    const stateMatches = state === "all" || session.state === state;
    const searchable = [
      session.endpointA.ip,
      session.endpointA.port,
      session.endpointB.ip,
      session.endpointB.port,
      session.state,
    ].join(" ").toLowerCase();

    return stateMatches && searchable.includes(search);
  });
}

function formatEndpoint(endpoint) {
  return `${endpoint.ip}:${endpoint.port}`;
}

function renderRows() {
  const filteredSessions = getFilteredSessions();

  rows.innerHTML = filteredSessions.map((session) => {
    const index = sessions.indexOf(session);

    return `
    <tr data-index="${index}" class="${index === selectedIndex ? "is-selected" : ""}">
      <td><span class="state-pill state-${session.state}">${stateLabels[session.state]}</span></td>
      <td class="endpoint">${session.endpointA.ip}</td>
      <td>${session.endpointA.port}</td>
      <td class="route-mark">----------&gt;</td>
      <td class="endpoint">${session.endpointB.ip}</td>
      <td>${session.endpointB.port}</td>
    </tr>
  `;
  }).join("");

  document.querySelectorAll("#sessionRows tr").forEach((row) => {
    row.addEventListener("click", () => {
      selectedIndex = Number(row.dataset.index);
      renderRows();
      renderInspector();
    });
  });
}

function countByState(state) {
  return sessions.filter((session) => session.state === state).length;
}

function renderSummary() {
  const closingCount = ["fin_sent", "ack_sent", "ack_fin_sent", "time_wait"].reduce(
    (sum, state) => sum + countByState(state),
    0,
  );
  const handshakeCount = countByState("syn_sent") + countByState("syn_ack_received");
  const establishedCount = countByState("established");
  const establishedRatio = Math.round((establishedCount / sessions.length) * 100);

  document.querySelector("#trackedCount").textContent = sessions.length;
  document.querySelector("#establishedCount").textContent = establishedCount;
  document.querySelector("#closingCount").textContent = closingCount;
  document.querySelector("#statTracked").textContent = sessions.length;
  document.querySelector("#statEstablishedRatio").textContent = `${establishedRatio}%`;
  document.querySelector("#statEstablishedMeta").textContent =
    `${establishedCount} stable flows`;
  document.querySelector("#statHandshake").textContent = handshakeCount;
  document.querySelector("#statClosing").textContent = closingCount;
}

function renderInspector() {
  const session = sessions[selectedIndex] ?? sessions[0];

  document.querySelector("#selectedId").textContent =
    `Session #${String(selectedIndex + 1).padStart(2, "0")}`;
  document.querySelector("#inspectA").textContent = formatEndpoint(session.endpointA);
  document.querySelector("#inspectB").textContent = formatEndpoint(session.endpointB);
  document.querySelector("#inspectState").textContent = stateLabels[session.state];
  document.querySelector("#inspectAPort").textContent = session.endpointA.port;
  document.querySelector("#inspectBPort").textContent = session.endpointB.port;
  document.querySelector("#inspectPayload").textContent = JSON.stringify(session, null, 2);
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => {
    toast.classList.remove("is-visible");
  }, 1800);
}

stateFilter.addEventListener("change", renderRows);
searchInput.addEventListener("input", renderRows);

refreshButton.addEventListener("click", () => {
  document.querySelector("#updatedAt").textContent = new Date().toLocaleTimeString("pl-PL", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  showToast("TCP sessions refreshed");
});

exportButton.addEventListener("click", async () => {
  const payload = JSON.stringify({ tcpSessions: getFilteredSessions() }, null, 2);

  try {
    await navigator.clipboard.writeText(payload);
    showToast("Filtered sessions copied");
  } catch {
    showToast("Export payload prepared");
  }
});

renderSummary();
renderRows();
renderInspector();
