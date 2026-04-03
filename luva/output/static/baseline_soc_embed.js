/**
 * Luva embedded SOC widgets (vis-network + comm table + alerts). Charts removed — use Executive / Assessment tabs.
 */
/* global vis */
function bl(id) {
  return document.getElementById("bl-" + id);
}

/** @type {Record<string, any> | null} */
let comm = null;
/** @type {Record<string, any> | null} */
let proto = null;
/** @type {Record<string, any> | null} */
let traffic = null;
/** @type {Record<string, any> | null} */
let cmd = null;

let network = null;

let sortState = { key: "packets", dir: "desc" };

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function fmtNum(n) {
  if (n == null || Number.isNaN(n)) return "—";
  return Number(n).toLocaleString();
}

function showError(msg) {
  const el = bl("error-panel");
  if (!el) return;
  if (!msg) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 12000);
}

function setLoading(show) {
  const el = bl("loading-overlay");
  if (el) el.classList.toggle("hidden", !show);
}

/** IPs involved in Modbus / writes (heuristic ICS touch). */
function buildIcsIpSet() {
  const s = new Set();
  if (!cmd) return s;
  (cmd.write_source_ips || []).forEach((ip) => s.add(ip));
  for (const row of cmd.function_codes || []) {
    for (const pair of row.top_sources || []) {
      if (pair[0]) s.add(pair[0]);
    }
  }
  return s;
}

function buildSuspiciousIpSet() {
  const s = new Set();
  const bc = comm?.baseline_comparison;
  if (bc?.new_devices) bc.new_devices.forEach((ip) => s.add(ip));
  const nw = bc?.modbus_writes?.new_write_source_ips;
  if (nw) nw.forEach((ip) => s.add(ip));
  for (const row of comm?.patterns?.one_to_many_sources || []) {
    if (row.src_ip) s.add(row.src_ip);
  }
  const hints = proto?.anomaly_hints?.it_style_tcp_sessions_sample || [];
  for (const h of hints) {
    if (h.src_ip) s.add(h.src_ip);
    if (h.dst_ip) s.add(h.dst_ip);
  }
  return s;
}

function buildItIpSet() {
  const s = new Set();
  const hints = proto?.anomaly_hints?.it_style_tcp_sessions_sample || [];
  for (const h of hints) {
    if (h.src_ip) s.add(h.src_ip);
    if (h.dst_ip) s.add(h.dst_ip);
  }
  return s;
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

function severityBadge(sev) {
  const map = {
    critical: "bg-red-100 text-red-900 border-red-300",
    high: "bg-orange-100 text-orange-900 border-orange-300",
    medium: "bg-amber-100 text-amber-900 border-amber-300",
    low: "bg-gray-100 text-gray-800 border-gray-300",
  };
  const cls = map[sev] || map.low;
  return `<span class="inline-block rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${cls}">${sev}</span>`;
}

function buildAlerts() {
  /** @type {{title: string, detail: string, severity: string}[]} */
  const out = [];
  const bc = comm?.baseline_comparison;

  if (bc?.baseline_loaded) {
    for (const ip of bc.new_devices || []) {
      out.push({ title: "New device (vs baseline)", detail: ip, severity: "high" });
    }
    const pairs = bc.new_communication_pairs || [];
    for (const p of pairs.slice(0, 25)) {
      out.push({
        title: "New communication pair",
        detail: `${p.src_ip} → ${p.dst_ip}`,
        severity: "medium",
      });
    }
    const trunc = bc.new_communication_pairs_truncated ?? 0;
    if (trunc > 0) {
      out.push({
        title: "More new pairs truncated",
        detail: `+${trunc} additional`,
        severity: "low",
      });
    }
    if (bc.traffic?.anomalous_traffic_increase) {
      out.push({
        title: "Traffic volume spike vs baseline",
        detail: `Mean PPS ratio: ${bc.traffic.mean_pps_ratio_vs_baseline ?? "n/a"}`,
        severity: "high",
      });
    }
    if (bc.modbus_writes?.ics_write_activity_flag) {
      out.push({
        title: "Modbus write anomaly vs baseline",
        detail: "New writers or elevated write PDUs",
        severity: "critical",
      });
    }
  } else if (bc?.note) {
    out.push({ title: "Baseline", detail: bc.note, severity: "low" });
  }

  const rare = comm?.patterns?.rare_low_volume_edges || [];
  for (const e of rare.slice(0, 15)) {
    out.push({
      title: "Rare low-volume edge",
      detail: `${e.src_ip} → ${e.dst_ip} (${fmtNum(e.packets)} pkts)`,
      severity: "low",
    });
  }

  const spikes = traffic?.anomalies?.spikes || [];
  for (const s of spikes.slice(0, 12)) {
    out.push({
      title: "Traffic spike second",
      detail: `t+${s.t_offset_sec}s — ${fmtNum(s.pps)} pps (rolling μ ${s.rolling_mean_pps})`,
      severity: "medium",
    });
  }

  if (cmd?.flags?.ics_write_activity) {
    out.push({
      title: "ICS write activity observed",
      detail: `${(cmd.write_source_ips || []).length} source(s) issued write-class PDUs`,
      severity: "high",
    });
  }

  const it = proto?.anomaly_hints?.it_style_tcp_sessions_sample || [];
  for (const h of it.slice(0, 20)) {
    out.push({
      title: `IT-style port: ${h.service_hint || h.port}`,
      detail: `${h.src_ip} → ${h.dst_ip}:${h.port}`,
      severity: h.port === 3389 || h.port === 445 ? "critical" : "medium",
    });
  }

  return out;
}

function renderAlerts() {
  const list = bl("alerts-list");
  const badge = bl("alert-count-badge");
  if (!list || !badge) return;
  const alerts = buildAlerts();
  badge.textContent = String(alerts.length);
  if (!alerts.length) {
    list.innerHTML = `<p class="text-gray-500">No alerts from current data.</p>`;
    return;
  }
  list.innerHTML = alerts
    .map(
      (a) => `
    <div class="flex items-start gap-3 rounded-lg border border-gray-200 bg-white p-3 shadow-sm transition hover:border-blue-300">
      <div class="shrink-0 pt-0.5">${severityBadge(a.severity)}</div>
      <div>
        <div class="font-medium text-gray-900">${escapeHtml(a.title)}</div>
        <div class="mt-0.5 font-mono text-xs text-gray-600">${escapeHtml(a.detail)}</div>
      </div>
    </div>`,
    )
    .join("");
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

// ---------------------------------------------------------------------------
// vis-network graph
// ---------------------------------------------------------------------------

function getFilteredEdges() {
  const edges = comm?.edges || [];
  const ipQ = (bl("filter-ip")?.value || "").trim().toLowerCase();
  const icsOnly = bl("filter-ics-only")?.checked ?? false;
  const icsSet = buildIcsIpSet();

  return edges.filter((e) => {
    if (ipQ && !e.src_ip.toLowerCase().includes(ipQ) && !e.dst_ip.toLowerCase().includes(ipQ)) return false;
    if (icsOnly && !icsSet.has(e.src_ip) && !icsSet.has(e.dst_ip)) return false;
    return true;
  });
}

function rebuildGraph() {
  const container = bl("network-graph");
  if (!container || !comm) return;

  const filtered = getFilteredEdges();
  const cap = 250;
  const use = filtered.slice(0, cap);

  const nodeIds = new Set();
  for (const e of use) {
    nodeIds.add(e.src_ip);
    nodeIds.add(e.dst_ip);
  }

  const icsSet = buildIcsIpSet();
  const susSet = buildSuspiciousIpSet();
  const itSet = buildItIpSet();

  const nodes = Array.from(nodeIds).map((id) => {
    let color = { background: "#aecbfa", border: "#1a73e8" };
    let label = id.split(".").slice(-2).join(".") || id;
    if (itSet.has(id)) {
      color = { background: "#f9ab9e", border: "#c5221f" };
    } else if (susSet.has(id)) {
      color = { background: "#fdc69c", border: "#e8710a" };
    } else if (icsSet.has(id)) {
      color = { background: "#ceead6", border: "#1e8e3e" };
    }
    return {
      id,
      label: label.length > 18 ? id : label,
      title: `${id}\nICS-touch: ${icsSet.has(id)}\nSuspicious: ${susSet.has(id)}`,
      color,
      font: { color: "#202124", size: 13 },
    };
  });

  const maxPk = Math.max(...use.map((e) => e.packets), 1);
  const visEdges = use.map((e) => ({
    from: e.src_ip,
    to: e.dst_ip,
    value: Math.max(1, Math.log1p(e.packets)),
    title: `Packets: ${fmtNum(e.packets)}\nBytes: ${fmtNum(e.bytes)}`,
    color: { color: "#5f6368", highlight: "#1a73e8" },
    arrows: "to",
  }));

  const data = { nodes, edges: visEdges };
  const options = {
    physics: {
      enabled: true,
      barnesHut: { gravitationalConstant: -12000, springLength: 140 },
      stabilization: { iterations: 120 },
    },
    interaction: { hover: true, tooltipDelay: 80, zoomView: true, dragView: true },
    edges: { smooth: { type: "continuous" } },
  };

  if (network) {
    network.destroy();
    network = null;
  }
  network = new vis.Network(container, data, options);
  network.once("stabilizationIterationsDone", () => {
    network.fit({ animation: false });
  });
  attachBaselineGraphResizeObserver();
}

function attachBaselineGraphResizeObserver() {
  const el = bl("network-graph");
  if (!el || typeof ResizeObserver === "undefined") return;
  if (window.__luvaBlGraphRO) window.__luvaBlGraphRO.disconnect();
  let raf = 0;
  window.__luvaBlGraphRO = new ResizeObserver(() => {
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => {
      if (network) network.fit({ animation: false });
    });
  });
  window.__luvaBlGraphRO.observe(el);
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

function cmp(a, b, key) {
  if (key === "packets" || key === "bytes") return a[key] - b[key];
  return String(a[key]).localeCompare(String(b[key]));
}

function getCommRowsForTable() {
  let rows = [...(comm?.edges || [])];
  const ipF = (bl("filter-ip")?.value || "").trim().toLowerCase();
  const icsOnly = bl("filter-ics-only")?.checked ?? false;
  const icsSet = buildIcsIpSet();
  if (icsOnly) {
    rows = rows.filter((e) => icsSet.has(e.src_ip) || icsSet.has(e.dst_ip));
  }
  if (ipF) {
    rows = rows.filter((e) => e.src_ip.toLowerCase().includes(ipF) || e.dst_ip.toLowerCase().includes(ipF));
  }
  return rows;
}

function renderCommTable() {
  const tbody = bl("comm-tbody");
  const info = bl("table-info");
  if (!tbody || !info) return;
  const q = (bl("table-search")?.value || "").trim().toLowerCase();
  let rows = getCommRowsForTable();
  if (q) {
    rows = rows.filter(
      (r) => r.src_ip.toLowerCase().includes(q) || r.dst_ip.toLowerCase().includes(q) || String(r.packets).includes(q),
    );
  }
  rows.sort((a, b) => (sortState.dir === "asc" ? cmp(a, b, sortState.key) : cmp(b, a, sortState.key)));
  const max = 500;
  const slice = rows.slice(0, max);
  tbody.innerHTML = slice
    .map(
      (e) => `
    <tr class="border-b border-gray-100 hover:bg-gray-50">
      <td class="px-3 py-1.5 font-mono text-xs text-blue-800">${escapeHtml(e.src_ip)}</td>
      <td class="px-3 py-1.5 font-mono text-xs text-gray-800">${escapeHtml(e.dst_ip)}</td>
      <td class="px-3 py-1.5 font-mono text-xs">${fmtNum(e.packets)}</td>
      <td class="px-3 py-1.5 font-mono text-xs">${fmtNum(e.bytes)}</td>
    </tr>`,
    )
    .join("");
  info.textContent = `Showing ${slice.length} of ${rows.length} rows (sort: ${sortState.key} ${sortState.dir}).`;
}

function applyData() {
  const meta = comm?.meta || proto?.meta || {};
  const ml = bl("meta-line");
  if (ml) {
    ml.textContent = [meta.tool || "luva_embed", meta.pcap_path ? `PCAP: ${meta.pcap_path}` : "", meta.generated_utc || ""]
      .filter(Boolean)
      .join(" · ");
  }
  renderAlerts();
  rebuildGraph();
  renderCommTable();
}

function exportBundle() {
  const blob = new Blob(
    [JSON.stringify({ communication_map: comm, protocol_distribution: proto, traffic_profile: traffic, command_profile: cmd }, null, 2)],
    { type: "application/json" },
  );
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "luva_soc_bundle.json";
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------------------------------------------------------------------------
// Boot (embedded in Luva HTML)
// ---------------------------------------------------------------------------

function wireBaselineSocOnce() {
  if (window.__luvaBaselineSocWired) return;
  window.__luvaBaselineSocWired = true;
  const e = bl("btn-export");
  if (e) e.addEventListener("click", exportBundle);
  const fi = bl("filter-ip");
  if (fi) fi.addEventListener("input", () => { rebuildGraph(); renderCommTable(); });
  const ic = bl("filter-ics-only");
  if (ic) ic.addEventListener("change", () => { rebuildGraph(); renderCommTable(); });
  const ts = bl("table-search");
  if (ts) ts.addEventListener("input", renderCommTable);
  document.querySelectorAll("#bl-comm-table thead [data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.getAttribute("data-sort");
      if (sortState.key === key) sortState.dir = sortState.dir === "asc" ? "desc" : "asc";
      else {
        sortState.key = key;
        sortState.dir = key === "src" || key === "dst" ? "asc" : "desc";
      }
      renderCommTable();
    });
  });
}

window.initLuvaBaselineSoc = function () {
  const dataEl = document.getElementById("luva-baseline-embed-data");
  if (!dataEl || window.__luvaBaselineSocInit) return;
  let bundle;
  try {
    bundle = JSON.parse(dataEl.textContent);
  } catch (err) {
    console.error("luva-baseline-embed-data parse error", err);
    return;
  }
  window.__luvaBaselineSocInit = true;
  comm = bundle.communication_map;
  proto = bundle.protocol_distribution;
  traffic = bundle.traffic_profile;
  cmd = bundle.command_profile;
  wireBaselineSocOnce();
  applyData();
};
