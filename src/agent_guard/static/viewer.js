"use strict";
const TOKEN = document.querySelector('meta[name="agent-guard-token"]').content;
const $ = (id) => document.getElementById(id);
let entries = [];
const open = new Set();

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function badge(decision) {
  const cls = decision === "allowed" || decision === "approved" ? "ok" : decision ? "bad" : "warn";
  return `<span class="badge ${cls}">${esc(decision || "-")}</span>`;
}
function piiText(p) {
  if (!p) return "";
  return Object.entries(p).map(([where, v]) => `${where}: ${v.mode} (${Object.entries(v.found).map(([k, n]) => k + "×" + n).join(", ")})`).join("<br>");
}
function fillSelect(sel, values) {
  const cur = sel.value;
  const first = sel.options[0].outerHTML;
  sel.innerHTML = first + [...values].sort().map((v) => `<option${v === cur ? " selected" : ""}>${esc(v)}</option>`).join("");
}

function render() {
  const q = $("q").value.toLowerCase();
  const fd = $("decision").value, ft = $("tool").value, fa = $("agent").value;
  const callsOnly = $("calls-only").checked;
  const rows = [];
  for (const e of entries) {
    const tool = e.tool_id || e.tool || "";
    if (callsOnly && e.event !== "tool_call") continue;
    if (fd && e.decision !== fd) continue;
    if (ft && tool !== ft) continue;
    if (fa && e.agent !== fa) continue;
    const args = e.arguments ? JSON.stringify(e.arguments) : "";
    const reason = e.decision === "allowed" || e.decision === "approved" ? (e.result_preview || "") : (e.reason || "");
    if (q && !(tool + args + reason + (e.event || "")).toLowerCase().includes(q)) continue;
    const time = (e.ts || "").replace("T", " ").slice(0, 23);
    const dec = e.event === "tool_call" ? badge(e.decision) : `<span class="badge warn">${esc(e.event)}</span>`;
    rows.push(`<tr class="row" data-seq="${e.seq}"><td>${e.seq}</td><td><code>${esc(time)}</code></td><td>${dec}</td>
      <td><code>${esc(tool)}</code></td><td>${esc(e.agent)}</td><td class="args"><code>${esc(args.slice(0, 200))}</code></td>
      <td class="reason">${esc(reason.slice(0, 240))}</td><td>${piiText(e.pii)}</td><td>${e.duration_ms ?? ""}</td></tr>`);
    if (open.has(e.seq)) rows.push(`<tr><td colspan="9"><pre>${esc(JSON.stringify(e, null, 2))}</pre></td></tr>`);
  }
  $("rows").innerHTML = rows.join("") || `<tr><td colspan="9" class="muted">No entries.</td></tr>`;
}

async function loadEntries() {
  const r = await fetch("api/entries?limit=1000");
  const data = await r.json();
  entries = data.entries;
  $("path").textContent = data.path;
  const c = data.chain;
  const chain = $("chain");
  if (!c) { chain.className = "badge warn"; chain.textContent = "no log yet"; }
  else if (c.ok) { chain.className = "badge ok"; chain.textContent = `chain intact · ${c.entries} entries`; chain.title = "head " + c.head; }
  else { chain.className = "badge bad"; chain.textContent = "chain BROKEN"; chain.title = c.error; }
  fillSelect($("decision"), new Set(entries.map((e) => e.decision).filter(Boolean)));
  fillSelect($("tool"), new Set(entries.map((e) => e.tool_id || e.tool).filter(Boolean)));
  fillSelect($("agent"), new Set(entries.map((e) => e.agent).filter(Boolean)));
  render();
}

async function loadPending() {
  const r = await fetch("api/pending");
  const { pending } = await r.json();
  $("pcount").textContent = pending.length ? `(${pending.length})` : "";
  const box = $("pending");
  const focused = document.activeElement && box.contains(document.activeElement);
  if (focused) return; // don't wipe a note the reviewer is typing
  if (!pending.length) { box.className = "muted"; box.innerHTML = "None."; return; }
  box.className = "";
  const now = Date.now() / 1000;
  box.innerHTML = pending.map((p) => `<div class="pending-item">
    <div><code>${esc(p.id)}</code> &nbsp; <b><code>${esc(p.tool_id)}</code></b> &nbsp; agent <b>${esc(p.agent)}</b>
      &nbsp; <span class="badge warn">${Math.max(0, Math.round(p.expires_at - now))}s left</span></div>
    <div class="muted">${esc(p.reason)}${p.rule ? " (rule: " + esc(p.rule) + ")" : ""}</div>
    <pre>${esc(JSON.stringify(p.arguments, null, 2))}</pre>
    <div class="actions"><input placeholder="note (optional)" id="note-${esc(p.id)}" size="30">
      <button class="approve" data-id="${esc(p.id)}" data-ok="1">Approve</button>
      <button class="deny" data-id="${esc(p.id)}" data-ok="0">Deny</button></div></div>`).join("");
}

async function decide(id, approved) {
  const note = ($("note-" + id) || {}).value || "";
  const r = await fetch("api/approvals/" + encodeURIComponent(id), {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Agent-Guard-Token": TOKEN },
    body: JSON.stringify({ approved, note }),
  });
  if (!r.ok) alert((await r.json()).error || "failed");
  document.activeElement && document.activeElement.blur();
  await refresh();
}

async function refresh() {
  try {
    await Promise.all([loadEntries(), loadPending()]);
    $("updated").textContent = "updated " + new Date().toLocaleTimeString();
  } catch (err) {
    $("updated").textContent = "viewer offline? " + err;
  }
}

$("pending").addEventListener("click", (ev) => {
  const b = ev.target.closest("button[data-id]");
  if (b) decide(b.dataset.id, b.dataset.ok === "1");
});
$("rows").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr.row");
  if (!tr) return;
  const seq = Number(tr.dataset.seq);
  open.has(seq) ? open.delete(seq) : open.add(seq);
  render();
});
for (const id of ["q", "decision", "tool", "agent", "calls-only"]) $(id).addEventListener("input", render);
refresh();
setInterval(refresh, 2000);
