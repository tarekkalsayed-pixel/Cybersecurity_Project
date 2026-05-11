// Simple pagination for any list of elements.
// containerId: the element whose direct children are the rows/cards to paginate.
// controlsId: where to render the prev/next controls.
// pageSize: how many items to show per page.
function paginate(containerId, controlsId, pageSize) {
    const container = document.getElementById(containerId);
    const controls  = document.getElementById(controlsId);
    if (!container || !controls) return;

    const items = Array.from(container.children);
    if (items.length <= pageSize) return; // no need to paginate

    let page = 0;
    const totalPages = Math.ceil(items.length / pageSize);

    function render() {
        items.forEach((item, i) => {
            item.style.display = (i >= page * pageSize && i < (page + 1) * pageSize) ? "" : "none";
        });
        controls.innerHTML = `
            <button class="button secondary" onclick="void(0)" id="${controlsId}-prev">&#8592; Prev</button>
            <span style="padding:0 14px;color:var(--muted)">Page ${page + 1} of ${totalPages}</span>
            <button class="button secondary" onclick="void(0)" id="${controlsId}-next">Next &#8594;</button>
        `;
        document.getElementById(`${controlsId}-prev`).disabled = page === 0;
        document.getElementById(`${controlsId}-next`).disabled = page === totalPages - 1;
        document.getElementById(`${controlsId}-prev`).addEventListener("click", () => { if (page > 0) { page--; render(); } });
        document.getElementById(`${controlsId}-next`).addEventListener("click", () => { if (page < totalPages - 1) { page++; render(); } });
    }
    render();
}

// Mark the nav link that matches the current page as active
document.querySelectorAll(".nav a").forEach(link => {
    if (link.pathname === window.location.pathname) {
        link.classList.add("active");
    }
});

async function refreshSummary() {
    const response = await fetch("/api/summary");
    if (!response.ok) {
        return;
    }

    const summary = await response.json();
    const statusLabel = document.getElementById("status-label");
    const statusDetail = document.getElementById("status-detail");
    const metricEvents = document.getElementById("metric-events");
    const metricSuspicious = document.getElementById("metric-suspicious");
    const metricRisk = document.getElementById("metric-risk");
    const monitorState = document.getElementById("monitor-state");

    document.body.dataset.status = summary.status;

    if (statusLabel) statusLabel.textContent = summary.status;
    if (statusDetail) statusDetail.textContent = summary.status_detail;
    if (metricEvents) metricEvents.textContent = summary.total_events;
    if (metricSuspicious) metricSuspicious.textContent = summary.suspicious_events;
    if (metricRisk) metricRisk.textContent = `${summary.current_risk_score}/100`;
    if (monitorState) monitorState.textContent = summary.status;
}

setInterval(() => {
    refreshSummary().catch(() => {});
}, 4000);

refreshSummary().catch(() => {});

paginate("events-rows",    "events-pagination",    25);
paginate("incidents-list", "incidents-pagination", 10);
