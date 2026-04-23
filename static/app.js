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
