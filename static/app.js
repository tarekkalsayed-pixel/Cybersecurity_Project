// ── Progress bar on page navigation ──
(function () {
    const bar = document.getElementById("progress-bar");
    if (!bar) return;
    let width = 0;
    const grow = setInterval(() => {
        width = width < 85 ? width + (85 - width) * 0.12 : width;
        bar.style.width = width + "%";
    }, 80);
    window.addEventListener("load", () => {
        clearInterval(grow);
        bar.style.width = "100%";
        setTimeout(() => { bar.style.opacity = "0"; }, 300);
    });
    document.querySelectorAll("a[href]").forEach(link => {
        link.addEventListener("click", () => {
            bar.style.opacity = "1";
            bar.style.width = "30%";
        });
    });
})();

// Simple pagination for any list of elements.
function paginate(containerId, controlsId, pageSize) {
    const container = document.getElementById(containerId);
    const controls  = document.getElementById(controlsId);
    if (!container || !controls) return;

    const items = Array.from(container.children);
    if (items.length <= pageSize) return;

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

const METRIC_IDS = ["metric-events", "metric-suspicious", "metric-risk", "status-label", "status-detail", "monitor-state"];

const TOAST_SESSION_KEY = "re_dismissed_recovery";

function dismissToast() {
    const toast = document.getElementById("recovery-toast");
    if (toast) toast.classList.add("hidden");
}

function showRecoveryToast(summary) {
    const toast  = document.getElementById("recovery-toast");
    const detail = document.getElementById("recovery-toast-detail");
    if (!toast || !summary.last_recovery) return;

    const key = summary.last_recovery.evidence_path;
    // Don't show if user already dismissed this recovery event
    if (sessionStorage.getItem(TOAST_SESSION_KEY) === key) return;
    // Don't show if already visible for same event
    if (toast.dataset.recoveryKey === key) return;

    toast.dataset.recoveryKey = key;
    const count    = summary.last_recovery.restore_result?.restored_count ?? "?";
    const score    = summary.last_recovery.triggered_score ?? "?";
    const severity = summary.last_recovery.triggered_severity ?? "HIGH";
    if (detail) detail.textContent = `Triggered by ${severity} risk score (${score}/100). ${count} file(s) restored from clean backup.`;
    toast.classList.remove("hidden");

    // Auto-dismiss after 5s and remember it was dismissed
    const timer = setTimeout(() => {
        sessionStorage.setItem(TOAST_SESSION_KEY, key);
        dismissToast();
    }, 5000);

    // X button also saves to sessionStorage so it won't reappear on other pages
    const closeBtn = toast.querySelector(".recovery-toast-close");
    if (closeBtn) {
        closeBtn.onclick = () => {
            clearTimeout(timer);
            sessionStorage.setItem(TOAST_SESSION_KEY, key);
            dismissToast();
        };
    }
}

async function refreshSummary() {
    // Pulse metrics while fetching
    METRIC_IDS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add("refreshing");
    });

    const response = await fetch("/api/summary");
    if (!response.ok) return;

    const summary = await response.json();

    document.body.dataset.status = summary.status;

    const updates = {
        "status-label":     summary.status,
        "status-detail":    summary.status_detail,
        "metric-events":    summary.total_events,
        "metric-suspicious":summary.suspicious_events,
        "metric-risk":      `${summary.current_risk_score}/100`,
        "monitor-state":    summary.status,
    };

    Object.entries(updates).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value;
            el.classList.remove("refreshing");
        }
    });

    showRecoveryToast(summary);
}

setInterval(() => { refreshSummary().catch(() => {}); }, 4000);
refreshSummary().catch(() => {});

paginate("events-rows",    "events-pagination",    25);
paginate("incidents-list", "incidents-pagination", 10);