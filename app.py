import atexit
import json

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for

from config import FlaskConfig
from core.lab import RansomEyeLab


app = Flask(__name__)
app.config.from_object(FlaskConfig)

lab = RansomEyeLab()
lab.initialize()
atexit.register(lab.shutdown)


@app.route("/")
def index():
    return render_template("index.html", summary=lab.dashboard_summary())


@app.route("/monitor")
def monitor():
    return render_template(
        "monitor.html",
        summary=lab.dashboard_summary(),
        recent_events=lab.recent_events(20),
    )


@app.route("/events")
def events():
    return render_template("events.html", events=lab.recent_events(200))


@app.route("/incidents")
def incidents():
    return render_template("incidents.html", incidents=lab.incidents(50))


@app.route("/recovery")
def recovery():
    return render_template(
        "recovery.html",
        backup_status=lab.backup_status(),
        recovery_history=lab.recovery_history(30),
        summary=lab.dashboard_summary(),
    )


@app.route("/simulator")
def simulator():
    return render_template("simulator.html", summary=lab.dashboard_summary())


@app.route("/settings")
def settings():
    return render_template("settings.html", summary=lab.dashboard_summary())


@app.route("/actions/monitor/start", methods=["POST"])
def start_monitor():
    flash(lab.start_monitoring(), "success")
    return redirect(request.referrer or url_for("monitor"))


@app.route("/actions/monitor/stop", methods=["POST"])
def stop_monitor():
    flash(lab.stop_monitoring(), "warning")
    return redirect(request.referrer or url_for("monitor"))


@app.route("/actions/backups/refresh", methods=["POST"])
def refresh_backups():
    result = lab.refresh_backups()
    flash(f"Backups refreshed for {result['file_count']} file(s).", "success")
    return redirect(request.referrer or url_for("recovery"))


@app.route("/actions/restore", methods=["POST"])
def restore_all():
    result = lab.manual_restore()
    flash(f"Restored {result['restored_count']} file(s) from backup.", "success")
    return redirect(request.referrer or url_for("recovery"))


@app.route("/actions/simulator/seed", methods=["POST"])
def seed_demo():
    result = lab.seed_demo_files()
    flash(result["message"], "success")
    return redirect(request.referrer or url_for("simulator"))


@app.route("/actions/simulator/run", methods=["POST"])
def run_simulator():
    scenario = request.form.get("scenario", "")
    try:
        result = lab.run_simulator(scenario)
        flash(result["message"], "success" if result["started"] else "warning")
    except ValueError as error:
        flash(str(error), "error")
    return redirect(request.referrer or url_for("simulator"))


@app.route("/actions/clear-logs", methods=["POST"])
def clear_logs():
    lab.clear_logs()
    flash("Event, incident, and recovery logs were cleared.", "warning")
    return redirect(request.referrer or url_for("index"))


@app.route("/api/summary")
def api_summary():
    return jsonify(lab.dashboard_summary())


@app.route("/api/events/recent")
def api_recent_events():
    rows = [dict(row) for row in lab.recent_events(25)]
    return jsonify(rows)


@app.route("/incidents/<int:incident_id>/download")
def download_incident(incident_id: int):
    report = lab.incident_report(incident_id)
    if report is None:
        return render_template("404.html"), 404

    format_name = request.args.get("format", "json").lower()
    if format_name == "txt":
        lines = [
            f"Incident ID: {report['id']}",
            f"Created: {report['created_at']}",
            f"Severity: {report['severity']}",
            f"Risk Score: {report['risk_score']}",
            f"Title: {report['title']}",
            "Reasons:",
            *[f"- {reason}" for reason in report["reasons"]],
            "Affected Files:",
            *[f"- {path}" for path in report["affected_files"]],
            f"Status: {report['status']}",
            f"Action Taken: {report['action_taken']}",
            f"Recovery Status: {report['recovery_status']}",
            f"Evidence Path: {report['evidence_path']}",
        ]
        payload = "\n".join(lines)
        return Response(
            payload,
            mimetype="text/plain",
            headers={
                "Content-Disposition": f"attachment; filename=incident_{incident_id}.txt"
            },
        )

    payload = json.dumps(report, indent=2)
    return Response(
        payload,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=incident_{incident_id}.json"
        },
    )


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(_error):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
