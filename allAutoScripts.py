#!/usr/bin/env python3
"""
DevOps / Platform / SRE Python Automation Scripts
==================================================
A curated collection of production-ready Python automation utilities.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 1. HEALTH CHECK — HTTP endpoint monitor with retry + alerting hook
# ─────────────────────────────────────────────────────────────────────────────
import requests
import time
import smtplib
from email.mime.text import MIMEText
from typing import Optional

def health_check(
    url: str,
    expected_status: int = 200,
    timeout: int = 5,
    retries: int = 3,
    retry_delay: int = 2,
    alert_email: Optional[str] = None,
) -> dict:
    """
    Poll an HTTP endpoint and return a health report.
    Retries on failure; optionally emails on persistent failure.
    """
    result = {"url": url, "status": "unknown", "latency_ms": None, "attempts": 0}
    for attempt in range(1, retries + 1):
        result["attempts"] = attempt
        try:
            t0 = time.perf_counter()
            resp = requests.get(url, timeout=timeout)
            latency = round((time.perf_counter() - t0) * 1000, 2)
            result["latency_ms"] = latency
            if resp.status_code == expected_status:
                result["status"] = "healthy"
                return result
            result["status"] = f"degraded (HTTP {resp.status_code})"
        except requests.exceptions.RequestException as exc:
            result["status"] = f"unreachable ({exc})"
        if attempt < retries:
            time.sleep(retry_delay)

    if alert_email:
        _send_alert(alert_email, url, result["status"])
    return result


def _send_alert(to: str, url: str, status: str) -> None:
    msg = MIMEText(f"ALERT: {url} is {status}")
    msg["Subject"] = f"[SRE Alert] Health check failed: {url}"
    msg["From"] = "sre-bot@company.com"
    msg["To"] = to
    with smtplib.SMTP("localhost") as smtp:
        smtp.send_message(msg)


# ─────────────────────────────────────────────────────────────────────────────
# 2. DISK USAGE WATCHER — alert when a mount point exceeds threshold
# ─────────────────────────────────────────────────────────────────────────────
import shutil
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("disk_watcher")


def check_disk_usage(path: str = "/", warn_pct: float = 80.0, crit_pct: float = 90.0) -> dict:
    """
    Returns disk usage stats and a severity level (ok / warn / critical).
    """
    total, used, free = shutil.disk_usage(path)
    used_pct = used / total * 100

    if used_pct >= crit_pct:
        severity = "critical"
    elif used_pct >= warn_pct:
        severity = "warn"
    else:
        severity = "ok"

    report = {
        "path": path,
        "total_gb": round(total / 1e9, 2),
        "used_gb": round(used / 1e9, 2),
        "free_gb": round(free / 1e9, 2),
        "used_pct": round(used_pct, 1),
        "severity": severity,
    }
    log_fn = logger.critical if severity == "critical" else (logger.warning if severity == "warn" else logger.info)
    log_fn("Disk usage on %(path)s: %(used_pct)s%% [%(severity)s]", report)
    return report


# ─────────────────────────────────────────────────────────────────────────────
# 3. PROCESS WATCHDOG — restart a crashed process automatically
# ─────────────────────────────────────────────────────────────────────────────
import subprocess
import signal

def watchdog(
    command: list[str],
    max_restarts: int = 5,
    backoff_seconds: int = 3,
    check_interval: int = 5,
) -> None:
    """
    Run `command` as a subprocess and restart it if it exits unexpectedly.
    Stops after `max_restarts` consecutive failures (resets on clean runs).
    """
    restarts = 0
    while restarts <= max_restarts:
        logger.info("Starting process: %s  (restart #%d)", command, restarts)
        proc = subprocess.Popen(command)
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.send_signal(signal.SIGTERM)
            logger.info("Watchdog stopped by user.")
            return

        if proc.returncode == 0:
            logger.info("Process exited cleanly.")
            return

        restarts += 1
        logger.warning("Process crashed (rc=%d). Restarting in %ds…", proc.returncode, backoff_seconds)
        time.sleep(backoff_seconds * restarts)  # exponential-ish backoff

    logger.critical("Max restarts (%d) reached. Giving up.", max_restarts)


# ─────────────────────────────────────────────────────────────────────────────
# 4. LOG PARSER — tail a log file and extract ERROR/CRITICAL lines
# ─────────────────────────────────────────────────────────────────────────────
import re
from pathlib import Path
from collections import defaultdict


def parse_error_logs(
    log_path: str,
    patterns: list[str] | None = None,
    tail_lines: int = 500,
) -> dict:
    """
    Read the last `tail_lines` lines of a log file, group matches by pattern.
    Default patterns: ERROR, CRITICAL, FATAL, Exception, Traceback.
    """
    patterns = patterns or [r"ERROR", r"CRITICAL", r"FATAL", r"Exception", r"Traceback"]
    compiled = [(p, re.compile(p, re.IGNORECASE)) for p in patterns]

    lines = Path(log_path).read_text(errors="replace").splitlines()[-tail_lines:]
    hits: dict[str, list[str]] = defaultdict(list)

    for line in lines:
        for label, rx in compiled:
            if rx.search(line):
                hits[label].append(line.strip())
                break  # count each line once

    summary = {label: {"count": len(matches), "samples": matches[:3]} for label, matches in hits.items()}
    return {"log_file": log_path, "lines_scanned": len(lines), "summary": summary}


# ─────────────────────────────────────────────────────────────────────────────
# 5. SECRET ROTATION — rotate an AWS IAM access key and update SSM Parameter Store
# ─────────────────────────────────────────────────────────────────────────────
import boto3


def rotate_iam_key(iam_username: str, ssm_param_prefix: str = "/secrets") -> dict:
    """
    1. Create a new IAM access key for `iam_username`.
    2. Store the new key + secret in SSM Parameter Store (SecureString).
    3. Delete the oldest existing key (keeps AWS's 2-key limit respected).
    Returns the new key ID.
    """
    iam = boto3.client("iam")
    ssm = boto3.client("ssm")

    # Create new key
    new_key = iam.create_access_key(UserName=iam_username)["AccessKey"]
    key_id = new_key["AccessKeyId"]
    secret = new_key["SecretAccessKey"]

    # Push to SSM
    for param, value in [("access_key_id", key_id), ("secret_access_key", secret)]:
        ssm.put_parameter(
            Name=f"{ssm_param_prefix}/{iam_username}/{param}",
            Value=value,
            Type="SecureString",
            Overwrite=True,
        )

    # Delete oldest key (if 2 already exist after creation)
    existing = iam.list_access_keys(UserName=iam_username)["AccessKeyMetadata"]
    existing.sort(key=lambda k: k["CreateDate"])
    if len(existing) > 2:
        old_id = existing[0]["AccessKeyId"]
        iam.delete_access_key(UserName=iam_username, AccessKeyId=old_id)
        logger.info("Deleted old key %s for user %s", old_id, iam_username)

    logger.info("Rotated key for %s → new key ID: %s", iam_username, key_id)
    return {"username": iam_username, "new_key_id": key_id}


# ─────────────────────────────────────────────────────────────────────────────
# 6. KUBERNETES POD RESTARTER — restart crashlooping pods in a namespace
# ─────────────────────────────────────────────────────────────────────────────
from kubernetes import client, config


def restart_crashlooping_pods(namespace: str = "default", restart_threshold: int = 3) -> list[str]:
    """
    Finds pods in CrashLoopBackOff with restart count >= threshold and deletes
    them (triggering a fresh start by the ReplicaSet/Deployment controller).
    Returns list of deleted pod names.
    """
    config.load_incluster_config()  # use load_kube_config() outside cluster
    v1 = client.CoreV1Api()

    pods = v1.list_namespaced_pod(namespace)
    deleted = []

    for pod in pods.items:
        for cs in pod.status.container_statuses or []:
            waiting = cs.state.waiting
            if waiting and waiting.reason == "CrashLoopBackOff":
                if cs.restart_count >= restart_threshold:
                    pod_name = pod.metadata.name
                    v1.delete_namespaced_pod(pod_name, namespace)
                    logger.warning("Deleted crashlooping pod %s/%s (restarts=%d)", namespace, pod_name, cs.restart_count)
                    deleted.append(pod_name)
    return deleted


# ─────────────────────────────────────────────────────────────────────────────
# 7. DEPLOYMENT DIFF — compare running image tags across two k8s namespaces
# ─────────────────────────────────────────────────────────────────────────────
from kubernetes import client as k8s_client


def deployment_image_diff(ns_a: str, ns_b: str) -> list[dict]:
    """
    Returns a list of deployments where the container image tag differs
    between namespace A (e.g. staging) and namespace B (e.g. production).
    """
    apps_v1 = k8s_client.AppsV1Api()

    def get_images(ns: str) -> dict[str, str]:
        deps = apps_v1.list_namespaced_deployment(ns).items
        result = {}
        for dep in deps:
            for c in dep.spec.template.spec.containers:
                result[f"{dep.metadata.name}/{c.name}"] = c.image
        return result

    images_a = get_images(ns_a)
    images_b = get_images(ns_b)

    diffs = []
    for key in set(images_a) | set(images_b):
        img_a = images_a.get(key, "<missing>")
        img_b = images_b.get(key, "<missing>")
        if img_a != img_b:
            diffs.append({"deployment/container": key, ns_a: img_a, ns_b: img_b})
    return diffs


# ─────────────────────────────────────────────────────────────────────────────
# 8. PROMETHEUS METRIC PUSHER — push custom metrics via Pushgateway
# ─────────────────────────────────────────────────────────────────────────────
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway


def push_custom_metric(
    job_name: str,
    metric_name: str,
    metric_value: float,
    labels: dict | None = None,
    gateway: str = "localhost:9091",
) -> None:
    """
    Push a single gauge metric to the Prometheus Pushgateway.
    Useful for batch jobs that don't run long enough to be scraped.
    """
    registry = CollectorRegistry()
    label_names = list(labels.keys()) if labels else []
    g = Gauge(metric_name, f"Custom metric: {metric_name}", label_names, registry=registry)
    if labels:
        g.labels(**labels).set(metric_value)
    else:
        g.set(metric_value)

    push_to_gateway(gateway, job=job_name, registry=registry)
    logger.info("Pushed %s=%.4f to Pushgateway [job=%s]", metric_name, metric_value, job_name)


# ─────────────────────────────────────────────────────────────────────────────
# 9. DB BACKUP — dump a Postgres DB and upload to S3
# ─────────────────────────────────────────────────────────────────────────────
import os
import datetime
import gzip
import boto3 as _boto3


def backup_postgres_to_s3(
    db_url: str,
    s3_bucket: str,
    s3_prefix: str = "db-backups",
    keep_local: bool = False,
) -> str:
    """
    pg_dump a PostgreSQL database, gzip it, and upload to S3.
    Returns the S3 object key.
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    local_file = f"/tmp/pgdump_{timestamp}.sql.gz"
    s3_key = f"{s3_prefix}/pgdump_{timestamp}.sql.gz"

    dump_cmd = ["pg_dump", "--no-password", "--format=plain", db_url]
    with gzip.open(local_file, "wb") as gz_out:
        proc = subprocess.run(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        gz_out.write(proc.stdout)

    s3 = _boto3.client("s3")
    s3.upload_file(local_file, s3_bucket, s3_key)
    logger.info("Uploaded DB backup to s3://%s/%s", s3_bucket, s3_key)

    if not keep_local:
        os.remove(local_file)
    return s3_key


# ─────────────────────────────────────────────────────────────────────────────
# 10. INCIDENT REPORT GENERATOR — Slack + PagerDuty integration
# ─────────────────────────────────────────────────────────────────────────────
import json
import datetime as _dt


def create_incident(
    title: str,
    severity: str,  # "P1" | "P2" | "P3"
    description: str,
    slack_webhook: str,
    pagerduty_routing_key: str,
) -> dict:
    """
    Fires a PagerDuty incident and posts a Slack notification simultaneously.
    Returns both API responses.
    """
    timestamp = _dt.datetime.utcnow().isoformat() + "Z"

    # PagerDuty Events API v2
    pd_payload = {
        "routing_key": pagerduty_routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": f"[{severity}] {title}",
            "severity": {"P1": "critical", "P2": "error", "P3": "warning"}.get(severity, "info"),
            "source": "sre-automation",
            "timestamp": timestamp,
            "custom_details": {"description": description},
        },
    }
    pd_resp = requests.post(
        "https://events.pagerduty.com/v2/enqueue",
        headers={"Content-Type": "application/json"},
        data=json.dumps(pd_payload),
        timeout=10,
    )

    # Slack Incoming Webhook
    color_map = {"P1": "#FF0000", "P2": "#FF8800", "P3": "#FFCC00"}
    slack_payload = {
        "attachments": [{
            "color": color_map.get(severity, "#888888"),
            "title": f"🚨 [{severity}] {title}",
            "text": description,
            "footer": "SRE Incident Bot",
            "ts": _dt.datetime.utcnow().timestamp(),
        }]
    }
    slack_resp = requests.post(slack_webhook, json=slack_payload, timeout=10)

    return {
        "pagerduty_status": pd_resp.status_code,
        "slack_status": slack_resp.status_code,
        "incident_title": title,
        "severity": severity,
        "fired_at": timestamp,
    }


# ─────────────────────────────────────────────────────────────────────────────
# USAGE EXAMPLES
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import pprint

    # 1. Health check
    pprint.pprint(health_check("https://httpbin.org/status/200", retries=2))

    # 2. Disk usage
    pprint.pprint(check_disk_usage("/", warn_pct=70))

    # 3. Log parsing
    # pprint.pprint(parse_error_logs("/var/log/syslog", tail_lines=200))

    # 4. Disk of a batch job metric push (needs Pushgateway running)
    # push_custom_metric("nightly_etl", "etl_rows_processed", 142500,
    #                    labels={"env": "prod", "pipeline": "user_events"})