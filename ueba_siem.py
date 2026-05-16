#!/usr/bin/env python3
"""
UEBA Module for SIEM - Security in Communications Networks
Dataset: 1  (X = 1)

Rules implemented:
  R1 - Internal BotNet detection (beaconing: very regular per-src/dst intervals)
  R2 - Data exfiltration via HTTPS (abnormally high upload/download ratio)
  R3 - Data exfiltration via DNS   (abnormally high DNS flow volume / large payloads)
  R4 - C&C activities via DNS      (high-frequency DNS polling)
  R5 - Anomalous external destinations (traffic to countries not in baseline)
  R6 - Anomalous external users    (unknown src IPs / abnormal up-down ratio / long idle intervals)
"""

import sys
import logging
import logging.handlers
import ipaddress
from datetime import datetime

import pandas as pd
import numpy as np
import geoip2.database

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATASET_DIR   = "dataset1"
GEODB_COUNTRY = "Geo-Localization Databases-20260516/dbip-country-lite-2026-05.mmdb"
GEODB_ASN     = "Geo-Localization Databases-20260516/dbip-asn-lite-2026-05.mmdb"

INTERNAL_TRAIN = f"{DATASET_DIR}/internal_train1.json"
INTERNAL_TEST  = f"{DATASET_DIR}/internal_test1.json"
EXTERNAL_TRAIN = f"{DATASET_DIR}/external_train1.json"
EXTERNAL_TEST  = f"{DATASET_DIR}/external_test1.json"

# Network definitions (discovered from data)
INTERNAL_NET   = ipaddress.IPv4Network("192.168.101.0/24")
CORPORATE_SRVS = {"200.0.0.11", "200.0.0.12"}

# Internal servers (identified from training data)
DNS_SERVERS    = {"192.168.101.226", "192.168.101.229"}
HTTPS_SERVER   = "192.168.101.240"

# Sigma multiplier for anomaly thresholds
SIGMA = 3

# ---------------------------------------------------------------------------
# Syslog / reporting setup
# ---------------------------------------------------------------------------
syslog_handler = None
try:
    syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
    syslog_handler.setFormatter(
        logging.Formatter("UEBA-SIEM %(levelname)s: %(message)s"))
    syslog_logger = logging.getLogger("ueba_siem")
    syslog_logger.setLevel(logging.WARNING)
    syslog_logger.addHandler(syslog_handler)
    syslog_logger.propagate = False   # prevent double-logging to root
    SYSLOG_AVAILABLE = True
except Exception:
    SYSLOG_AVAILABLE = False

# Console logger for all output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("ueba_console")


def alert(rule_id: str, severity: str, src_ip: str, detail: str):
    """Emit an alert to console and (if available) to rsyslog."""
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    msg = f"[{ts}] ALERT rule={rule_id} severity={severity} src_ip={src_ip} | {detail}"
    if severity == "HIGH":
        log.warning(msg)
    else:
        log.info(msg)
    if SYSLOG_AVAILABLE:
        syslog_logger.warning(msg)


# ---------------------------------------------------------------------------
# Helper: geo-lookup (cached)
# ---------------------------------------------------------------------------
def build_cc_cache(ip_series: pd.Series, geodb) -> dict:
    """Return {ip_str: country_code} for a series of IP strings."""
    cache = {}
    for ip in ip_series.unique():
        try:
            cc = geodb.country(ip).country.iso_code
            cache[ip] = cc if cc else "XX"
        except Exception:
            cache[ip] = "XX"
    return cache


# ---------------------------------------------------------------------------
# Baseline computation from training data
# ---------------------------------------------------------------------------
def compute_baselines(itr: pd.DataFrame, etr: pd.DataFrame, geodb) -> dict:
    """
    Derive all rule thresholds from the anomaly-free training datasets.
    Returns a dict of named thresholds and supporting data structures.
    """
    log.info("Computing baselines from training data …")
    bl = {}

    # --- HTTPS up/down ratio baseline (per device total) ------------------
    https_r = itr[itr["port"] == 443]
    up_r    = https_r.groupby("src_ip")["up_bytes"].sum()
    dn_r    = https_r.groupby("src_ip")["down_bytes"].sum()
    ratio_r = up_r / dn_r
    bl["https_ratio_mean"] = ratio_r.mean()
    bl["https_ratio_std"]  = ratio_r.std()
    bl["https_ratio_thr"]  = ratio_r.mean() + SIGMA * ratio_r.std()
    log.info(
        "  HTTPS up/down ratio  mean=%.4f  std=%.5f  threshold=%.4f",
        bl["https_ratio_mean"], bl["https_ratio_std"], bl["https_ratio_thr"],
    )

    # --- DNS flow count per device baseline --------------------------------
    dns_r = itr[itr["port"] == 53]
    dns_cnt_r = dns_r.groupby("src_ip").size()
    bl["dns_count_mean"] = dns_cnt_r.mean()
    bl["dns_count_std"]  = dns_cnt_r.std()
    bl["dns_count_thr"]  = dns_cnt_r.mean() + SIGMA * dns_cnt_r.std()
    log.info(
        "  DNS flow count/dev   mean=%.1f  std=%.1f  threshold=%.1f",
        bl["dns_count_mean"], bl["dns_count_std"], bl["dns_count_thr"],
    )

    # --- DNS per-flow upload size baseline ---------------------------------
    bl["dns_up_mean"] = dns_r["up_bytes"].mean()
    bl["dns_up_std"]  = dns_r["up_bytes"].std()
    bl["dns_up_thr"]  = dns_r["up_bytes"].mean() + SIGMA * dns_r["up_bytes"].std()
    log.info(
        "  DNS up_bytes/flow    mean=%.1f  std=%.1f  threshold=%.1f",
        bl["dns_up_mean"], bl["dns_up_std"], bl["dns_up_thr"],
    )

    # --- Botnet beaconing: per-(src,dst) CoV of intervals -----------------
    # Only external (public) destinations
    def is_public(ip: str) -> bool:
        return ipaddress.IPv4Address(ip) not in INTERNAL_NET

    itr_ext = itr[itr["dst_ip"].apply(is_public)].sort_values(
        ["src_ip", "dst_ip", "timestamp"]
    ).copy()
    itr_ext["diff"] = itr_ext.groupby(["src_ip", "dst_ip"])["timestamp"].diff()
    pair_r = itr_ext.groupby(["src_ip", "dst_ip"])["diff"].agg(["count", "mean", "std"])
    pair_r = pair_r[pair_r["count"] >= 30].copy()
    pair_r["cov"] = (pair_r["std"] / pair_r["mean"]).fillna(0)
    bl["beacon_cov_min"]  = pair_r["cov"].min()
    bl["beacon_cov_mean"] = pair_r["cov"].mean()
    bl["beacon_cov_std"]  = pair_r["cov"].std()
    # Threshold: anything BELOW mean-3σ (abnormally regular)
    # Floor at 0.10 to avoid flagging CDN bursts; true botnet shows CoV << 0.01
    bl["beacon_cov_thr"]  = max(
        pair_r["cov"].mean() - SIGMA * pair_r["cov"].std(), 0.10
    )
    log.info(
        "  Beacon CoV (pair)    min=%.3f  mean=%.3f  std=%.3f  threshold=%.3f",
        bl["beacon_cov_min"], bl["beacon_cov_mean"],
        bl["beacon_cov_std"], bl["beacon_cov_thr"],
    )

    # --- Baseline countries (from internal HTTPS to public IPs) -----------
    pub_https_r = itr[itr["port"] == 443]
    pub_ips_r   = pub_https_r[
        pub_https_r["dst_ip"].apply(is_public)
    ]["dst_ip"]
    cc_cache_r  = build_cc_cache(pub_ips_r, geodb)
    bl["train_countries"]    = set(cc_cache_r.values())
    bl["train_dst_ips"]      = set(pub_ips_r.unique())
    bl["cc_cache_train"]     = cc_cache_r
    log.info("  Known countries: %s", sorted(bl["train_countries"]))

    # --- External user baselines ------------------------------------------
    up_er      = etr.groupby("src_ip")["up_bytes"].sum()
    dn_er      = etr.groupby("src_ip")["down_bytes"].sum()
    ratio_er   = up_er / dn_er
    bl["ext_ratio_mean"] = ratio_er.mean()
    bl["ext_ratio_std"]  = ratio_er.std()
    bl["ext_ratio_lo"]   = ratio_er.mean() - SIGMA * ratio_er.std()
    bl["ext_ratio_hi"]   = ratio_er.mean() + SIGMA * ratio_er.std()
    log.info(
        "  Ext up/down ratio    mean=%.5f  std=%.6f  range=[%.5f, %.5f]",
        bl["ext_ratio_mean"], bl["ext_ratio_std"],
        bl["ext_ratio_lo"], bl["ext_ratio_hi"],
    )

    etr_s = etr.sort_values(["src_ip", "timestamp"]).copy()
    etr_s["diff"] = etr_s.groupby("src_ip")["timestamp"].diff()
    aibf_er = etr_s.groupby("src_ip")["diff"].mean()
    bl["ext_aibf_mean"] = aibf_er.mean()
    bl["ext_aibf_std"]  = aibf_er.std()
    bl["ext_aibf_thr"]  = aibf_er.mean() + SIGMA * aibf_er.std()
    log.info(
        "  Ext interval/flow    mean=%.1f  std=%.1f  threshold=%.1f",
        bl["ext_aibf_mean"], bl["ext_aibf_std"], bl["ext_aibf_thr"],
    )

    bl["train_ext_ips"] = set(etr["src_ip"].unique())

    return bl


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------

def rule_r1_botnet_beaconing(ite: pd.DataFrame, bl: dict) -> pd.DataFrame:
    """
    R1 – Internal BotNet: detect devices with extremely regular (low CoV)
    periodic connections to a SINGLE external IP address, sustained over the day.

    Two conditions must both be met:
      (a) CoV < beacon_cov_thr  (statistically abnormal regularity vs training)
      (b) mean_interval >= 6000 (1/100 s) = 60 s  — sustained periodic beaconing,
          not a short burst; and the flows span >= 10 % of the day.
    """
    log.info("=== R1: BotNet beaconing (per src/dst interval CoV) ===")

    def is_public(ip):
        return ipaddress.IPv4Address(ip) not in INTERNAL_NET

    ite_ext = ite[ite["dst_ip"].apply(is_public)].sort_values(
        ["src_ip", "dst_ip", "timestamp"]
    ).copy()
    ite_ext["diff"] = ite_ext.groupby(["src_ip", "dst_ip"])["timestamp"].diff()

    pair_t = ite_ext.groupby(["src_ip", "dst_ip"]).agg(
        count=("diff", "count"),
        mean_interval=("diff", "mean"),
        std_interval=("diff", "std"),
        ts_min=("timestamp", "min"),
        ts_max=("timestamp", "max"),
    )
    pair_t = pair_t[pair_t["count"] >= 30].copy()
    pair_t["cov"]      = (pair_t["std_interval"] / pair_t["mean_interval"]).fillna(0)
    pair_t["span"]     = pair_t["ts_max"] - pair_t["ts_min"]   # 1/100 s
    DAY_UNITS          = 86400 * 100                            # full day in 1/100s
    thr = bl["beacon_cov_thr"]

    # Require: low CoV AND mean interval >= 60 s AND spans >= 10 % of day
    flagged = pair_t[
        (pair_t["cov"] < thr)
        & (pair_t["mean_interval"] >= 6000)
        & (pair_t["span"] >= 0.10 * DAY_UNITS)
    ].reset_index()
    flagged["mean_interval_s"] = (flagged["mean_interval"] / 100).round(1)

    for _, row in flagged.iterrows():
        alert(
            "R1", "HIGH", row["src_ip"],
            f"BotNet beaconing → dst={row['dst_ip']}  "
            f"flows={int(row['count'])}  "
            f"mean_interval={row['mean_interval_s']:.1f}s  "
            f"CoV={row['cov']:.4f}  (threshold={thr:.4f})",
        )
    if flagged.empty:
        log.info("  No BotNet beaconing detected.")
    return flagged[["src_ip", "dst_ip", "count", "mean_interval_s", "cov"]]


def rule_r2_https_exfiltration(ite: pd.DataFrame, bl: dict) -> pd.DataFrame:
    """
    R2 – Data exfiltration via HTTPS: detect devices whose HTTPS upload/download
    ratio greatly exceeds the baseline (upload >> download implies data exfiltration).

    Threshold: ratio > mean + 3σ  (baseline mean≈0.108, threshold≈0.116)
    """
    log.info("=== R2: HTTPS data exfiltration (up/down ratio) ===")
    https_t = ite[ite["port"] == 443]
    up_t    = https_t.groupby("src_ip")["up_bytes"].sum()
    dn_t    = https_t.groupby("src_ip")["down_bytes"].sum()
    ratio_t = (up_t / dn_t).rename("ratio")
    thr     = bl["https_ratio_thr"]

    flagged = ratio_t[ratio_t > thr].reset_index()
    flagged["up_total"]  = up_t[flagged["src_ip"]].values
    flagged["dn_total"]  = dn_t[flagged["src_ip"]].values
    flagged = flagged.sort_values("ratio", ascending=False)

    for _, row in flagged.iterrows():
        alert(
            "R2", "HIGH", row["src_ip"],
            f"HTTPS exfiltration: up/down ratio={row['ratio']:.4f}  "
            f"(threshold={thr:.4f})  "
            f"up={int(row['up_total']):,}B  down={int(row['dn_total']):,}B",
        )
    if flagged.empty:
        log.info("  No HTTPS exfiltration detected.")
    return flagged[["src_ip", "ratio", "up_total", "dn_total"]]


def rule_r3_dns_exfiltration(ite: pd.DataFrame, bl: dict) -> pd.DataFrame:
    """
    R3 – Data exfiltration via DNS: detect devices generating an abnormally
    large number of DNS queries, consistent with DNS tunnelling (data encoded
    in query names / subdomain labels).

    Threshold: DNS flow count per device > mean + 3σ  (baseline max≈1446, thr≈1399)
    """
    log.info("=== R3: DNS data exfiltration (high DNS flow count) ===")
    dns_t   = ite[ite["port"] == 53]
    cnt_t   = dns_t.groupby("src_ip").size().rename("dns_flows")
    thr     = bl["dns_count_thr"]
    flagged = cnt_t[cnt_t > thr].reset_index().sort_values("dns_flows", ascending=False)

    for _, row in flagged.iterrows():
        up_mean = dns_t[dns_t["src_ip"] == row["src_ip"]]["up_bytes"].mean()
        alert(
            "R3", "HIGH", row["src_ip"],
            f"DNS exfiltration: dns_flows={int(row['dns_flows'])}  "
            f"(threshold={thr:.0f})  "
            f"mean_payload={up_mean:.0f}B",
        )
    if flagged.empty:
        log.info("  No DNS exfiltration detected.")
    return flagged[["src_ip", "dns_flows"]]


def rule_r4_cc_dns(ite: pd.DataFrame, bl: dict) -> pd.DataFrame:
    """
    R4 – C&C via DNS: detect devices issuing high-frequency DNS queries
    (very short mean interval between DNS flows), consistent with polling
    a C&C server for commands embedded in DNS responses.

    Flag devices where dns_flows > dns_count_thr / 4  AND  mean_interval < 200 (1/100s)
    (i.e. more than ~1 query every 2 s, over a sustained period).
    """
    log.info("=== R4: C&C via DNS (high-frequency DNS polling) ===")
    dns_t  = ite[ite["port"] == 53].sort_values(["src_ip", "timestamp"]).copy()
    dns_t["diff"] = dns_t.groupby("src_ip")["timestamp"].diff()
    stats  = dns_t.groupby("src_ip").agg(
        dns_flows=("up_bytes", "count"),
        mean_interval=("diff", "mean"),
    )
    # Must have anomalously many queries AND short intervals
    thr_cnt  = bl["dns_count_thr"] / 4   # more permissive count
    thr_int  = 200                         # < 2 s between queries (1/100 s units)

    flagged = stats[
        (stats["dns_flows"] > thr_cnt) & (stats["mean_interval"] < thr_int)
    ].reset_index().sort_values("dns_flows", ascending=False)

    for _, row in flagged.iterrows():
        interval_s = row["mean_interval"] / 100
        alert(
            "R4", "HIGH", row["src_ip"],
            f"C&C via DNS: flows={int(row['dns_flows'])}  "
            f"mean_interval={interval_s:.2f}s  "
            f"(thr_count>{thr_cnt:.0f}, thr_interval<{thr_int/100:.0f}s)",
        )
    if flagged.empty:
        log.info("  No C&C via DNS detected.")
    return flagged[["src_ip", "dns_flows", "mean_interval"]]


def rule_r5_anomalous_destinations(ite: pd.DataFrame, bl: dict, geodb) -> pd.DataFrame:
    """
    R5 – Anomalous external destinations: detect internal devices communicating
    with countries not present in the training baseline.

    Uses geo-localization of public destination IPs.
    """
    log.info("=== R5: Anomalous external destinations (new countries) ===")

    def is_public(ip):
        return ipaddress.IPv4Address(ip) not in INTERNAL_NET

    https_t = ite[ite["port"] == 443]
    pub_t   = https_t[https_t["dst_ip"].apply(is_public)].copy()

    # Re-use known cc cache; look up only new IPs
    known_cc   = bl["cc_cache_train"]
    new_ips    = [ip for ip in pub_t["dst_ip"].unique() if ip not in known_cc]
    new_cc_map = build_cc_cache(pd.Series(new_ips), geodb)
    cc_map     = {**known_cc, **new_cc_map}

    pub_t["dst_cc"] = pub_t["dst_ip"].map(cc_map).fillna("XX")
    train_cc = bl["train_countries"]
    new_country_flows = pub_t[~pub_t["dst_cc"].isin(train_cc)]

    if new_country_flows.empty:
        log.info("  No anomalous destinations detected.")
        return pd.DataFrame()

    # Aggregate: per (src_ip, country)
    summary = (
        new_country_flows.groupby(["src_ip", "dst_cc"])
        .agg(flows=("up_bytes", "count"), up_bytes=("up_bytes", "sum"))
        .reset_index()
        .sort_values(["src_ip", "flows"], ascending=[True, False])
    )

    for src_ip in summary["src_ip"].unique():
        sub = summary[summary["src_ip"] == src_ip]
        countries = ", ".join(
            f"{r['dst_cc']}({int(r['flows'])})" for _, r in sub.iterrows()
        )
        alert(
            "R5", "MEDIUM", src_ip,
            f"Traffic to new countries: {countries}",
        )
    return summary


def rule_r6_anomalous_external_users(ete: pd.DataFrame, bl: dict) -> pd.DataFrame:
    """
    R6 – Anomalous external users: detect external clients accessing corporate
    servers in an anomalous way (three sub-checks):
      R6a – Source IP not seen in training (entirely new client)
      R6b – Up/down ratio outside baseline range (abnormal request/response ratio)
      R6c – Mean inter-flow interval far above baseline (very slow / irregular access)
    """
    log.info("=== R6: Anomalous external users ===")
    results = []

    # R6a – new source IPs
    new_ips = sorted(set(ete["src_ip"].unique()) - bl["train_ext_ips"])
    for ip in new_ips:
        n = len(ete[ete["src_ip"] == ip])
        alert("R6a", "HIGH", ip, f"Unknown external client (not in baseline), flows={n}")
        results.append({"src_ip": ip, "reason": "new_client", "value": float(n)})

    # R6b – up/down ratio
    up_et  = ete.groupby("src_ip")["up_bytes"].sum()
    dn_et  = ete.groupby("src_ip")["down_bytes"].sum()
    ratio_et = up_et / dn_et
    lo, hi   = bl["ext_ratio_lo"], bl["ext_ratio_hi"]
    bad_ratio = ratio_et[(ratio_et < lo) | (ratio_et > hi)]
    for ip, val in bad_ratio.items():
        alert(
            "R6b", "MEDIUM", ip,
            f"Abnormal up/down ratio={val:.5f}  "
            f"(baseline=[{lo:.5f}, {hi:.5f}])",
        )
        results.append({"src_ip": ip, "reason": "ratio", "value": round(val, 6)})

    # R6c – inter-flow interval
    ete_s = ete.sort_values(["src_ip", "timestamp"]).copy()
    ete_s["diff"] = ete_s.groupby("src_ip")["timestamp"].diff()
    aibf_t = ete_s.groupby("src_ip")["diff"].mean()
    thr_aibf = bl["ext_aibf_thr"]
    bad_interval = aibf_t[aibf_t > thr_aibf]
    for ip, val in bad_interval.items():
        alert(
            "R6c", "MEDIUM", ip,
            f"Abnormal mean inter-flow interval={val/100:.1f}s  "
            f"(threshold={thr_aibf/100:.1f}s)",
        )
        results.append({"src_ip": ip, "reason": "interval", "value": round(val, 2)})

    if not results:
        log.info("  No anomalous external users detected.")
    return pd.DataFrame(results) if results else pd.DataFrame()


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

def print_summary(
    r1, r2, r3, r4, r5, r6
):
    sep = "=" * 70
    print(f"\n{sep}")
    print("  UEBA / SIEM ANOMALY DETECTION REPORT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(sep)

    print("\n--- R1: Internal BotNet (beaconing) ---")
    if r1.empty:
        print("  No anomalies detected.")
    else:
        for _, row in r1.iterrows():
            print(
                f"  [ALERT] {row['src_ip']}  →  {row['dst_ip']}"
                f"  flows={int(row['count'])}  interval={row['mean_interval_s']:.1f}s"
                f"  CoV={row['cov']:.4f}"
            )

    print("\n--- R2: HTTPS Data Exfiltration ---")
    if r2.empty:
        print("  No anomalies detected.")
    else:
        for _, row in r2.iterrows():
            print(
                f"  [ALERT] {row['src_ip']}  ratio={row['ratio']:.4f}"
                f"  up={int(row['up_total']):,}B  down={int(row['dn_total']):,}B"
            )

    print("\n--- R3: DNS Data Exfiltration ---")
    if r3.empty:
        print("  No anomalies detected.")
    else:
        for _, row in r3.iterrows():
            print(f"  [ALERT] {row['src_ip']}  dns_flows={int(row['dns_flows'])}")

    print("\n--- R4: C&C via DNS ---")
    if r4.empty:
        print("  No anomalies detected.")
    else:
        for _, row in r4.iterrows():
            print(
                f"  [ALERT] {row['src_ip']}  dns_flows={int(row['dns_flows'])}"
                f"  mean_interval={row['mean_interval']/100:.2f}s"
            )

    print("\n--- R5: Anomalous External Destinations ---")
    if r5 is None or r5.empty:
        print("  No anomalies detected.")
    else:
        for ip in r5["src_ip"].unique():
            sub = r5[r5["src_ip"] == ip]
            cc_list = ", ".join(
                f"{r['dst_cc']}({int(r['flows'])} flows)" for _, r in sub.iterrows()
            )
            print(f"  [ALERT] {ip}  new countries: {cc_list}")

    print("\n--- R6: Anomalous External Users ---")
    if r6 is None or r6.empty:
        print("  No anomalies detected.")
    else:
        for _, row in r6.iterrows():
            print(
                f"  [ALERT] {row['src_ip']}  reason={row['reason']}"
                f"  value={row['value']}"
            )

    # Unique flagged IPs
    internal_flagged = set()
    for df in [r1, r2, r3, r4]:
        if df is not None and not df.empty:
            internal_flagged.update(df["src_ip"].unique())
    if r5 is not None and not r5.empty:
        internal_flagged.update(r5["src_ip"].unique())

    external_flagged = set()
    if r6 is not None and not r6.empty:
        external_flagged.update(r6["src_ip"].unique())

    print(f"\n{sep}")
    print(f"  Internal anomalous IPs ({len(internal_flagged)}):")
    for ip in sorted(internal_flagged):
        print(f"    {ip}")
    print(f"\n  External anomalous IPs ({len(external_flagged)}):")
    for ip in sorted(external_flagged):
        print(f"    {ip}")
    print(sep)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("Loading datasets …")
    itr = pd.read_json(INTERNAL_TRAIN)
    ite = pd.read_json(INTERNAL_TEST)
    etr = pd.read_json(EXTERNAL_TRAIN)
    ete = pd.read_json(EXTERNAL_TEST)

    log.info(
        "  internal_train=%d rows  internal_test=%d rows",
        len(itr), len(ite),
    )
    log.info(
        "  external_train=%d rows  external_test=%d rows",
        len(etr), len(ete),
    )

    geodb    = geoip2.database.Reader(GEODB_COUNTRY)
    geodbasn = geoip2.database.Reader(GEODB_ASN)

    bl = compute_baselines(itr, etr, geodb)

    log.info("\nApplying UEBA rules to test datasets …\n")
    r1 = rule_r1_botnet_beaconing(ite, bl)
    r2 = rule_r2_https_exfiltration(ite, bl)
    r3 = rule_r3_dns_exfiltration(ite, bl)
    r4 = rule_r4_cc_dns(ite, bl)
    r5 = rule_r5_anomalous_destinations(ite, bl, geodb)
    r6 = rule_r6_anomalous_external_users(ete, bl)

    print_summary(r1, r2, r3, r4, r5, r6)

    geodb.close()
    geodbasn.close()

    if SYSLOG_AVAILABLE:
        log.info("Alerts also forwarded to rsyslog (/dev/log).")
    else:
        log.info("rsyslog not available (running without /dev/log).")


if __name__ == "__main__":
    main()
