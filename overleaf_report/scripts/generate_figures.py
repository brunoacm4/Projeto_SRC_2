#!/usr/bin/env python3
"""Generate the figures used by the Overleaf report."""

from __future__ import annotations

from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
FIG_DIR = Path(__file__).resolve().parents[1] / "figures"
sys.path.insert(0, str(ROOT))

import ueba_siem as ueba  # noqa: E402


plt.rcParams.update(
    {
        "figure.figsize": (8.2, 4.6),
        "axes.grid": True,
        "grid.alpha": 0.25,
        "font.size": 9,
        "axes.titlesize": 11,
        "axes.labelsize": 9,
        "legend.fontsize": 8,
        "savefig.bbox": "tight",
    }
)


BLUE = "#2c7fb8"
ORANGE = "#f28e2b"
RED = "#d62728"
GREEN = "#59a14f"
GRAY = "#6b7280"


def load_analysis():
    itr = pd.read_json(ROOT / ueba.INTERNAL_TRAIN)
    ite = pd.read_json(ROOT / ueba.INTERNAL_TEST)
    etr = pd.read_json(ROOT / ueba.EXTERNAL_TRAIN)
    ete = pd.read_json(ROOT / ueba.EXTERNAL_TEST)

    geodb = ueba.geoip2.database.Reader(str(ROOT / ueba.GEODB_COUNTRY))
    geodbasn = ueba.geoip2.database.Reader(str(ROOT / ueba.GEODB_ASN))
    try:
        bl = ueba.compute_baselines(itr, etr, geodb, geodbasn)
        results = ueba.run_rules(ite, ete, bl, geodb, geodbasn, emit=False)
    finally:
        geodb.close()
        geodbasn.close()

    return itr, ite, etr, ete, bl, results


def save(fig, name: str) -> None:
    fig.savefig(FIG_DIR / name)
    plt.close(fig)


def plot_internal_services(itr, ite, bl):
    internal_net = bl["internal_net"]
    private_train = itr[
        itr["dst_ip"].apply(lambda ip: ueba.is_in_network(ip, internal_net))
    ].copy()
    private_train["service"] = (
        private_train["dst_ip"]
        + ":"
        + private_train["port"].astype(str)
        + "/"
        + private_train["proto"]
    )
    normal_counts = private_train["service"].value_counts().sort_values()

    private_test = ite[
        ite["dst_ip"].apply(lambda ip: ueba.is_in_network(ip, internal_net))
    ].copy()
    allowed = pd.DataFrame(
        list(bl["allowed_internal_services"]),
        columns=["dst_ip", "port", "proto"],
    )
    unexpected = private_test.merge(
        allowed.assign(_allowed=True),
        on=["dst_ip", "port", "proto"],
        how="left",
    )
    unexpected = unexpected[unexpected["_allowed"].isna()].copy()
    unexpected["pair"] = unexpected["src_ip"] + " -> " + unexpected["dst_ip"]
    unexpected_counts = unexpected["pair"].value_counts().sort_values()

    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2))
    normal_counts.plot(kind="barh", ax=axes[0], color=BLUE)
    axes[0].set_title("Clean internal services")
    axes[0].set_xlabel("flows in internal_train")
    axes[0].set_ylabel("")

    unexpected_counts.plot(kind="barh", ax=axes[1], color=RED)
    axes[1].set_title("Unexpected internal communication")
    axes[1].set_xlabel("flows in internal_test")
    axes[1].set_ylabel("")
    fig.suptitle("Internal service baseline and BotNet/lateral movement signal")
    save(fig, "internal_services.pdf")


def plot_https_ratios(itr, ite, bl, results):
    train = ueba.https_stats(itr)
    test = ueba.https_stats(ite)
    r2_ips = set(results["R2"]["src_ip"]) if not results["R2"].empty else set()

    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2))

    axes[0].boxplot(
        [train["ratio"].dropna(), test["ratio"].dropna()],
        labels=["train", "test"],
        showfliers=False,
        patch_artist=True,
        boxprops={"facecolor": "#dbeafe", "edgecolor": BLUE},
        medianprops={"color": RED},
    )
    axes[0].axhline(bl["https_ratio_max"], color=RED, linestyle="--", linewidth=1)
    axes[0].set_title("HTTPS up/down ratio distribution")
    axes[0].set_ylabel("upload/download ratio")
    axes[0].text(
        1.52,
        bl["https_ratio_max"],
        "clean max",
        color=RED,
        va="bottom",
        fontsize=8,
    )

    top = test.sort_values("ratio", ascending=False).head(10).copy()
    colors = [RED if ip in r2_ips else GRAY for ip in top.index]
    axes[1].barh(top.index, top["ratio"], color=colors)
    axes[1].axvline(bl["https_ratio_max"], color=RED, linestyle="--", linewidth=1)
    axes[1].set_xscale("log")
    axes[1].invert_yaxis()
    axes[1].set_title("Top HTTPS ratio devices in test")
    axes[1].set_xlabel("upload/download ratio (log scale)")

    fig.suptitle("HTTPS exfiltration: ratio drift from clean behaviour")
    save(fig, "https_ratios.pdf")


def plot_dns_cc(itr, ite, bl, results):
    train = ueba.dns_stats(itr).dropna(subset=["mean_interval"])
    test = ueba.dns_stats(ite).dropna(subset=["mean_interval"])
    r4_ips = set(results["R4"]["src_ip"]) if not results["R4"].empty else set()
    r4 = test.loc[test.index.intersection(r4_ips)]

    fig, ax = plt.subplots(figsize=(8.4, 4.8))
    ax.scatter(
        train["mean_interval"] / 100,
        train["dns_flows"],
        s=22,
        alpha=0.45,
        color=BLUE,
        label="clean train devices",
    )
    ax.scatter(
        test["mean_interval"] / 100,
        test["dns_flows"],
        s=22,
        alpha=0.35,
        color=GRAY,
        label="test devices",
    )
    if not r4.empty:
        ax.scatter(
            r4["mean_interval"] / 100,
            r4["dns_flows"],
            s=70,
            color=RED,
            label="R4 alerts",
            edgecolor="black",
            linewidth=0.4,
        )
        for ip, row in r4.iterrows():
            ax.annotate(ip.split(".")[-1], (row["mean_interval"] / 100, row["dns_flows"]))

    ax.axhline(bl["dns_flow_max"], color=RED, linestyle="--", linewidth=1)
    ax.axvline(bl["dns_mean_interval_min"] / 100, color=RED, linestyle="--", linewidth=1)
    ax.set_yscale("log")
    ax.set_xlabel("mean interval between DNS flows (s)")
    ax.set_ylabel("DNS flows per device (log scale)")
    ax.set_title("DNS C&C: high flow count plus short polling interval")
    ax.legend(loc="best")
    save(fig, "dns_cc_scatter.pdf")


def plot_new_country_flows(results, bl):
    r5 = results["R5"]
    if r5.empty:
        return
    totals = (
        r5.groupby(["src_ip", "severity"])["flows"]
        .sum()
        .reset_index()
        .sort_values("flows", ascending=True)
    )
    colors = [RED if sev == "HIGH" else ORANGE for sev in totals["severity"]]

    fig, ax = plt.subplots(figsize=(8.6, 4.5))
    ax.barh(totals["src_ip"], totals["flows"], color=colors)
    ax.axvline(bl["country_flow_high_thr"], color=RED, linestyle="--", linewidth=1)
    ax.set_xlabel("flows to countries unseen in training")
    ax.set_ylabel("source IP")
    ax.set_title("Anomalous external destinations by source")
    ax.text(
        bl["country_flow_high_thr"] * 1.02,
        -0.35,
        "high severity threshold",
        color=RED,
        fontsize=8,
    )
    save(fig, "new_country_flows.pdf")


def plot_external_users(etr, ete, bl, results):
    train = ueba.external_user_stats(etr)
    test = ueba.external_user_stats(ete)
    r6 = results["R6"]
    ratio_ips = set(r6.loc[r6["rule"] == "R6_ratio", "src_ip"]) if not r6.empty else set()
    timing_ips = set(r6.loc[r6["rule"] == "R6_timing", "src_ip"]) if not r6.empty else set()

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    axes[0].scatter(range(len(train)), train["ratio"].sort_values(), color=BLUE, alpha=0.45, label="train")
    test_sorted = test["ratio"].sort_values()
    point_colors = [RED if ip in ratio_ips else GRAY for ip in test_sorted.index]
    axes[0].scatter(range(len(test_sorted)), test_sorted, color=point_colors, alpha=0.7, label="test")
    axes[0].axhline(bl["ext_ratio_min"], color=RED, linestyle="--", linewidth=1)
    axes[0].axhline(bl["ext_ratio_max"], color=RED, linestyle="--", linewidth=1)
    axes[0].set_title("External client up/down ratio")
    axes[0].set_xlabel("clients sorted by ratio")
    axes[0].set_ylabel("upload/download ratio")

    train_int = (train["mean_interval"] / 100).sort_values()
    test_int = (test["mean_interval"] / 100).sort_values()
    point_colors = [RED if ip in timing_ips else GRAY for ip in test_int.index]
    axes[1].scatter(range(len(train_int)), train_int, color=BLUE, alpha=0.45, label="train")
    axes[1].scatter(range(len(test_int)), test_int, color=point_colors, alpha=0.7, label="test")
    axes[1].axhline(bl["ext_interval_max"] / 100, color=RED, linestyle="--", linewidth=1)
    axes[1].set_title("External client timing")
    axes[1].set_xlabel("clients sorted by interval")
    axes[1].set_ylabel("mean interval between flows (s)")
    axes[1].legend(loc="best")

    fig.suptitle("External users: behavioural drift, not traffic volume")
    save(fig, "external_users.pdf")


def plot_rule_counts(results):
    counts = {rule: len(df.drop_duplicates(["rule", "src_ip", "detail"])) for rule, df in results.items()}
    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    ax.bar(counts.keys(), counts.values(), color=[BLUE, RED, GRAY, RED, ORANGE, GREEN])
    ax.set_ylabel("alerts")
    ax.set_title("Alerts generated by each UEBA rule")
    for i, value in enumerate(counts.values()):
        ax.text(i, value + 0.2, str(value), ha="center", va="bottom")
    save(fig, "rule_counts.pdf")


def main():
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    itr, ite, etr, ete, bl, results = load_analysis()
    plot_internal_services(itr, ite, bl)
    plot_https_ratios(itr, ite, bl, results)
    plot_dns_cc(itr, ite, bl, results)
    plot_new_country_flows(results, bl)
    plot_external_users(etr, ete, bl, results)
    plot_rule_counts(results)
    print(f"Figures written to {FIG_DIR}")


if __name__ == "__main__":
    main()
