# UEBA/SIEM anomaly detection report

Generated: 2026-06-05 14:22:32 UTC

## Objective

This report documents the UEBA module developed for the SIEM project. The goal is to learn normal behaviour from anomaly-free historical flow logs and then detect anomalous devices in the test logs. The implemented detector analyses internal clients, external clients, traffic volumes, upload/download ratios, timing patterns, destination countries and destination ASN/owner information.

The training files are treated as clean ground truth. For that reason, each rule is calibrated using values observed in the training data and the script validates that the same rules produce zero alerts when applied back to the training files.

## Dataset and analysis method

- Internal training rows: `890749`; internal test rows: `1008425`.
- External training rows: `712488`; external test rows: `681696`.
- Internal training devices: `198`; external training clients: `196`.

The analysis was performed in four steps:

1. Infer the normal network structure from `internal_train1.json` and `external_train1.json`.
2. Quantify normal behaviour: services, flow counts, byte totals, upload/download ratios, inter-flow intervals, countries and ASNs.
3. Define UEBA rules using only thresholds derived from the clean training data.
4. Apply the rules to the test datasets and report anomalous IPs with the metric observed, the threshold used and a severity level.

## Normal behaviour learned from training data

- Internal network: `192.168.101.0/24`
- Allowed internal services: `192.168.101.226:53/udp`, `192.168.101.229:53/udp`, `192.168.101.240:443/tcp`
- Corporate public servers observed from external accesses: `200.0.0.11`, `200.0.0.12`
- HTTPS up/down ratio range: `0.098509` to `0.116756`; ratio-factor threshold `1.185`
- DNS max flows per device: `1446`; minimum clean DNS mean interval: `22.23s`
- DNS exfiltration threshold: total DNS upload `>290254B` and mean_up `>211.13B` or up/down `>0.4755`
- DNS/HTTPS clean balance: max byte-ratio `0.003383`, max flow-ratio `0.2054` (used by R3b)
- Known destination countries: `36`; known destination owners (ASNs): `39`; new-destination high severity threshold: `339` flows
- External user ratio range: `0.116103` to `0.118993`; 3-sigma band `[0.115953, 0.119287]`; max clean interval `21.44s`

The most important conclusion from the clean data is that internal clients normally contact only three internal services: two DNS servers and one HTTPS server. Any internal traffic to other private clients is therefore suspicious. Another important conclusion is that normal HTTPS traffic is download-heavy: the upload/download ratio stays below `0.116756` in the clean day. For external users, the amount of traffic is not the main signal; the useful signals are ratio drift and timing drift.

## Rule design and justification

### R1 - Internal BotNet activity

R1 has two sub-rules. `R1a` detects internal lateral communication: if a private destination service was not present in the clean training day, it is considered anomalous. This follows the observation that normal internal traffic only targets the known DNS/HTTPS servers. `R1b` detects beaconing to one external destination by measuring the coefficient of variation of inter-flow intervals; highly regular periodic traffic is a typical C&C/beaconing pattern.

### R2 - HTTPS data exfiltration

R2 detects devices whose HTTPS upload/download ratio deviates strongly from both the global clean maximum and their own clean historical ratio. This avoids false positives from small natural fluctuations and focuses on devices sending data in a way that is incompatible with the normal download-heavy HTTPS baseline.

### R3 - DNS data exfiltration

R3 uses two complementary signals. `R3a` alerts when DNS upload volume is above the historical maximum and the payload size / up-down ratio also deviates from the clean baseline. `R3b` compares each device's DNS-to-HTTPS byte ratio against the clean maximum: a device tunnelling data over DNS shows an abnormally large DNS payload relative to its own normal HTTPS usage, even when the absolute DNS volume still looks modest. R3b surfaces a device that the volume-only test misses and also corroborates the DNS C&C devices reported by R4.

### R4 - C&C via DNS

R4 detects DNS command-and-control behaviour using two simultaneous conditions: more DNS flows than any clean device and a mean interval between DNS flows shorter than the clean minimum. This captures polling-like DNS behaviour without confusing it with normal DNS usage.

### R5 - Anomalous external destinations

R5 flags HTTPS traffic to destinations never seen in the clean training day. A destination is novel when its country *or* its owner (ASN) was not contacted during training. Owner novelty is the stronger signal: it detects a brand-new network operator even inside a known country, and avoids false positives from a known CDN owner serving from a new country edge. Severity is higher when the total number of novel-destination flows exceeds the 75th percentile of normal per-device/per-country flow counts.

### R6 - Anomalous external users

R6 analyses external clients accessing the corporate public servers. New source IPs are not automatically anomalous because the assignment states that the anomaly is not simply traffic amount or flow count. Instead, R6 flags clients whose upload/download ratio falls outside the 3-sigma band of the clean external-client ratio, or whose mean interval between flows exceeds the maximum clean interval. Timing is the primary behavioural signal; the statistical ratio band keeps the secondary ratio check from firing on normal fluctuation.

## Validation

The script applies all rules to the clean training datasets before testing. The implemented version passed this check with `0` training alerts. This is an important sanity check: if a rule alerts on the known-good history, the threshold is too aggressive or poorly justified.

## Rule results on test data

### R1 - Internal BotNet activity

```
rule severity          src_ip                                                                                                                                                                                  detail
 R1a     HIGH 192.168.101.138  Unauthorized internal service dst=192.168.101.68:443/tcp flows=114 up=296230B down=299861B; allowed_services=[192.168.101.226:53/udp, 192.168.101.229:53/udp, 192.168.101.240:443/tcp]
 R1a     HIGH 192.168.101.138  Unauthorized internal service dst=192.168.101.186:443/tcp flows=95 up=215723B down=215486B; allowed_services=[192.168.101.226:53/udp, 192.168.101.229:53/udp, 192.168.101.240:443/tcp]
 R1a     HIGH 192.168.101.186 Unauthorized internal service dst=192.168.101.138:443/tcp flows=223 up=527827B down=522907B; allowed_services=[192.168.101.226:53/udp, 192.168.101.229:53/udp, 192.168.101.240:443/tcp]
 R1a     HIGH 192.168.101.186  Unauthorized internal service dst=192.168.101.68:443/tcp flows=206 up=484293B down=486554B; allowed_services=[192.168.101.226:53/udp, 192.168.101.229:53/udp, 192.168.101.240:443/tcp]
 R1a     HIGH  192.168.101.68 Unauthorized internal service dst=192.168.101.138:443/tcp flows=139 up=354442B down=355331B; allowed_services=[192.168.101.226:53/udp, 192.168.101.229:53/udp, 192.168.101.240:443/tcp]
 R1a     HIGH  192.168.101.68 Unauthorized internal service dst=192.168.101.186:443/tcp flows=134 up=312701B down=306442B; allowed_services=[192.168.101.226:53/udp, 192.168.101.229:53/udp, 192.168.101.240:443/tcp]
 R1b     HIGH 192.168.101.187                                                                                     External beaconing dst=216.58.192.40 flows=36 mean_interval=1199.9s cov=0.0011 threshold_cov<1.0360
 R1b     HIGH 192.168.101.197                                                                                      External beaconing dst=104.244.43.1 flows=185 mean_interval=120.1s cov=0.0084 threshold_cov<1.0360
 R1b     HIGH  192.168.101.26                                                                                    External beaconing dst=104.244.43.221 flows=362 mean_interval=120.0s cov=0.0086 threshold_cov<1.0360
```

### R2 - HTTPS Data Exfiltration

```
rule severity          src_ip                                                                                                                                         detail
  R2     HIGH  192.168.101.14 HTTPS up/down ratio=18.6467 train_ratio=0.1089 ratio_factor=171.25 threshold_ratio>0.1168 threshold_factor>1.19 up=5352080158B down=287025750B
  R2     HIGH 192.168.101.208   HTTPS up/down ratio=8.9710 train_ratio=0.1020 ratio_factor=87.93 threshold_ratio>0.1168 threshold_factor>1.19 up=4402039688B down=490694588B
  R2     HIGH 192.168.101.187  HTTPS up/down ratio=7.3984 train_ratio=0.1096 ratio_factor=67.53 threshold_ratio>0.1168 threshold_factor>1.19 up=7586286509B down=1025390501B
  R2     HIGH  192.168.101.26     HTTPS up/down ratio=0.5063 train_ratio=0.1094 ratio_factor=4.63 threshold_ratio>0.1168 threshold_factor>1.19 up=259246737B down=511993215B
  R2     HIGH 192.168.101.197     HTTPS up/down ratio=0.4203 train_ratio=0.1081 ratio_factor=3.89 threshold_ratio>0.1168 threshold_factor>1.19 up=138302804B down=329086638B
  R2     HIGH 192.168.101.188      HTTPS up/down ratio=0.2634 train_ratio=0.1058 ratio_factor=2.49 threshold_ratio>0.1168 threshold_factor>1.19 up=39410573B down=149630219B
```

### R3 - DNS Data Exfiltration

```
rule severity          src_ip                                                                                                                                         detail
 R3b     HIGH  192.168.101.41 DNS/HTTPS imbalance byte_ratio=0.173889 (dns_up=7898782B / https_up=45424252B) dns_flows=39493 https_flows=3965; threshold byte_ratio>0.003383
 R3b     HIGH  192.168.101.23  DNS/HTTPS imbalance byte_ratio=0.075266 (dns_up=1734018B / https_up=23038429B) dns_flows=8651 https_flows=1990; threshold byte_ratio>0.003383
 R3b     HIGH  192.168.101.32       DNS/HTTPS imbalance byte_ratio=0.007187 (dns_up=46530B / https_up=6473967B) dns_flows=240 https_flows=575; threshold byte_ratio>0.003383
 R3b     HIGH 192.168.101.148   DNS/HTTPS imbalance byte_ratio=0.006617 (dns_up=329313B / https_up=49768696B) dns_flows=1661 https_flows=4370; threshold byte_ratio>0.003383
 R3b     HIGH 192.168.101.201   DNS/HTTPS imbalance byte_ratio=0.006011 (dns_up=583107B / https_up=97001879B) dns_flows=2941 https_flows=8463; threshold byte_ratio>0.003383
```

### R4 - C&C via DNS

```
rule severity          src_ip                                                                                          detail
  R4     HIGH  192.168.101.41 DNS C&C polling flows=39493 mean_interval=0.78s; thresholds flows>1446 and mean_interval<22.23s
  R4     HIGH  192.168.101.23  DNS C&C polling flows=8651 mean_interval=1.10s; thresholds flows>1446 and mean_interval<22.23s
  R4     HIGH 192.168.101.201 DNS C&C polling flows=2941 mean_interval=15.33s; thresholds flows>1446 and mean_interval<22.23s
  R4     HIGH 192.168.101.148 DNS C&C polling flows=1661 mean_interval=17.23s; thresholds flows>1446 and mean_interval<22.23s
```

### R5 - Anomalous External Destinations

```
rule severity          src_ip                                                                                                                                                                                                                                                                                    detail
  R5     HIGH 192.168.101.125                                Traffic to never-seen destinations new_countries=RU(411), IR(75), UA(11), BG(8), SC(5), PL(4), FI(3), LV(2), CZ(2), DK(1), PY(1); new_owners=PJSC Rostelecom(23), CHINA UNICOM China169 Backbone(21), Apple Inc.(19); total_flows=659; high_threshold>=339
  R5   MEDIUM 192.168.101.167                                                                                                                                                                               Traffic to never-seen destinations new_countries=BE(9); new_owners=none; total_flows=9; high_threshold>=339
  R5   MEDIUM 192.168.101.175                                                                                                                                                                               Traffic to never-seen destinations new_countries=BE(4); new_owners=none; total_flows=4; high_threshold>=339
  R5   MEDIUM 192.168.101.189                                                                                                                                                                               Traffic to never-seen destinations new_countries=BE(2); new_owners=none; total_flows=2; high_threshold>=339
  R5     HIGH  192.168.101.36 Traffic to never-seen destinations new_countries=RU(720), IR(125), EE(9), KZ(8), IQ(6), UA(6), GE(5), BY(5), CZ(4), LU(4), BA(3), AR(2), FI(2), PL(2), BG(1), HU(1), LV(1); new_owners=PJSC Rostelecom(44), PJSC "Vimpelcom"(21), JSC Selectel(18); total_flows=1100; high_threshold>=339
  R5     HIGH  192.168.101.72                Traffic to never-seen destinations new_countries=RU(925), IR(164), KZ(11), UA(10), BY(10), PL(7), BD(5), GR(5), NG(5), BZ(4), FI(3), HR(2), EE(2), LV(2), LU(2); new_owners=PJSC Rostelecom(34), PJSC MegaFon(33), JSC Selectel(29); total_flows=1427; high_threshold>=339
```

### R6 - Anomalous External Users

```
     rule severity        src_ip                                                                                                                                 detail
 R6_ratio   MEDIUM 188.83.72.182   External user low up/down ratio=0.115455; train_ratio=0.118945; threshold=ratio outside 3-sigma band [0.115953, 0.119287]; flows=769
 R6_ratio   MEDIUM 188.83.72.210   External user low up/down ratio=0.115688; train_ratio=0.117941; threshold=ratio outside 3-sigma band [0.115953, 0.119287]; flows=239
 R6_ratio   MEDIUM  188.83.72.64 External user high up/down ratio=0.119927; train_ratio=0.117160; threshold=ratio outside 3-sigma band [0.115953, 0.119287]; flows=1496
 R6_ratio   MEDIUM 188.83.72.174  External user high up/down ratio=0.119986; train_ratio=0.116757; threshold=ratio outside 3-sigma band [0.115953, 0.119287]; flows=906
 R6_ratio   MEDIUM  188.83.72.61  External user high up/down ratio=0.121477; train_ratio=0.117190; threshold=ratio outside 3-sigma band [0.115953, 0.119287]; flows=477
R6_timing   MEDIUM  188.83.72.55                                          External user abnormal timing mean_interval=43.11s; threshold=mean_interval>21.44s; flows=517
R6_timing   MEDIUM 188.83.72.194                                          External user abnormal timing mean_interval=24.30s; threshold=mean_interval>21.44s; flows=819
R6_timing   MEDIUM  188.83.72.65                                          External user abnormal timing mean_interval=22.15s; threshold=mean_interval>21.44s; flows=704
R6_timing   MEDIUM 188.83.72.114                                          External user abnormal timing mean_interval=22.08s; threshold=mean_interval>21.44s; flows=776
R6_timing   MEDIUM  188.83.72.96                                         External user abnormal timing mean_interval=21.88s; threshold=mean_interval>21.44s; flows=1662
```

## Final anomalous IP lists

Internal: `192.168.101.125`, `192.168.101.138`, `192.168.101.14`, `192.168.101.148`, `192.168.101.167`, `192.168.101.175`, `192.168.101.186`, `192.168.101.187`, `192.168.101.188`, `192.168.101.189`, `192.168.101.197`, `192.168.101.201`, `192.168.101.208`, `192.168.101.23`, `192.168.101.26`, `192.168.101.32`, `192.168.101.36`, `192.168.101.41`, `192.168.101.68`, `192.168.101.72`

External: `188.83.72.114`, `188.83.72.174`, `188.83.72.182`, `188.83.72.194`, `188.83.72.210`, `188.83.72.55`, `188.83.72.61`, `188.83.72.64`, `188.83.72.65`, `188.83.72.96`

## Conclusions

The strongest internal findings are the unauthorized private communications between `192.168.101.68`, `192.168.101.138` and `192.168.101.186`, the HTTPS exfiltration candidates with large upload/download ratio drift, and the DNS C&C candidates with very short polling intervals. The anomalous-destination rule also identified three high-severity devices contacting many destinations in countries absent from the clean baseline: `192.168.101.36`, `192.168.101.72` and `192.168.101.125`.

For external users, the flagged clients are anomalous because of behavioural differences, not because they are new IPs or because they generated the largest amount of traffic. The relevant signals were upload/download ratio drift and longer-than-normal inter-flow intervals.

## SIEM reporting

Every alert is printed to console with `rule`, `severity`, `src_ip` and the metric/threshold justification. The script can also send alerts to a remote SIEM/Wazuh syslog endpoint using `--syslog-host` and `--syslog-port`. The emitted syslog message starts with `Alarm UEBA <src_ip>`, matching the decoder structure used in the SIEM class material.

## Future work: plots for Overleaf

The report would benefit from plots when moved to Overleaf. The most useful figures would be: HTTPS upload/download ratio boxplots for train vs test, DNS flow-count and mean-interval scatter plots, a bar chart of new-country flows per source IP, and external-user ratio/interval plots. These plots were left as future work to keep the current deliverable focused on the validated rules and numeric justifications.
