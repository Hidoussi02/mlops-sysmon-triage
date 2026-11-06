#!/usr/bin/env python3
import json, csv
from datetime import datetime, timedelta, timezone
from collections import Counter

BASE = "/home/ghaith/dataset-ml/"
BUFFER = timedelta(minutes=3)
OFFSETS = {"kali": 0, "atomic": 0}   # set to your real offsets if not UTC

def parse_wazuh(s):
    s = s.replace("+0000", "+00:00")
    return datetime.fromisoformat(s).astimezone(timezone.utc)

def to_utc(s, source):
    tz = timezone(timedelta(hours=OFFSETS[source.strip().lower()]))
    naive = datetime.strptime(s.strip(), "%Y-%m-%d %H:%M:%S")
    return naive.replace(tzinfo=tz).astimezone(timezone.utc)

windows = []
with open(BASE + "attack_log.csv") as f:
    for r in csv.DictReader(f):
        windows.append({
            "tid": r["technique_id"], "src": r["source"].strip(),
            "start": to_utc(r["start_time"], r["source"]) - BUFFER,
            "end": to_utc(r["end_time"], r["source"]) + BUFFER,
        })

fields = ["timestamp","event_id","rule_id","rule_level","rule_description",
          "agent_name","agent_ip","source_ip","target_user","logon_type",
          "process_name","label","technique_id","attack_source"]

rows, counts, first_bad = [], Counter(), None
with open(BASE + "win10_all_raw.jsonl") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule, agent = e.get("rule", {}), e.get("agent", {})
        win = e.get("data", {}).get("win", {})
        evtd, sysd = win.get("eventdata", {}), win.get("system", {})
        ts = e.get("timestamp", "")
        label, tid, src = "NORMAL", "", ""
        try:
            t = parse_wazuh(ts)
            for w in windows:
                if w["start"] <= t <= w["end"]:
                    label, tid, src = "MALICIOUS", w["tid"], w["src"]
                    break
        except Exception:
            label = "UNKNOWN"
            first_bad = first_bad or ts
        counts[label] += 1
        rows.append({
            "timestamp": ts, "event_id": sysd.get("eventID", ""),
            "rule_id": rule.get("id", ""), "rule_level": rule.get("level", ""),
            "rule_description": rule.get("description", ""),
            "agent_name": agent.get("name", ""), "agent_ip": agent.get("ip", ""),
            "source_ip": evtd.get("ipAddress", ""), "target_user": evtd.get("targetUserName", ""),
            "logon_type": evtd.get("logonType", ""), "process_name": evtd.get("newProcessName", ""),
            "label": label, "technique_id": tid, "attack_source": src,
        })

with open(BASE + "win10_dataset_labeled.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)

print("TOTAL:", len(rows), dict(counts))
print("By technique:", dict(Counter(r["technique_id"] for r in rows if r["label"]=="MALICIOUS")))
if first_bad:
    print("First unparsed timestamp:", first_bad)
