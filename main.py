"""Validate DNSSEC-related records (DS/DNSKEY) in a zone file.

Usage: python3 main.py zone.txt
A zone is defined by its SOA record. For each zone this checks
whether DS and DNSKEY records exist under the zone apex:
- SECURE: both DS and DNSKEY are present.
- PARTIAL: only one of DS / DNSKEY is present.
- UNSIGNED: neither DS nor DNSKEY is present.
A DS record needs at least a key tag, algorithm, digest type
and digest; a DNSKEY record needs at least flags, protocol,
algorithm and a public key. Records that are too short, or DS /
DNSKEY records whose owner name is not a zone apex, are
reported as skipped, not silently dropped. UNSIGNED zones come
first, then PARTIAL, then SECURE; within a verdict by zone name.
"""
import argparse, sys

VERDICT_ORDER = {"UNSIGNED": 0, "PARTIAL": 1, "SECURE": 2}

def _parse(lines):
    zones = []
    records = []
    skipped = 0
    for raw in lines:
        line = raw.split(";", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            skipped += 1
            continue
        owner, rtype = parts[0], None
        # layout: owner [ttl] class type rdata...  (ttl optional)
        if len(parts) >= 5 and parts[2].upper() in ("IN", "CH", "HS"):
            rtype = parts[3].upper()
            rdata = parts[4:]
        elif len(parts) >= 4:
            rtype = parts[2].upper()
            rdata = parts[3:]
        else:
            skipped += 1
            continue
        if rtype == "SOA":
            if owner not in zones:
                zones.append(owner)
        elif rtype in ("DS", "DNSKEY"):
            records.append((owner, rtype, rdata))
    return zones, records, skipped

def check(lines):
    zones, records, skipped = _parse(lines)
    zone_set = set(zones)
    per_zone = {z: {"DS": [], "DNSKEY": [], "ksk": 0} for z in zones}
    for owner, rtype, rdata in records:
        if owner not in zone_set:
            skipped += 1
            continue
        if rtype == "DS" and len(rdata) < 4:
            skipped += 1
            continue
        if rtype == "DNSKEY" and len(rdata) < 4:
            skipped += 1
            continue
        per_zone[owner][rtype].append(rdata)
        if rtype == "DNSKEY" and rdata[0] == "257":
            per_zone[owner]["ksk"] += 1
    out = []
    for zone in zones:
        info = per_zone[zone]
        has_ds = bool(info["DS"])
        has_key = bool(info["DNSKEY"])
        zsk = len(info["DNSKEY"]) - info["ksk"]
        if has_ds and has_key:
            verdict = "SECURE"
        elif has_ds or has_key:
            verdict = "PARTIAL"
        else:
            verdict = "UNSIGNED"
        detail = (f"DS {'present (' + str(len(info['DS'])) + ' record(s))' if has_ds else 'missing'}, "
                  f"DNSKEY {'present (' + str(info['ksk']) + ' KSK, ' + str(zsk) + ' ZSK)' if has_key else 'missing'}")
        out.append((zone, verdict, detail))
    out.sort(key=lambda r: (VERDICT_ORDER[r[1]], r[0]))
    return out, skipped

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    args = parser.parse_args(argv)
    with open(args.path, encoding="utf-8") as f:
        results, skipped = check(f.readlines())
    for zone, verdict, detail in results:
        print(f"{zone}: {verdict} - {detail}")
    counts = {v: sum(1 for _, verdict, _ in results if verdict == v)
              for v in VERDICT_ORDER}
    print(f"{counts['SECURE']} secure, {counts['PARTIAL']} partial, "
          f"{counts['UNSIGNED']} unsigned out of {len(results)} zone(s).")
    if skipped:
        print(f"Skipped {skipped} invalid record(s).")
    return 0

if __name__ == "__main__":
    sys.exit(main())
