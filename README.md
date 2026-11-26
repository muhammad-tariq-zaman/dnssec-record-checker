# dnssec-record-checker

Validate DNSSEC-related records (DS/DNSKEY) in a zone file: a zone is defined by its SOA record, and for each zone this checks whether DS and DNSKEY records exist under the zone apex — SECURE when both are present, PARTIAL when only one of them is present, UNSIGNED when neither is present — UNSIGNED first, then PARTIAL, then SECURE. A DS record needs at least a key tag, algorithm, digest type and digest; a DNSKEY record needs at least flags, protocol, algorithm and a public key. Records that are too short, or DS/DNSKEY records whose owner name is not a zone apex, are reported as skipped, not silently dropped.

Sample input is included (sample.zone with four zones, one invalid DS record).

## How to run

```sh
python3 main.py sample.zone
```

## Example output

```
example.edu.: UNSIGNED - DS missing, DNSKEY missing
example.net.: PARTIAL - DS present (1 record(s)), DNSKEY missing
example.org.: PARTIAL - DS missing, DNSKEY present (0 KSK, 1 ZSK)
example.com.: SECURE - DS present (1 record(s)), DNSKEY present (1 KSK, 0 ZSK)
1 secure, 2 partial, 1 unsigned out of 4 zone(s).
Skipped 1 invalid record(s).
```

Standard library only. Run the tests with `python3 -m unittest discover`.
