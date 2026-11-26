import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import check

def zone_file(text):
    return text.strip().splitlines()

SOA_A = "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2026111601 7200 3600 1209600 3600"
SOA_B = "example.org. 3600 IN SOA ns1.example.org. admin.example.org. 2026111601 7200 3600 1209600 3600"

class TestDnssecChecker(unittest.TestCase):
    def test_secure(self):
        lines = zone_file(SOA_A + "\nexample.com. 3600 IN DS 12345 8 2 ABCDEF0123\nexample.com. 3600 IN DNSKEY 257 3 8 AwEAAaBc\n")
        r, skipped = check(lines)
        self.assertEqual(r[0][1], "SECURE")
        self.assertIn("1 KSK, 0 ZSK", r[0][2])
        self.assertEqual(skipped, 0)

    def test_partial_dnskey_only(self):
        lines = zone_file(SOA_A + "\nexample.com. 3600 IN DNSKEY 256 3 8 AwEAAaBc\n")
        r, _ = check(lines)
        self.assertEqual((r[0][1], r[0][2].split(",")[0]), ("PARTIAL", "DS missing"))

    def test_partial_ds_only(self):
        lines = zone_file(SOA_A + "\nexample.com. 3600 IN DS 12345 8 2 ABCDEF0123\n")
        r, _ = check(lines)
        self.assertEqual(r[0][1], "PARTIAL")
        self.assertIn("DNSKEY missing", r[0][2])

    def test_unsigned(self):
        r, _ = check(zone_file(SOA_A))
        self.assertEqual(r[0][1], "UNSIGNED")

    def test_unsigned_comes_first(self):
        lines = zone_file(SOA_A + "\n" + SOA_B + "\nexample.org. 3600 IN DS 1 8 2 AA\nexample.org. 3600 IN DNSKEY 257 3 8 AwEA\n")
        r, _ = check(lines)
        self.assertEqual([x[0] for x in r], ["example.com.", "example.org."])

    def test_short_ds_is_skipped(self):
        lines = zone_file(SOA_A + "\nexample.com. 3600 IN DS 999\n")
        r, skipped = check(lines)
        self.assertEqual((r[0][1], skipped), ("UNSIGNED", 1))

    def test_short_dnskey_is_skipped(self):
        lines = zone_file(SOA_A + "\nexample.com. 3600 IN DNSKEY 257 3\n")
        r, skipped = check(lines)
        self.assertEqual((r[0][1], skipped), ("UNSIGNED", 1))

    def test_record_under_non_zone_is_skipped(self):
        lines = zone_file(SOA_A + "\nother.com. 3600 IN DS 1 8 2 AA\n")
        r, skipped = check(lines)
        self.assertEqual((len(r), skipped), (1, 1))

    def test_empty_input(self):
        self.assertEqual(check([]), ([], 0))
