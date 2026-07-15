import datetime
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests

import update_rules as rules


FIXTURES = Path(__file__).parent / "fixtures"


def first_embedded_domain_policy(config, hostname):
    """Return the first locally embedded domain rule policy for hostname."""
    _, _, rule_block = rules._johnshall_rule_block(config, "Generated fixture")
    hostname = hostname.lower().rstrip(".")

    for raw_line in rule_block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        rule_type = parts[0].upper()
        if rule_type == "DOMAIN" and hostname == parts[1].lower().rstrip("."):
            return parts[2]
        if rule_type == "DOMAIN-SUFFIX":
            suffix = parts[1].lower().rstrip(".")
            if hostname == suffix or hostname.endswith(f".{suffix}"):
                return parts[2]
        if rule_type == "DOMAIN-KEYWORD" and parts[1].lower() in hostname:
            return parts[2]
        if rule_type == "FINAL":
            return parts[1]
    return None


class FakeResponse:
    def __init__(self, content, status_code=200, content_type="text/plain; charset=utf-8"):
        self.content = content.encode("utf-8") if isinstance(content, str) else content
        self.status_code = status_code
        self.headers = {"content-type": content_type}


class RuleGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider_content = (FIXTURES / "provider.list").read_text(encoding="utf-8")
        cls.johnshall_content = (FIXTURES / "johnshall.conf").read_text(encoding="utf-8")

    def test_attach_policy_inserts_policy_before_no_resolve(self):
        self.assertEqual(
            rules.attach_policy("IP-CIDR,192.0.2.1/32,no-resolve", "V3 Static Residential"),
            "IP-CIDR,192.0.2.1/32,V3 Static Residential,no-resolve",
        )
        self.assertEqual(
            rules.attach_policy("IP-ASN,64500,no-resolve", "DIRECT"),
            "IP-ASN,64500,DIRECT,no-resolve",
        )
        self.assertEqual(
            rules.attach_policy("DOMAIN-SUFFIX,fixture.example", "DIRECT"),
            "DOMAIN-SUFFIX,fixture.example,DIRECT",
        )

    def test_invalid_online_provider_never_pollutes_valid_cache(self):
        invalid_responses = {
            "html": FakeResponse("<!doctype html><html><body>upstream error</body></html>"),
            "empty": FakeResponse("\n\t\n"),
            # The cache has four rules; one valid rule is below the permitted 50% floor.
            "truncated": FakeResponse("DOMAIN-SUFFIX,only-one.example\n"),
        }

        for label, response in invalid_responses.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary_dir:
                cache_path = Path(temporary_dir) / "provider.list"
                cache_path.write_text(self.provider_content, encoding="utf-8")
                original_bytes = cache_path.read_bytes()

                with mock.patch.object(rules.requests, "get", return_value=response):
                    is_online, content = rules.fetch_or_fallback(
                        "https://rules.invalid/provider.list",
                        cache_path,
                        "Fixture provider",
                        rules.validate_provider_content,
                    )

                self.assertFalse(is_online)
                self.assertEqual(content, self.provider_content)
                self.assertEqual(cache_path.read_bytes(), original_bytes)

    def test_online_fixed_inputs_preserve_key_order_and_policies(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            output_path = root / "custom.conf"
            cache_dir = root / "cache"
            backup_dir = root / "backups"

            def online_response(url, timeout):
                self.assertEqual(timeout, rules.SOURCE_TIMEOUT_SECONDS)
                if url == rules.johnshall_url:
                    return FakeResponse(self.johnshall_content)
                return FakeResponse(self.provider_content)

            fixed_now = datetime.datetime(2026, 7, 15, 12, 34, 56)
            with (
                mock.patch.object(rules.requests, "get", side_effect=online_response),
                mock.patch.object(rules, "MIN_JOHNSHALL_RULES", 1),
                mock.patch.object(rules, "MIN_GENERATED_RULES", 1),
                mock.patch.object(rules, "SOURCE_BASELINE_RULE_COUNTS", {}),
            ):
                generated = rules.build_config(
                    output_path=output_path,
                    cache_dir=cache_dir,
                    backup_dir=backup_dir,
                    now=fixed_now,
                )

            self.assertEqual(output_path.read_text(encoding="utf-8"), generated)
            expected_backup = backup_dir / "custom_rules_20260715_123456.conf"
            self.assertEqual(expected_backup.read_text(encoding="utf-8"), generated)
            # Golden SHA locks the approved oaistatsig addition and all other
            # normal online output to byte-for-byte compatibility.
            self.assertEqual(
                hashlib.sha256(generated.encode("utf-8")).hexdigest(),
                "055c03dfa27612cfd982727b5d270302b3c27706f74f78440618b32bd7c6971e",
            )

            ordered_markers = [
                "# Apple & iCloud Services (DIRECT)",
                "# Tonghuashun (DIRECT)",
                "# OpenAI (使用节点:",
                "# Claude 全家桶 (使用节点:",
                "# GitHub Copilot & Codex (使用节点:",
                "# --- Johnshall 去广告与基础代理区块 ---",
                "# --- 国内常用 APP 及服务 (DIRECT) ---",
                "# 兜底规则",
            ]
            positions = [generated.index(marker) for marker in ordered_markers]
            self.assertEqual(positions, sorted(positions))

            self.assertIn(f"RULE-SET,{rules.openai_url},{rules.openai_node}", generated)
            self.assertIn(f"RULE-SET,{rules.claude_url},{rules.claude_node}", generated)
            oaistatsig_rule = (
                f"DOMAIN-SUFFIX,{rules.openai_manual_domains[0]},{rules.openai_node}"
            )
            self.assertEqual(generated.count(oaistatsig_rule), 1)
            self.assertLess(
                generated.index(oaistatsig_rule),
                generated.index(f"RULE-SET,{rules.openai_url},{rules.openai_node}"),
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, "oaistatsig.com"),
                rules.openai_node,
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, "events.oaistatsig.com"),
                rules.openai_node,
            )
            # Existing high-priority policies remain first-match compatible.
            self.assertEqual(first_embedded_domain_policy(generated, "apple.com"), "DIRECT")
            self.assertEqual(
                first_embedded_domain_policy(generated, "quote.10jqka.com.cn"),
                "DIRECT",
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, "claude.ai"),
                rules.claude_node,
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, rules.copilot_domains[0]),
                rules.openai_node,
            )
            self.assertIn(
                f"DOMAIN,{rules.copilot_domains[0]},{rules.openai_node}", generated
            )
            for name, url in rules.domestic_lists.items():
                with self.subTest(domestic=name):
                    self.assertIn(f"RULE-SET,{url},DIRECT", generated)
            self.assertIn("DOMAIN-SUFFIX,foreign.fixture.example,Proxy", generated)
            self.assertTrue(generated.rstrip().endswith("hostname = fixture.example"))
            self.assertIn(f"FINAL,{rules.default_node}", generated)
            self.assertEqual(generated.upper().count("\nFINAL,"), 1)
            self.assertNotIn(",no-resolve,DIRECT", generated)
            self.assertNotIn(f",no-resolve,{rules.openai_node}", generated)

    def test_fully_offline_complete_cache_inlines_openai_claude_and_all_domestic_lists(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            output_path = root / "custom.conf"
            cache_dir = root / "cache"
            backup_dir = root / "backups"
            cache_dir.mkdir()

            (cache_dir / "OpenAI.list").write_text(self.provider_content, encoding="utf-8")
            (cache_dir / "Claude.list").write_text(self.provider_content, encoding="utf-8")
            (cache_dir / "johnshall_latest.conf").write_text(
                self.johnshall_content, encoding="utf-8"
            )
            for name in rules.domestic_lists:
                (cache_dir / f"{name}.list").write_text(
                    self.provider_content, encoding="utf-8"
                )

            with (
                mock.patch.object(
                    rules.requests,
                    "get",
                    side_effect=requests.ConnectionError("fixture offline"),
                ),
                mock.patch.object(rules, "MIN_JOHNSHALL_RULES", 1),
                mock.patch.object(rules, "MIN_GENERATED_RULES", 1),
                mock.patch.object(rules, "SOURCE_BASELINE_RULE_COUNTS", {}),
            ):
                generated = rules.build_config(
                    output_path=output_path,
                    cache_dir=cache_dir,
                    backup_dir=backup_dir,
                    now=datetime.datetime(2026, 7, 15, 12, 34, 56),
                )

            self.assertNotIn("RULE-SET,", generated)
            oaistatsig_rule = (
                f"DOMAIN-SUFFIX,{rules.openai_manual_domains[0]},{rules.openai_node}"
            )
            self.assertEqual(generated.count(oaistatsig_rule), 1)
            self.assertLess(
                generated.index(oaistatsig_rule),
                generated.index(
                    f"DOMAIN-SUFFIX,fixture.example,{rules.openai_node}"
                ),
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, "oaistatsig.com"),
                rules.openai_node,
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, "events.oaistatsig.com"),
                rules.openai_node,
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, "unrelatedstatsig.com"),
                rules.default_node,
            )
            self.assertEqual(first_embedded_domain_policy(generated, "apple.com"), "DIRECT")
            self.assertEqual(
                first_embedded_domain_policy(generated, "quote.10jqka.com.cn"),
                "DIRECT",
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, "claude.ai"),
                rules.claude_node,
            )
            self.assertEqual(
                first_embedded_domain_policy(generated, rules.copilot_domains[0]),
                rules.openai_node,
            )
            self.assertIn(
                f"IP-CIDR,192.0.2.1/32,{rules.openai_node},no-resolve", generated
            )
            self.assertIn(f"IP-ASN,64500,{rules.claude_node},no-resolve", generated)
            self.assertEqual(
                generated.count("DOMAIN-SUFFIX,fixture.example,DIRECT"),
                len(rules.domestic_lists),
            )
            self.assertEqual(len(rules.domestic_lists), 29)
            for name in rules.domestic_lists:
                with self.subTest(domestic=name):
                    self.assertIn(f"# {name} (降级使用本地缓存内联)", generated)
            self.assertNotIn(",no-resolve,DIRECT", generated)
            self.assertNotIn(f",no-resolve,{rules.openai_node}", generated)
            self.assertEqual(generated.upper().count("\nFINAL,"), 1)

    def test_missing_online_source_and_cache_fails_without_changing_output(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            output_path = root / "custom.conf"
            output_path.write_text("existing known-good config\n", encoding="utf-8")
            original_bytes = output_path.read_bytes()

            with mock.patch.object(
                rules.requests,
                "get",
                side_effect=requests.ConnectionError("fixture offline"),
            ):
                with self.assertRaisesRegex(
                    rules.RuleValidationError,
                    "OpenAI 在线内容和本地缓存都不可用",
                ):
                    rules.build_config(
                        output_path=output_path,
                        cache_dir=root / "empty-cache",
                        backup_dir=root / "backups",
                        now=datetime.datetime(2026, 7, 15, 12, 34, 56),
                    )

            self.assertEqual(output_path.read_bytes(), original_bytes)
            self.assertEqual(list((root / "backups").glob("*.conf")), [])

    def test_johnshall_rejects_missing_duplicate_and_misordered_sections(self):
        malformed = {
            "missing Rule": self.johnshall_content.replace("[Rule]\n", ""),
            "duplicate Rule": self.johnshall_content.replace(
                "[URL Rewrite]\n", "[Rule]\n[URL Rewrite]\n"
            ),
            "intervening section": self.johnshall_content.replace(
                "[URL Rewrite]\n", "[Host]\nfixture = 127.0.0.1\n\n[URL Rewrite]\n"
            ),
            "misordered sections": self.johnshall_content.replace(
                "[URL Rewrite]", "[SECTION PLACEHOLDER]"
            ).replace("[MITM]", "[URL Rewrite]").replace(
                "[SECTION PLACEHOLDER]", "[MITM]"
            ),
        }

        for label, content in malformed.items():
            with self.subTest(label=label), mock.patch.object(
                rules, "MIN_JOHNSHALL_RULES", 1
            ):
                with self.assertRaises(rules.RuleValidationError):
                    rules.validate_johnshall_content(content, f"Johnshall {label}")

    def test_invalid_online_johnshall_never_pollutes_valid_cache(self):
        corrupt_content = self.johnshall_content.replace(
            "DOMAIN-SUFFIX,foreign.fixture.example,Proxy",
            "DOMAIN,,Proxy",
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            cache_path = Path(temporary_dir) / "johnshall.conf"
            cache_path.write_text(self.johnshall_content, encoding="utf-8")
            original_bytes = cache_path.read_bytes()

            with (
                mock.patch.object(
                    rules.requests,
                    "get",
                    return_value=FakeResponse(corrupt_content),
                ),
                mock.patch.object(rules, "MIN_JOHNSHALL_RULES", 1),
            ):
                is_online, content = rules.fetch_or_fallback(
                    "https://rules.invalid/johnshall.conf",
                    cache_path,
                    "Johnshall fixture",
                    rules.validate_johnshall_content,
                )

            self.assertFalse(is_online)
            self.assertEqual(content, self.johnshall_content)
            self.assertEqual(cache_path.read_bytes(), original_bytes)

    def test_johnshall_transform_handles_normalized_terminator_and_anchored_dns(self):
        modified_johnshall = self.johnshall_content.replace(
            "bypass-system = true\n",
            "bypass-system = true\n# dns-server = comment must remain untouched\n",
        ).replace("FINAL,Proxy", "  final,Proxy")

        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)

            def online_response(url, timeout):
                if url == rules.johnshall_url:
                    return FakeResponse(modified_johnshall)
                return FakeResponse(self.provider_content)

            with (
                mock.patch.object(rules.requests, "get", side_effect=online_response),
                mock.patch.object(rules, "MIN_JOHNSHALL_RULES", 1),
                mock.patch.object(rules, "MIN_GENERATED_RULES", 1),
                mock.patch.object(rules, "SOURCE_BASELINE_RULE_COUNTS", {}),
            ):
                generated = rules.build_config(
                    output_path=root / "custom.conf",
                    cache_dir=root / "cache",
                    backup_dir=root / "backups",
                    now=datetime.datetime(2026, 7, 15, 12, 34, 56),
                )

            self.assertEqual(generated.upper().count("\nFINAL,"), 1)
            self.assertIn("# dns-server = comment must remain untouched", generated)
            self.assertEqual(
                generated.count(
                    "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query"
                ),
                1,
            )

    def test_final_validation_failure_does_not_commit_pending_caches(self):
        modified_johnshall = self.johnshall_content.replace(
            "bypass-system = true",
            "bypass-system = false",
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            cache_dir = root / "cache"
            cache_dir.mkdir()
            johnshall_cache = cache_dir / "johnshall_latest.conf"
            johnshall_cache.write_text(self.johnshall_content, encoding="utf-8")
            original_cache_bytes = johnshall_cache.read_bytes()
            output_path = root / "custom.conf"
            output_path.write_text("known-good\n", encoding="utf-8")

            def online_response(url, timeout):
                if url == rules.johnshall_url:
                    return FakeResponse(modified_johnshall)
                return FakeResponse(self.provider_content)

            with (
                mock.patch.object(rules.requests, "get", side_effect=online_response),
                mock.patch.object(rules, "MIN_JOHNSHALL_RULES", 1),
                mock.patch.object(rules, "SOURCE_BASELINE_RULE_COUNTS", {}),
                mock.patch.object(
                    rules,
                    "validate_generated_config",
                    side_effect=rules.RuleValidationError("forced final validation failure"),
                ),
            ):
                with self.assertRaisesRegex(
                    rules.RuleValidationError,
                    "forced final validation failure",
                ):
                    rules.build_config(
                        output_path=output_path,
                        cache_dir=cache_dir,
                        backup_dir=root / "backups",
                        now=datetime.datetime(2026, 7, 15, 12, 34, 56),
                    )

            self.assertEqual(johnshall_cache.read_bytes(), original_cache_bytes)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "known-good\n")
            self.assertEqual(list((root / "backups").glob("*.conf")), [])

    def test_provider_rejects_invalid_domain_cidr_and_asn(self):
        invalid_rules = {
            "domain": "DOMAIN-SUFFIX,bad domain.example\n",
            "cidr": "IP-CIDR,999.0.0.1/32,no-resolve\n",
            "asn": "IP-ASN,not-an-asn,no-resolve\n",
        }
        for label, content in invalid_rules.items():
            with self.subTest(label=label):
                with self.assertRaises(rules.RuleValidationError):
                    rules.validate_provider_content(content, f"Invalid {label}")

    def test_atomic_replace_failure_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "custom.conf"
            output_path.write_text("known-good\n", encoding="utf-8")
            original_bytes = output_path.read_bytes()

            with mock.patch.object(rules.os, "replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    rules.atomic_write_text(output_path, "new but unpublished\n")

            self.assertEqual(output_path.read_bytes(), original_bytes)
            self.assertEqual(
                [path.name for path in output_path.parent.iterdir()],
                [output_path.name],
            )


if __name__ == "__main__":
    unittest.main()
