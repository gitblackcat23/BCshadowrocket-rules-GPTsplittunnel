import datetime
import json
import tempfile
import unittest
from contextlib import ExitStack
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


def openai_embedded_block(config):
    start = config.index("# OpenAI (使用节点:")
    end = config.index("# Claude 全家桶 (使用节点:", start)
    return config[start:end]


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
        cls.openai_vps_content = (FIXTURES / "openai_vps.list").read_text(
            encoding="utf-8"
        )
        cls.openai_v2fly_content = (FIXTURES / "openai_v2fly.txt").read_text(
            encoding="utf-8"
        )
        cls.openai_voice_content = (FIXTURES / "openai_voice.json").read_text(
            encoding="utf-8"
        )

    def online_response(self, url, timeout, johnshall_content=None):
        self.assertEqual(timeout, rules.SOURCE_TIMEOUT_SECONDS)
        if url == rules.openai_vps_url:
            return FakeResponse(self.openai_vps_content)
        if url == rules.openai_v2fly_url:
            return FakeResponse(self.openai_v2fly_content)
        if url == rules.openai_voice_url:
            return FakeResponse(self.openai_voice_content, content_type="application/json")
        if url == rules.johnshall_url:
            return FakeResponse(johnshall_content or self.johnshall_content)
        return FakeResponse(self.provider_content)

    def relaxed_build_context(self, response_side_effect):
        stack = ExitStack()
        stack.enter_context(
            mock.patch.object(rules.requests, "get", side_effect=response_side_effect)
        )
        stack.enter_context(mock.patch.object(rules, "MIN_JOHNSHALL_RULES", 1))
        stack.enter_context(mock.patch.object(rules, "MIN_GENERATED_RULES", 1))
        stack.enter_context(mock.patch.object(rules, "OPENAI_MIN_MERGED_RULES", 1))
        stack.enter_context(mock.patch.object(rules, "SOURCE_BASELINE_RULE_COUNTS", {}))
        return stack

    def write_complete_offline_cache(self, cache_dir):
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "OpenAI_VPSDance.list").write_text(
            self.openai_vps_content, encoding="utf-8"
        )
        (cache_dir / "OpenAI_v2fly.txt").write_text(
            self.openai_v2fly_content, encoding="utf-8"
        )
        (cache_dir / "OpenAI_voice.json").write_text(
            self.openai_voice_content, encoding="utf-8"
        )
        (cache_dir / "Claude.list").write_text(self.provider_content, encoding="utf-8")
        (cache_dir / "johnshall_latest.conf").write_text(
            self.johnshall_content, encoding="utf-8"
        )
        for name in rules.domestic_lists:
            (cache_dir / f"{name}.list").write_text(
                self.provider_content, encoding="utf-8"
            )

    def test_attach_policy_inserts_policy_before_no_resolve(self):
        self.assertEqual(
            rules.attach_policy("IP-CIDR,192.0.2.1/32,no-resolve", "V3 Static Residential"),
            "IP-CIDR,192.0.2.1/32,V3 Static Residential,no-resolve",
        )
        self.assertEqual(
            rules.attach_policy("IP-CIDR6,2606:4700::1/128,no-resolve", "Proxy"),
            "IP-CIDR6,2606:4700::1/128,Proxy,no-resolve",
        )
        self.assertEqual(
            rules.attach_policy("IP-ASN,64500,no-resolve", "DIRECT"),
            "IP-ASN,64500,DIRECT,no-resolve",
        )
        self.assertEqual(
            rules.attach_policy("DOMAIN-SUFFIX,fixture.example", "DIRECT"),
            "DOMAIN-SUFFIX,fixture.example,DIRECT",
        )

    def test_ip_cidr6_enforces_ipv6_while_legacy_ip_cidr_accepts_both_families(self):
        self.assertEqual(
            rules.validate_provider_rule("IP-CIDR6,2606:4700::1/128,no-resolve")[0],
            "IP-CIDR6",
        )
        # Historical Johnshall lists sometimes spell IPv6 rules as IP-CIDR.
        self.assertEqual(
            rules.validate_provider_rule("IP-CIDR,2606:4700::1/128,no-resolve")[0],
            "IP-CIDR",
        )
        rules.validate_routed_rule(
            "IP-CIDR6,2606:4700::1/128,Proxy,no-resolve",
            "IPv6 routed fixture",
            1,
        )
        with self.assertRaisesRegex(rules.RuleValidationError, "IPv6"):
            rules.validate_provider_rule("IP-CIDR6,20.20.20.20/32,no-resolve")
        with self.assertRaisesRegex(rules.RuleValidationError, "IPv6"):
            rules.validate_routed_rule(
                "IP-CIDR6,20.20.20.20/32,Proxy,no-resolve",
                "Wrong-family fixture",
                1,
            )

    def test_vps_openai_rejects_unapproved_sensitive_rules_and_as20473(self):
        self.assertEqual(
            rules.validate_vps_openai_content(self.openai_vps_content, "VPS fixture"),
            7,
        )
        invalid = {
            "new keyword": "DOMAIN-KEYWORD,unreviewed-openai-token\n",
            "new network": "IP-CIDR,8.8.8.0/24,no-resolve\n",
            "shared ASN": "IP-ASN,20473,no-resolve\n",
        }
        for label, content in invalid.items():
            with self.subTest(label=label), self.assertRaises(rules.RuleValidationError):
                rules.validate_vps_openai_content(content, f"Invalid VPS {label}")

    def test_v2fly_converts_bare_full_known_regexp_and_keeps_ads_entries(self):
        self.assertEqual(
            rules.v2fly_openai_rule_lines(self.openai_v2fly_content),
            [
                "DOMAIN-SUFFIX,openai.com",
                "DOMAIN,chat.openai.com",
                "DOMAIN-KEYWORD,chatgpt-async-webps-prod-",
                "DOMAIN-SUFFIX,oaistatic.com",
            ],
        )
        self.assertEqual(
            rules.validate_v2fly_openai_content(
                self.openai_v2fly_content, "v2fly fixture"
            ),
            4,
        )

    def test_v2fly_rejects_unknown_directive_regexp_and_malformed_attribute(self):
        invalid = {
            "directive": "include:openai\n",
            "regexp": r"regexp:^unreviewed-[a-z]+\.example$" + "\n",
            "attribute": "openai.com ads\n",
        }
        for label, content in invalid.items():
            with self.subTest(label=label), self.assertRaises(rules.RuleValidationError):
                rules.v2fly_openai_rule_lines(content, f"Invalid v2fly {label}")

    def test_voice_json_converts_public_ipv4_and_ipv6_single_hosts(self):
        creation_time, voice_rules = rules.voice_openai_rule_lines(
            self.openai_voice_content
        )
        self.assertEqual(creation_time, "2026-07-16T00:00:00Z")
        self.assertEqual(
            voice_rules,
            [
                "IP-CIDR,20.20.20.20/32,no-resolve",
                "IP-CIDR6,2606:4700::1/128,no-resolve",
            ],
        )
        self.assertEqual(
            rules.validate_voice_openai_content(
                self.openai_voice_content, "Voice fixture"
            ),
            2,
        )

    def test_voice_json_rejects_malformed_empty_unsafe_or_non_host_prefixes(self):
        def voice_payload(prefixes, creation_time="2026-07-16T00:00:00Z"):
            return json.dumps({"creationTime": creation_time, "prefixes": prefixes})

        invalid = {
            "malformed JSON": "{",
            "empty prefixes": voice_payload([]),
            "missing timezone": voice_payload(
                [{"ipv4Prefix": "20.20.20.20/32"}], "2026-07-16T00:00:00"
            ),
            "IPv4 broad range": voice_payload([{"ipv4Prefix": "20.20.20.0/24"}]),
            "IPv6 broad range": voice_payload([{"ipv6Prefix": "2606:4700::/48"}]),
            "wrong family": voice_payload([{"ipv4Prefix": "2606:4700::1/128"}]),
            "non-public": voice_payload([{"ipv4Prefix": "192.0.2.1/32"}]),
            "extra field": voice_payload(
                [{"ipv4Prefix": "20.20.20.20/32", "description": "unexpected"}]
            ),
            "duplicate": voice_payload(
                [
                    {"ipv4Prefix": "20.20.20.20/32"},
                    {"ipv4Prefix": "20.20.20.20/32"},
                ]
            ),
        }
        for label, content in invalid.items():
            with self.subTest(label=label), self.assertRaises(rules.RuleValidationError):
                rules.voice_openai_rule_lines(content, f"Invalid Voice {label}")

    def test_merge_deduplicates_exact_rules_but_preserves_semantic_overlap(self):
        merged = rules.merge_openai_rule_lines(
            [
                "DOMAIN,api.example.com",
                "DOMAIN-SUFFIX,example.com",
                "IP-ASN,20473,no-resolve",
                "DOMAIN,humb.apple.com",
            ],
            [
                "domain,API.EXAMPLE.COM.",
                "DOMAIN-SUFFIX,EXAMPLE.COM.",
                "IP-ASN,AS20473,no-resolve",
                "DOMAIN-SUFFIX,HUMB.APPLE.COM.",
            ],
        )
        self.assertEqual(
            merged,
            ["DOMAIN,api.example.com", "DOMAIN-SUFFIX,example.com"],
        )
        self.assertEqual(len(merged), len(set(merged)))

    def test_merged_openai_validation_enforces_minimum_and_sentinels(self):
        with (
            mock.patch.object(rules, "OPENAI_MIN_MERGED_RULES", 3),
            mock.patch.object(rules, "OPENAI_REQUIRED_RULES", set()),
        ):
            with self.assertRaisesRegex(rules.RuleValidationError, "低于安全下限"):
                rules.validate_merged_openai_rules(
                    ["DOMAIN,a.example", "DOMAIN,b.example"], [], []
                )

        required = {"DOMAIN,required.example", "DOMAIN-SUFFIX,sentinel.example"}
        with (
            mock.patch.object(rules, "OPENAI_MIN_MERGED_RULES", 1),
            mock.patch.object(rules, "OPENAI_REQUIRED_RULES", required),
        ):
            with self.assertRaisesRegex(rules.RuleValidationError, "缺少哨兵项"):
                rules.validate_merged_openai_rules(
                    ["DOMAIN,required.example"], [], []
                )

            valid = sorted(required | {"IP-CIDR,20.20.20.20/32,no-resolve"})
            self.assertEqual(
                rules.validate_merged_openai_rules(
                    valid,
                    ["DOMAIN,required.example"],
                    ["IP-CIDR,20.20.20.20/32,no-resolve"],
                ),
                3,
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

    def test_each_openai_source_uses_its_own_last_known_good_cache(self):
        sources = [
            (
                rules.openai_vps_url,
                "OpenAI_VPSDance.list",
                "OpenAI VPSDance",
                rules.validate_vps_openai_content,
                self.openai_vps_content,
            ),
            (
                rules.openai_v2fly_url,
                "OpenAI_v2fly.txt",
                "OpenAI v2fly",
                rules.validate_v2fly_openai_content,
                self.openai_v2fly_content,
            ),
            (
                rules.openai_voice_url,
                "OpenAI_voice.json",
                "OpenAI Voice",
                rules.validate_voice_openai_content,
                self.openai_voice_content,
            ),
        ]
        for url, filename, source_name, validator, expected in sources:
            with self.subTest(source=source_name), tempfile.TemporaryDirectory() as temporary_dir:
                cache_path = Path(temporary_dir) / filename
                cache_path.write_text(expected, encoding="utf-8")
                original_bytes = cache_path.read_bytes()
                pending = []
                with (
                    mock.patch.object(
                        rules.requests,
                        "get",
                        side_effect=requests.ConnectionError("fixture offline"),
                    ),
                    mock.patch.object(rules, "SOURCE_BASELINE_RULE_COUNTS", {}),
                ):
                    is_online, content = rules.fetch_or_fallback(
                        url, cache_path, source_name, validator, pending
                    )

                self.assertFalse(is_online)
                self.assertEqual(content, expected)
                self.assertEqual(pending, [])
                self.assertEqual(cache_path.read_bytes(), original_bytes)

    def test_online_fixed_inputs_inline_openai_and_preserve_other_policies(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            output_path = root / "custom.conf"
            cache_dir = root / "cache"
            backup_dir = root / "backups"
            generated_openai_path = root / "audit" / "OpenAI.generated.list"
            fixed_now = datetime.datetime(2026, 7, 15, 12, 34, 56)

            with self.relaxed_build_context(self.online_response):
                generated = rules.build_config(
                    output_path=output_path,
                    cache_dir=cache_dir,
                    backup_dir=backup_dir,
                    now=fixed_now,
                    openai_generated_path=generated_openai_path,
                )

            self.assertEqual(output_path.read_text(encoding="utf-8"), generated)
            expected_backup = backup_dir / "custom_rules_20260715_123456.conf"
            self.assertEqual(expected_backup.read_text(encoding="utf-8"), generated)
            self.assertEqual(
                generated_openai_path.read_text(encoding="utf-8"),
                (cache_dir / "OpenAI.list").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "# Voice creationTime: 2026-07-16T00:00:00Z",
                generated_openai_path.read_text(encoding="utf-8"),
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

            openai_block = openai_embedded_block(generated)
            self.assertNotIn("RULE-SET,", openai_block)
            for source_url in (
                rules.openai_vps_url,
                rules.openai_v2fly_url,
                rules.openai_voice_url,
            ):
                self.assertNotIn(source_url, generated)
            self.assertIn(
                f"DOMAIN-SUFFIX,oaistatsig.com,{rules.openai_node}", openai_block
            )
            self.assertIn(
                f"DOMAIN,chat.openai.com,{rules.openai_node}", openai_block
            )
            self.assertIn(
                f"DOMAIN-KEYWORD,chatgpt-async-webps-prod-,{rules.openai_node}",
                openai_block,
            )
            self.assertIn(
                f"IP-CIDR,20.20.20.20/32,{rules.openai_node},no-resolve",
                openai_block,
            )
            self.assertIn(
                f"IP-CIDR6,2606:4700::1/128,{rules.openai_node},no-resolve",
                openai_block,
            )
            self.assertNotIn("IP-ASN,20473", openai_block)

            self.assertEqual(
                first_embedded_domain_policy(generated, "events.oaistatsig.com"),
                rules.openai_node,
            )
            # Existing high-priority policies remain first-match compatible.
            self.assertEqual(first_embedded_domain_policy(generated, "apple.com"), "DIRECT")
            self.assertEqual(
                first_embedded_domain_policy(generated, "humb.apple.com"), "DIRECT"
            )
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
                f"RULE-SET,{rules.claude_url},{rules.claude_node}", generated
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

    def test_fully_offline_complete_cache_inlines_all_openai_and_existing_sources(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            output_path = root / "custom.conf"
            cache_dir = root / "cache"
            backup_dir = root / "backups"
            generated_openai_path = root / "audit" / "OpenAI.generated.list"
            self.write_complete_offline_cache(cache_dir)

            offline = requests.ConnectionError("fixture offline")
            with self.relaxed_build_context(offline):
                generated = rules.build_config(
                    output_path=output_path,
                    cache_dir=cache_dir,
                    backup_dir=backup_dir,
                    now=datetime.datetime(2026, 7, 15, 12, 34, 56),
                    openai_generated_path=generated_openai_path,
                )

            self.assertNotIn("RULE-SET,", generated)
            self.assertNotIn("IP-ASN,20473", generated)
            self.assertIn(
                f"IP-CIDR,20.20.20.20/32,{rules.openai_node},no-resolve",
                generated,
            )
            self.assertIn(
                f"IP-CIDR6,2606:4700::1/128,{rules.openai_node},no-resolve",
                generated,
            )
            self.assertEqual(
                generated_openai_path.read_text(encoding="utf-8"),
                (cache_dir / "OpenAI.list").read_text(encoding="utf-8"),
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
            generated_openai_path = root / "audit" / "OpenAI.generated.list"

            with mock.patch.object(
                rules.requests,
                "get",
                side_effect=requests.ConnectionError("fixture offline"),
            ):
                with self.assertRaisesRegex(
                    rules.RuleValidationError,
                    "OpenAI VPSDance 在线内容和本地缓存都不可用",
                ):
                    rules.build_config(
                        output_path=output_path,
                        cache_dir=root / "empty-cache",
                        backup_dir=root / "backups",
                        now=datetime.datetime(2026, 7, 15, 12, 34, 56),
                        openai_generated_path=generated_openai_path,
                    )

            self.assertEqual(output_path.read_bytes(), original_bytes)
            self.assertFalse(generated_openai_path.exists())
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
            )
            .replace("[MITM]", "[URL Rewrite]")
            .replace("[SECTION PLACEHOLDER]", "[MITM]"),
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
                return self.online_response(url, timeout, modified_johnshall)

            with self.relaxed_build_context(online_response):
                generated = rules.build_config(
                    output_path=root / "custom.conf",
                    cache_dir=root / "cache",
                    backup_dir=root / "backups",
                    now=datetime.datetime(2026, 7, 15, 12, 34, 56),
                    openai_generated_path=root / "audit" / "OpenAI.generated.list",
                )

            self.assertEqual(generated.upper().count("\nFINAL,"), 1)
            self.assertIn("# dns-server = comment must remain untouched", generated)
            self.assertEqual(
                generated.count(
                    "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query"
                ),
                1,
            )

    def test_final_validation_failure_does_not_commit_openai_raw_or_merged_caches(self):
        modified_johnshall = self.johnshall_content.replace(
            "bypass-system = true",
            "bypass-system = false",
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            cache_dir = root / "cache"
            cache_dir.mkdir()
            output_path = root / "custom.conf"
            output_path.write_text("known-good\n", encoding="utf-8")
            generated_openai_path = root / "audit" / "OpenAI.generated.list"
            generated_openai_path.parent.mkdir()

            existing_files = {
                cache_dir / "OpenAI_VPSDance.list": "# old VPS cache sentinel\n"
                + self.openai_vps_content,
                cache_dir / "OpenAI_v2fly.txt": "# old v2fly cache sentinel\n"
                + self.openai_v2fly_content,
                cache_dir / "OpenAI_voice.json": self.openai_voice_content.replace(
                    "{", "{\n  \"oldCacheSentinel\": true,", 1
                ),
                cache_dir / "OpenAI.list": "old merged cache sentinel\n",
                generated_openai_path: "old generated audit sentinel\n",
                cache_dir / "johnshall_latest.conf": self.johnshall_content,
            }
            for path, content in existing_files.items():
                path.write_text(content, encoding="utf-8")
            original_bytes = {path: path.read_bytes() for path in existing_files}

            def online_response(url, timeout):
                return self.online_response(url, timeout, modified_johnshall)

            with self.relaxed_build_context(online_response), mock.patch.object(
                rules,
                "validate_generated_config",
                side_effect=rules.RuleValidationError("forced final validation failure"),
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
                        openai_generated_path=generated_openai_path,
                    )

            for path, expected in original_bytes.items():
                with self.subTest(path=path.name):
                    self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "known-good\n")
            self.assertEqual(list((root / "backups").glob("*.conf")), [])

    def test_provider_rejects_invalid_domain_cidr_address_family_and_asn(self):
        invalid_rules = {
            "domain": "DOMAIN-SUFFIX,bad domain.example\n",
            "cidr": "IP-CIDR,999.0.0.1/32,no-resolve\n",
            "cidr6 family": "IP-CIDR6,20.20.20.20/32,no-resolve\n",
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
