import argparse
import concurrent.futures
import datetime
import hashlib
import ipaddress
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import requests


# ================= 基础配置 =================
default_node = "V3(vless+vision+reality)"
openai_node = "V3 Static Residential"
# SCCR2685 含 OpenAI 也会使用的共享基础设施规则。若要让两者使用不同
# 节点，必须先缩窄这些共享规则并完成受保护分流审计。
claude_node = "V3 Static Residential"

DEFAULT_CACHE_DIR = Path("backups/rules_cache")
DEFAULT_BACKUP_DIR = Path("backups")
DEFAULT_OUTPUT_PATH = Path("custom_shadowrocket_rules.conf")
REPOSITORY_DIR = Path(__file__).resolve().parent
OPENAI_RULES_DIR = REPOSITORY_DIR / "rules/openai"
OPENAI_COMPATIBILITY_PATH = OPENAI_RULES_DIR / "compatibility-baseline.list"
OPENAI_OFFICIAL_PATH = OPENAI_RULES_DIR / "official-extra.list"
OPENAI_GENERATED_PATH = OPENAI_RULES_DIR / "generated.list"
CLAUDE_RULES_DIR = REPOSITORY_DIR / "rules/claude"
CLAUDE_SCCR2685_PATH = CLAUDE_RULES_DIR / "sccr2685.list"
CLAUDE_LEGACY_EXTRA_PATH = CLAUDE_RULES_DIR / "legacy-extra.list"
CLAUDE_SCCR2685_RULE_COUNT = 39
CLAUDE_LEGACY_EXTRA_RULE_COUNT = 15
CLAUDE_SCCR2685_SHA256 = "d36acf549e26fba491436a8b42c1c98de1db0f669f70ff2c8a368eb5efc1f817"
CLAUDE_LEGACY_EXTRA_SHA256 = "032059abf3b92ba23925d9e398482df5fd890079aea27538c9e4e0153952f3f0"
CLAUDE_OFFICIAL_EXTRA_RULES = (
    # Anthropic 官方说明 npm/bun 安装需要访问该共享 registry；用户于
    # 2026-08-05 明确批准纳入 Claude 固定出口。
    "DOMAIN,registry.npmjs.org",
)
SOURCE_TIMEOUT_SECONDS = 12
SOURCE_CONNECT_TIMEOUT_SECONDS = 5
SOURCE_DOWNLOAD_ATTEMPTS = 3
SOURCE_RETRY_BACKOFF_SECONDS = 0.25
SOURCE_DOWNLOAD_CHUNK_SIZE = 64 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_DOWNLOAD_WORKERS = 8
ALLOWED_SOURCE_HOSTS = {
    "johnshall.github.io",
    "raw.githubusercontent.com",
}
MIN_RULE_COUNT_RATIO = 0.5
MAX_RULE_COUNT_RATIO = 2.0
MIN_JOHNSHALL_RULES = 10_000
MIN_GENERATED_RULES = 10_000

# Audited active-rule counts for known-good sources. Existing source counts were
# established at commit 85ef191; the two dynamic OpenAI source counts were reviewed on
# 2026-07-16. Crossing the 50%-200% envelope requires an explicit baseline review.
SOURCE_BASELINE_RULE_COUNTS = {
    "OpenAI VPSDance": 45,
    "OpenAI v2fly": 23,
    "WeChat": 33,
    "WeType": 1,
    "Zhihu": 7,
    "Weibo": 4,
    "DouBan": 3,
    "ByteDance": 371,
    "DouYin": 13,
    "BiliBili": 127,
    "XiaoHongShu": 4,
    "NetEaseMusic": 30,
    "Himalaya": 18,
    "JingDong": 249,
    "Pinduoduo": 3,
    "XianYu": 16,
    "SMZDM": 9,
    "MeiTuan": 7,
    "CaiNiao": 9,
    "AliPay": 21,
    "CMB": 38,
    "ICBC": 58,
    "CCB": 18,
    "EastMoney": 33,
    "DiDi": 25,
    "XieCheng": 29,
    "12306": 15,
    "Baidu": 251,
    "ChinaMobile": 36,
    "ChinaTelecom": 83,
    "115": 10,
}

PROVIDER_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "USER-AGENT",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
}

PINNED_PROVIDER_RULE_TYPES = PROVIDER_RULE_TYPES | {"DST-PORT"}

GENERATED_RULE_TYPES = PINNED_PROVIDER_RULE_TYPES | {
    "GEOIP",
    "RULE-SET",
    "FINAL",
}

# Johnshall historically may use MATCH as an upstream terminator; the generator
# intentionally removes MATCH/FINAL and writes its own single FINAL. Keep
# pinned-only DST-PORT unavailable to this dynamic upstream.
JOHNSHALL_RULE_TYPES = PROVIDER_RULE_TYPES | {
    "GEOIP",
    "RULE-SET",
    "FINAL",
    "MATCH",
}

OPENAI_MIN_MERGED_RULES = 65
OPENAI_V2FLY_REGEX_RULES = {
    r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$": (
        "DOMAIN-KEYWORD,chatgpt-async-webps-prod-"
    ),
}
OPENAI_APPROVED_VPS_SENSITIVE_RULES = {
    "DOMAIN-KEYWORD,chatgpt-async-webps-prod",
    "DOMAIN-KEYWORD,openai",
    "IP-CIDR,199.47.142.0/23,no-resolve",
    "IP-CIDR,24.199.123.28/32,no-resolve",
    "IP-CIDR,64.23.132.171/32,no-resolve",
    "IP-CIDR6,2604:f20::/32,no-resolve",
    "IP-ASN,401518,no-resolve",
}
OPENAI_REQUIRED_RULES = {
    "DOMAIN-SUFFIX,chat.com",
    "DOMAIN-SUFFIX,chatgpt.com",
    "DOMAIN-SUFFIX,chatgpt.livekit.cloud",
    "DOMAIN-SUFFIX,host.livekit.cloud",
    "DOMAIN-SUFFIX,oaistatic.com",
    "DOMAIN-SUFFIX,oaistatsig.com",
    "DOMAIN-SUFFIX,oaiusercontent.com",
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN-SUFFIX,sora.com",
    "DOMAIN-SUFFIX,turn.livekit.cloud",
    "DOMAIN,ws.chatgpt.com",
    "IP-CIDR,199.47.142.0/23,no-resolve",
    "IP-CIDR6,2604:f20::/32,no-resolve",
    "IP-ASN,401518,no-resolve",
}


class RuleValidationError(ValueError):
    """Raised when downloaded or generated rule content is unsafe to use."""


# 硬编码高优先级直连域名
apple_domains = [
    "apple.com", "apple.cn", "apple-cloudkit.com", "apple-livephotoskit.com",
    "icloud.com", "icloud.com.cn", "icloud-content.com", "me.com",
    "files.apple.com", "ws.icloud.com", "com.apple.ubiquity.bulletin", "com.apple.photos",
    "identity.apple.com", "gs.apple.com", "albert.apple.com", "gdmf.apple.com",
    "setup.icloud.com", "configuration.apple.com", "itunes.com", "mzstatic.com",
    "cdn-apple.com", "aaplimg.com", "static.ips.apple.com", "apps.apple.com",
    "p30-buy.itunes.apple.com", "books.itunes.apple.com", "secure.store.apple.com",
    "news-assets.apple.com", "streaming.apple.com", "music.apple.com", "tv.apple.com",
    "search.itunes.apple.com", "push.apple.com", "1-courier.push.apple.com",
    "2-courier.push.apple.com", "3-courier.push.apple.com", "4-courier.push.apple.com",
    "5-courier.push.apple.com", "captive.apple.com", "deviceenrollment.apple.com",
    "deviceservices-external.apple.com", "iprofiles.apple.com", "sq-device.apple.com",
    "tbsc.apple.com", "time.apple.com", "time-ios.apple.com", "time-macos.apple.com",
    "gsa.apple.com", "iadsdk.apple.com", "metrics.apple.com", "wallet.apple.com",
    "weather-data.apple.com", "api.weather.com", "siri.apple.com", "locationd.apple.com",
    "icloud-api.apple.com", "mask.icloud.com", "mask-h2.icloud.com", "gateway.icloud.com",
    # Explicit iCloud diagnostics and newer Apple hosts to keep Shadowrocket routing direct.
    "gc.apple.com", "icloud.apple.com", "probe.icloud.com", "pong.icloud.com",
    "mask-api.icloud.com", "metrics.icloud.com",
    # iCloud China/CNAME paths are required for reliable Notes and CloudKit sync.
    "apzones.com", "apple-icloud.cn", "appleicloud.cn", "icloud-apple.cn",
    "icloud.cn", "icloud.net.cn", "icloudapple.cn",
    "www-cdn.icloud.com.akadns.net",
]

apple_keywords = [
    "icloud.com.akadns.net",
]

tonghuashun_domains = [
    "10jqka.com.cn", "hexin.cn", "data.10jqka.com.cn", "t.10jqka.com.cn",
    "news.10jqka.com.cn", "q.10jqka.com.cn", "basic.10jqka.com.cn", "moni.10jqka.com.cn",
    "upass.10jqka.com.cn", "user.10jqka.com.cn", "search.10jqka.com.cn", "5188.money.10jqka.com.cn",
]

copilot_domains = [
    "api.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "copilot-telemetry.githubusercontent.com",
    "origin-tracker.githubusercontent.com",
]

# Audited across focused rules from fmz200/wool_scripts,
# blackmatrix7/ios_rule_script, and TG-Twilight/AWAvenue-Ads-Rule.
# Keep these static so an unrelated upstream plugin change cannot silently broaden
# the locally trusted REJECT/MITM surface during a scheduled build.
DONGQIUDI_AD_RULE = "DOMAIN-KEYWORD,apimg.qunliao.info,REJECT"
DONGQIUDI_REWRITE_RULE = r"^https?:\/\/ap\.dongdianqiu\.com\/plat\/v4 reject"
DONGQIUDI_LEGACY_REWRITE_RULE = r"^https?:\/\/ap\.dongqiudi\.com\/plat\/v4 reject"
DONGQIUDI_MITM_HOSTNAME = "ap.dongdianqiu.com"
DONGQIUDI_LEGACY_MITM_HOSTNAME = "ap.dongqiudi.com"
DONGQIUDI_REWRITE_RULES = (
    DONGQIUDI_REWRITE_RULE,
    DONGQIUDI_LEGACY_REWRITE_RULE,
)
DONGQIUDI_MITM_HOSTNAMES = (
    DONGQIUDI_MITM_HOSTNAME,
    DONGQIUDI_LEGACY_MITM_HOSTNAME,
)

# 国内外链规则字典
domestic_lists = {
    "WeChat": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeChat/WeChat.list",
    "WeType": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeType/WeType.list",
    "Zhihu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Zhihu/Zhihu.list",
    "Weibo": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Weibo/Weibo.list",
    "DouBan": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DouBan/DouBan.list",
    "ByteDance": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ByteDance/ByteDance.list",
    "DouYin": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DouYin/DouYin.list",
    "BiliBili": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/BiliBili/BiliBili.list",
    "XiaoHongShu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XiaoHongShu/XiaoHongShu.list",
    "NetEaseMusic": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/NetEaseMusic/NetEaseMusic.list",
    "Himalaya": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Himalaya/Himalaya.list",
    "JingDong": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/JingDong/JingDong.list",
    "Pinduoduo": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Pinduoduo/Pinduoduo.list",
    "XianYu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XianYu/XianYu.list",
    "SMZDM": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/SMZDM/SMZDM.list",
    "MeiTuan": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/MeiTuan/MeiTuan.list",
    "CaiNiao": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CaiNiao/CaiNiao.list",
    "AliPay": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AliPay/AliPay.list",
    "CMB": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CMB/CMB.list",
    "ICBC": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ICBC/ICBC.list",
    "CCB": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CCB/CCB.list",
    "EastMoney": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/EastMoney/EastMoney.list",
    "DiDi": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DiDi/DiDi.list",
    "XieCheng": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XieCheng/XieCheng.list",
    "12306": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/12306/12306.list",
    "Baidu": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Baidu/Baidu.list",
    "ChinaMobile": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaMobile/ChinaMobile.list",
    "ChinaTelecom": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaTelecom/ChinaTelecom.list",
    "115": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/115/115.list",
}

openai_vps_url = "https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/shadowrocket/openai.list"
openai_v2fly_url = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai"
johnshall_url = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"


# ================= 文件与内容校验 =================
def _decode_utf8(data, source_name):
    try:
        return data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuleValidationError(f"{source_name}: 内容不是合法 UTF-8") from exc


def read_text_strict(path, source_name=None):
    path = Path(path)
    return _decode_utf8(path.read_bytes(), source_name or str(path))


def _reject_empty_or_html(content, source_name, content_type=""):
    if not content.strip():
        raise RuleValidationError(f"{source_name}: 内容为空")

    lowered_type = content_type.lower()
    sample = content.lstrip()[:256].lower()
    if "text/html" in lowered_type or sample.startswith("<!doctype html") or sample.startswith("<html"):
        raise RuleValidationError(f"{source_name}: 返回了 HTML，而不是规则文本")


def _section_matches(content):
    return list(re.finditer(r"(?m)^\[([^\]\r\n]+)\][ \t]*\r?$", content))


def _section_body_start(content, section_match):
    """Return the first byte after a section header and its line ending."""
    position = section_match.end()
    if position < len(content) and content[position] == "\n":
        position += 1
    return position


def _single_section(content, section_name, source_name):
    matches = [m for m in _section_matches(content) if m.group(1).strip().lower() == section_name.lower()]
    if len(matches) != 1:
        raise RuleValidationError(f"{source_name}: 需要且只能有一个 [{section_name}]，实际为 {len(matches)} 个")
    return matches[0]


def _check_rule_count_ratio(source_name, rule_count, baseline_count):
    if baseline_count is None:
        return

    lower = baseline_count * MIN_RULE_COUNT_RATIO
    upper = baseline_count * MAX_RULE_COUNT_RATIO
    if rule_count < lower or rule_count > upper:
        raise RuleValidationError(
            f"{source_name}: 有效规则数从 {baseline_count} 变为 {rule_count}，"
            f"超出允许范围 {MIN_RULE_COUNT_RATIO:.0%}～{MAX_RULE_COUNT_RATIO:.0%}"
        )


def provider_rule_lines(content, source_name, allowed_rule_types=None):
    lines = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            raise RuleValidationError(f"{source_name}:{line_number}: provider 列表不应包含配置区块")
        validate_provider_rule(
            line,
            source_name,
            line_number,
            allowed_rule_types=allowed_rule_types,
        )
        lines.append(line)
    return lines


def _validate_domain_target(target, location):
    candidate = target[:-1] if target.endswith(".") else target
    if candidate.startswith("*."):
        candidate = candidate[2:]
    try:
        ascii_candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise RuleValidationError(f"{location}: 域名无法进行 IDNA 编码") from exc
    if not ascii_candidate or len(ascii_candidate) > 253:
        raise RuleValidationError(f"{location}: 域名为空或长度超过 253")
    labels = ascii_candidate.split(".")
    label_pattern = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise RuleValidationError(f"{location}: 域名格式不合法 {target!r}")


def _validate_keyword_or_user_agent(target, location, maximum_length):
    if not target or len(target) > maximum_length or any(ord(character) < 32 for character in target):
        raise RuleValidationError(f"{location}: 匹配目标为空、过长或含控制字符")


def _validate_cidr(target, location, expected_version=None):
    if "/" not in target:
        raise RuleValidationError(f"{location}: CIDR 缺少前缀长度")
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise RuleValidationError(f"{location}: CIDR 格式不合法 {target!r}") from exc
    if expected_version is not None and network.version != expected_version:
        raise RuleValidationError(
            f"{location}: CIDR 地址族应为 IPv{expected_version}，实际为 IPv{network.version}"
        )


def _validate_asn(target, location):
    candidate = target[2:] if target.upper().startswith("AS") else target
    if not candidate.isdigit() or not 0 < int(candidate) <= 4_294_967_295:
        raise RuleValidationError(f"{location}: ASN 格式或范围不合法 {target!r}")


def _validate_port(target, location):
    bounds = target.split("-", 1)
    if any(not bound.isdigit() for bound in bounds):
        raise RuleValidationError(f"{location}: 端口格式不合法 {target!r}")
    ports = [int(bound) for bound in bounds]
    if any(not 1 <= port <= 65_535 for port in ports):
        raise RuleValidationError(f"{location}: 端口超出 1～65535 {target!r}")
    if len(ports) == 2 and ports[0] > ports[1]:
        raise RuleValidationError(f"{location}: 端口范围起点大于终点 {target!r}")


def _validate_policy(policy, location):
    # Tolerate the one existing upstream inline comment without treating it as
    # part of the policy name, while preserving the original line byte-for-byte.
    effective_policy = re.split(r"\s+#", policy, maxsplit=1)[0].strip()
    if (
        not effective_policy
        or effective_policy.lower() == "no-resolve"
        or any(ord(character) < 32 for character in effective_policy)
    ):
        raise RuleValidationError(f"{location}: 策略为空、错位或含控制字符")


def validate_provider_rule(
    line,
    source_name="规则源",
    line_number=None,
    allowed_rule_types=None,
):
    location = f"{source_name}:{line_number}" if line_number is not None else source_name
    parts = [part.strip() for part in line.split(",")]
    if allowed_rule_types is None:
        allowed_rule_types = PROVIDER_RULE_TYPES
    if not parts or parts[0].upper() not in allowed_rule_types:
        rule_type = parts[0] if parts else ""
        raise RuleValidationError(f"{location}: 不支持的规则类型 {rule_type!r}")
    if len(parts) < 2 or not parts[1]:
        raise RuleValidationError(f"{location}: 规则目标为空")

    rule_type = parts[0].upper()
    if rule_type in {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "USER-AGENT",
        "DST-PORT",
    }:
        if len(parts) != 2:
            raise RuleValidationError(f"{location}: {rule_type} 应为两个字段且不能预带策略")
    elif len(parts) not in {2, 3}:
        raise RuleValidationError(f"{location}: {rule_type} 字段数量不合法")
    elif len(parts) == 3 and parts[2].lower() != "no-resolve":
        raise RuleValidationError(f"{location}: 第三个字段只能是 no-resolve")

    target = parts[1]
    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        _validate_domain_target(target, location)
    elif rule_type == "DOMAIN-KEYWORD":
        _validate_keyword_or_user_agent(target, location, 253)
    elif rule_type == "USER-AGENT":
        _validate_keyword_or_user_agent(target, location, 1_024)
    elif rule_type == "IP-CIDR":
        # Preserve compatibility with Johnshall's historical IP-CIDR lines that
        # contain IPv6 prefixes. New OpenAI IPv6 rules use explicit IP-CIDR6.
        _validate_cidr(target, location)
    elif rule_type == "IP-CIDR6":
        _validate_cidr(target, location, 6)
    elif rule_type == "IP-ASN":
        _validate_asn(target, location)
    elif rule_type == "DST-PORT":
        _validate_port(target, location)
    return parts


def validate_routed_rule(line, source_name, line_number, allow_match=False):
    """Validate a complete Shadowrocket rule that already contains a policy."""
    location = f"{source_name}:{line_number}"
    parts = [part.strip() for part in line.split(",")]
    rule_type = parts[0].upper() if parts else ""
    allowed_types = JOHNSHALL_RULE_TYPES if allow_match else GENERATED_RULE_TYPES
    if rule_type not in allowed_types:
        raise RuleValidationError(f"{location}: 未知规则类型 {rule_type!r}")

    if rule_type in {"FINAL", "MATCH"}:
        if len(parts) != 2:
            raise RuleValidationError(f"{location}: {rule_type} 必须只有策略字段")
        _validate_policy(parts[1], location)
        return parts

    if len(parts) < 3 or not parts[1]:
        raise RuleValidationError(f"{location}: 规则目标或策略字段缺失")
    _validate_policy(parts[2], location)

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        if len(parts) != 3:
            raise RuleValidationError(f"{location}: {rule_type} 字段数量不合法")
        _validate_domain_target(parts[1], location)
    elif rule_type == "DOMAIN-KEYWORD":
        if len(parts) != 3:
            raise RuleValidationError(f"{location}: DOMAIN-KEYWORD 字段数量不合法")
        _validate_keyword_or_user_agent(parts[1], location, 253)
    elif rule_type == "USER-AGENT":
        if len(parts) != 3:
            raise RuleValidationError(f"{location}: USER-AGENT 字段数量不合法")
        _validate_keyword_or_user_agent(parts[1], location, 1_024)
    elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
        if len(parts) not in {3, 4}:
            raise RuleValidationError(f"{location}: {rule_type} 字段数量不合法")
        _validate_cidr(parts[1], location, None if rule_type == "IP-CIDR" else 6)
        if len(parts) == 4 and parts[3].lower() != "no-resolve":
            raise RuleValidationError(f"{location}: {rule_type} 可选字段只能是 no-resolve")
    elif rule_type == "IP-ASN":
        if len(parts) not in {3, 4}:
            raise RuleValidationError(f"{location}: IP-ASN 字段数量不合法")
        _validate_asn(parts[1], location)
        if len(parts) == 4 and parts[3].lower() != "no-resolve":
            raise RuleValidationError(f"{location}: IP-ASN 可选字段只能是 no-resolve")
    elif rule_type == "DST-PORT":
        if len(parts) != 3:
            raise RuleValidationError(f"{location}: DST-PORT 字段数量不合法")
        _validate_port(parts[1], location)
    elif rule_type == "GEOIP":
        if len(parts) != 3 or not re.fullmatch(r"[A-Za-z]{2}", parts[1]):
            raise RuleValidationError(f"{location}: GEOIP 国家代码或字段数量不合法")
    elif rule_type == "RULE-SET":
        parsed_url = urlparse(parts[1])
        if len(parts) != 3 or parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise RuleValidationError(f"{location}: RULE-SET URL 或字段数量不合法")
    return parts


def validate_provider_content(
    content,
    source_name,
    baseline_count=None,
    content_type="",
    allowed_rule_types=None,
):
    _reject_empty_or_html(content, source_name, content_type)
    lines = provider_rule_lines(
        content,
        source_name,
        allowed_rule_types=allowed_rule_types,
    )
    if not lines:
        raise RuleValidationError(f"{source_name}: 没有有效规则")
    canonical_source_name = source_name.removesuffix(" 本地缓存")
    audited_baseline = SOURCE_BASELINE_RULE_COUNTS.get(canonical_source_name)
    _check_rule_count_ratio(
        source_name,
        len(lines),
        baseline_count if baseline_count is not None else audited_baseline,
    )
    return len(lines)


def normalize_provider_rule(
    line,
    source_name="OpenAI 规则",
    allowed_rule_types=None,
):
    """Return a canonical provider rule while preserving matching semantics."""
    parts = validate_provider_rule(
        line,
        source_name,
        allowed_rule_types=allowed_rule_types,
    )
    rule_type = parts[0].upper()
    target = parts[1]

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        target = target.lower().rstrip(".")
    elif rule_type == "DOMAIN-KEYWORD":
        target = target.lower()
    elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
        target = str(ipaddress.ip_network(target, strict=False))
    elif rule_type == "IP-ASN":
        target = target[2:] if target.upper().startswith("AS") else target
    elif rule_type == "DST-PORT":
        target = "-".join(str(int(bound)) for bound in target.split("-", 1))

    normalized = [rule_type, target]
    if len(parts) == 3:
        normalized.append(parts[2].lower())
    return ",".join(normalized)


def validate_vps_openai_content(content, source_name, baseline_count=None, content_type=""):
    count = validate_provider_content(
        content,
        source_name,
        baseline_count=baseline_count,
        content_type=content_type,
    )
    sensitive_types = {"DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN"}
    for line in provider_rule_lines(content, source_name):
        normalized = normalize_provider_rule(line, source_name)
        rule_type = normalized.split(",", 1)[0]
        if normalized.startswith("IP-ASN,20473,") or normalized == "IP-ASN,20473":
            raise RuleValidationError(f"{source_name}: 禁止重新引入共享托管 ASN 20473")
        if (
            rule_type in sensitive_types
            and normalized not in OPENAI_APPROVED_VPS_SENSITIVE_RULES
        ):
            raise RuleValidationError(
                f"{source_name}: 出现未经审核的高影响规则 {normalized!r}"
            )
    return count


def v2fly_openai_rule_lines(content, source_name="OpenAI v2fly"):
    lines = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        fields = line.split()
        entry = fields[0]
        attributes = fields[1:]
        if any(not attribute.startswith("@") for attribute in attributes):
            raise RuleValidationError(
                f"{source_name}:{line_number}: v2fly 属性格式不合法"
            )

        if entry.startswith("full:"):
            target = entry.removeprefix("full:")
            rule = f"DOMAIN,{target}"
        elif entry.startswith("regexp:"):
            expression = entry.removeprefix("regexp:")
            rule = OPENAI_V2FLY_REGEX_RULES.get(expression)
            if rule is None:
                raise RuleValidationError(
                    f"{source_name}:{line_number}: 未审核的 v2fly 正则 {expression!r}"
                )
        elif ":" in entry:
            directive = entry.split(":", 1)[0]
            raise RuleValidationError(
                f"{source_name}:{line_number}: 不支持的 v2fly 指令 {directive!r}"
            )
        else:
            rule = f"DOMAIN-SUFFIX,{entry}"

        lines.append(normalize_provider_rule(rule, f"{source_name}:{line_number}"))

    if not lines:
        raise RuleValidationError(f"{source_name}: 没有有效规则")
    return lines


def validate_v2fly_openai_content(content, source_name, baseline_count=None, content_type=""):
    _reject_empty_or_html(content, source_name, content_type)
    lines = v2fly_openai_rule_lines(content, source_name)
    canonical_source_name = source_name.removesuffix(" 本地缓存")
    audited_baseline = SOURCE_BASELINE_RULE_COUNTS.get(canonical_source_name)
    _check_rule_count_ratio(
        source_name,
        len(lines),
        baseline_count if baseline_count is not None else audited_baseline,
    )
    return len(lines)


def local_provider_rule_lines(path, source_name, allowed_rule_types=None):
    content = read_text_strict(path, source_name)
    validate_provider_content(
        content,
        source_name,
        allowed_rule_types=allowed_rule_types,
    )
    return [
        normalize_provider_rule(
            line,
            source_name,
            allowed_rule_types=allowed_rule_types,
        )
        for line in provider_rule_lines(
            content,
            source_name,
            allowed_rule_types=allowed_rule_types,
        )
    ]


def local_openai_rule_lines(path, source_name):
    return local_provider_rule_lines(path, source_name)


def _pinned_rule_digest(lines):
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_pinned_claude_rules(path, source_name, expected_count, expected_digest):
    lines = local_provider_rule_lines(
        path,
        source_name,
        allowed_rule_types=PINNED_PROVIDER_RULE_TYPES,
    )
    if len(lines) != expected_count:
        raise RuleValidationError(
            f"{source_name}: 规则数量为 {len(lines)}，预期 {expected_count}"
        )
    if len(lines) != len(set(lines)):
        raise RuleValidationError(f"{source_name}: 含文本重复项")

    digest = _pinned_rule_digest(lines)
    if digest != expected_digest:
        raise RuleValidationError(
            f"{source_name}: 固定内容摘要不匹配，实际 sha256={digest}"
        )
    return lines


def build_claude_rule_groups():
    if claude_node != openai_node:
        raise RuleValidationError(
            "SCCR2685 含 Sentry、Statsig、Intercom、Datadog 等 OpenAI 共享规则；"
            "Claude 与 OpenAI 节点不一致时会破坏受保护分流"
        )

    primary_rules = _load_pinned_claude_rules(
        CLAUDE_SCCR2685_PATH,
        "Claude SCCR2685 固定主规则",
        CLAUDE_SCCR2685_RULE_COUNT,
        CLAUDE_SCCR2685_SHA256,
    )
    legacy_rules = _load_pinned_claude_rules(
        CLAUDE_LEGACY_EXTRA_PATH,
        "Claude 原有兼容补充",
        CLAUDE_LEGACY_EXTRA_RULE_COUNT,
        CLAUDE_LEGACY_EXTRA_SHA256,
    )
    official_rules = [
        normalize_provider_rule(line, "Claude 官方条件补充")
        for line in CLAUDE_OFFICIAL_EXTRA_RULES
    ]

    combined = primary_rules + legacy_rules + official_rules
    if len(combined) != len(set(combined)):
        raise RuleValidationError("Claude SCCR2685、原有兼容与官方条件补充含文本重复项")

    priority_types = {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "USER-AGENT",
    }
    network_types = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
    primary_priority = [
        line for line in primary_rules if line.split(",", 1)[0] in priority_types
    ]
    primary_network = [
        line for line in primary_rules if line.split(",", 1)[0] in network_types
    ]
    primary_ntp = [
        line for line in primary_rules if line.split(",", 1)[0] == "DST-PORT"
    ]
    if len(primary_priority) + len(primary_network) + len(primary_ntp) != len(primary_rules):
        raise RuleValidationError("Claude SCCR2685 出现未分组的规则类型")
    if primary_ntp != ["DST-PORT,123"]:
        raise RuleValidationError("Claude SCCR2685 NTP 兜底不是唯一的 DST-PORT,123")
    if any(line.split(",", 1)[0] not in priority_types for line in legacy_rules):
        raise RuleValidationError("Claude 原有兼容补充只能包含域名或 User-Agent 规则")
    if any(line.split(",", 1)[0] != "DOMAIN" for line in official_rules):
        raise RuleValidationError("Claude 官方条件补充只能包含精确域名")

    print(
        "-> Claude 固定规则已校验: "
        f"SCCR2685={len(primary_rules)}, legacy={len(legacy_rules)}, "
        f"official-extra={len(official_rules)}, merged={len(combined)}"
    )
    return {
        "primary_priority": primary_priority,
        "legacy_priority": legacy_rules,
        "official_priority": official_rules,
        "network": primary_network,
        "ntp": primary_ntp,
    }


def merge_openai_rule_lines(*rule_groups):
    merged = set()
    for group in rule_groups:
        for line in group:
            normalized = normalize_provider_rule(line)
            parts = normalized.split(",")
            if parts[0] == "IP-ASN" and parts[1] == "20473":
                continue
            if parts[0] in {"DOMAIN", "DOMAIN-SUFFIX"} and parts[1] == "humb.apple.com":
                continue
            merged.add(normalized)

    type_order = {
        "DOMAIN": 0,
        "DOMAIN-SUFFIX": 1,
        "DOMAIN-KEYWORD": 2,
        "USER-AGENT": 3,
        "IP-CIDR": 4,
        "IP-CIDR6": 5,
        "IP-ASN": 6,
    }
    return sorted(
        merged,
        key=lambda line: (
            type_order.get(line.split(",", 1)[0], 99),
            line.split(",")[1],
            line,
        ),
    )


def validate_merged_openai_rules(lines, baseline_rules):
    rules = set(lines)
    if len(lines) != len(rules):
        raise RuleValidationError("OpenAI 合并规则仍含文本重复项")
    if len(lines) < OPENAI_MIN_MERGED_RULES:
        raise RuleValidationError(
            f"OpenAI 合并规则只有 {len(lines)} 条，低于安全下限 {OPENAI_MIN_MERGED_RULES}"
        )

    missing_required = sorted(OPENAI_REQUIRED_RULES - rules)
    if missing_required:
        raise RuleValidationError(f"OpenAI 合并规则缺少哨兵项: {missing_required}")
    missing_baseline = sorted(set(baseline_rules) - rules)
    if missing_baseline:
        raise RuleValidationError(f"OpenAI 合并规则缩减了固定兼容底座: {missing_baseline}")
    if any(line.startswith("IP-ASN,20473,") or line == "IP-ASN,20473" for line in lines):
        raise RuleValidationError("OpenAI 合并规则禁止包含共享托管 ASN 20473")
    return len(lines)


def render_openai_provider(lines):
    return (
        "# BC OpenAI merged provider\n"
        "# Sources: conservative baseline + official domain overlay + VPSDance + v2fly\n"
        f"# Rule count: {len(lines)}\n\n"
        + "\n".join(lines)
        + "\n"
    )


def _johnshall_rule_block(content, source_name):
    sections = _section_matches(content)
    required_names = ["general", "rule", "url rewrite", "mitm"]
    required_matches = []
    for name in required_names:
        matches = [m for m in sections if m.group(1).strip().lower() == name]
        if len(matches) != 1:
            raise RuleValidationError(f"{source_name}: 需要且只能有一个 [{name}] 区块")
        required_matches.append(matches[0])

    positions = [m.start() for m in required_matches]
    if positions != sorted(positions):
        raise RuleValidationError(f"{source_name}: General/Rule/URL Rewrite/MITM 区块顺序异常")

    rule_match = required_matches[1]
    following_sections = [m for m in sections if m.start() > rule_match.start()]
    if not following_sections:
        raise RuleValidationError(f"{source_name}: [Rule] 后缺少下一个配置区块")
    next_section = min(following_sections, key=lambda m: m.start())
    if next_section.start() != required_matches[2].start():
        raise RuleValidationError(
            f"{source_name}: [Rule] 后的下一个区块必须是 [URL Rewrite]，"
            f"实际为 [{next_section.group(1).strip()}]"
        )
    rule_body_start = _section_body_start(content, rule_match)
    return rule_match, next_section, content[rule_body_start:next_section.start()]


def inject_url_rewrite_rules(content, rules, marker, source_name):
    """Prepend locally audited URL rewrites and remove exact upstream duplicates."""
    rewrite_match = _single_section(content, "URL Rewrite", source_name)
    mitm_match = _single_section(content, "MITM", source_name)
    if rewrite_match.start() > mitm_match.start():
        raise RuleValidationError(f"{source_name}: [URL Rewrite] 必须位于 [MITM] 之前")

    body_start = _section_body_start(content, rewrite_match)
    rewrite_body = content[body_start:mitm_match.start()]
    exact_rules = set(rules)
    filtered_body = "".join(
        raw_line
        for raw_line in rewrite_body.splitlines(keepends=True)
        if raw_line.strip() not in exact_rules
    )
    custom_block = marker + "\n" + "\n".join(rules) + "\n\n"
    return (
        content[:body_start]
        + custom_block
        + filtered_body
        + content[mitm_match.start():]
    )


def prepend_mitm_hostnames(content, hostnames, source_name):
    """Add required MITM hosts to the single hostname line without duplicates."""
    mitm_match = _single_section(content, "MITM", source_name)
    sections = _section_matches(content)
    following_sections = [
        match for match in sections if match.start() > mitm_match.start()
    ]
    body_end = min(
        (match.start() for match in following_sections),
        default=len(content),
    )
    body_start = _section_body_start(content, mitm_match)
    mitm_body = content[body_start:body_end]
    hostname_matches = list(
        re.finditer(r"(?m)^(hostname[ \t]*=[ \t]*)([^\r\n]*)", mitm_body)
    )
    if len(hostname_matches) != 1:
        raise RuleValidationError(
            f"{source_name}: [MITM] 需要且只能有一个 hostname 行，实际为 {len(hostname_matches)} 个"
        )

    hostname_match = hostname_matches[0]
    existing = [
        item.strip()
        for item in hostname_match.group(2).split(",")
        if item.strip()
    ]
    existing_lower = {item.lower() for item in existing}
    additions = [
        hostname for hostname in hostnames if hostname.lower() not in existing_lower
    ]
    combined = additions + existing
    replacement = hostname_match.group(1) + ",".join(combined)
    rewritten_body = (
        mitm_body[:hostname_match.start()]
        + replacement
        + mitm_body[hostname_match.end():]
    )
    return content[:body_start] + rewritten_body + content[body_end:]


def validate_johnshall_content(content, source_name, baseline_count=None, content_type=""):
    _reject_empty_or_html(content, source_name, content_type)
    _, _, rule_block = _johnshall_rule_block(content, source_name)

    active_rules = []
    for line_number, raw_line in enumerate(rule_block.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        validate_routed_rule(line, f"{source_name} [Rule]", line_number, allow_match=True)
        active_rules.append(line)

    if len(active_rules) < MIN_JOHNSHALL_RULES:
        raise RuleValidationError(
            f"{source_name}: [Rule] 只有 {len(active_rules)} 条，低于安全下限 {MIN_JOHNSHALL_RULES}"
        )
    _check_rule_count_ratio(source_name, len(active_rules), baseline_count)

    if len(re.findall(r"(?m)^dns-server[ \t]*=", content)) != 1:
        raise RuleValidationError(f"{source_name}: dns-server 行数量不是 1")
    return len(active_rules)


def attach_policy(line, policy):
    """Insert a policy before optional provider-rule options such as no-resolve."""
    parts = validate_provider_rule(
        line,
        allowed_rule_types=PINNED_PROVIDER_RULE_TYPES,
    )
    if not policy or "," in policy or "\n" in policy or "\r" in policy:
        raise RuleValidationError("策略名称为空或包含非法分隔符")
    return ",".join(parts[:2] + [policy] + parts[2:])


def _stage_bytes(path, data, suffix, mode):
    """Write and fsync bytes to a sibling temporary file."""
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=suffix, dir=str(path.parent)
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as temporary_file:
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return Path(temporary_name)


def _fsync_directories(directories):
    for directory in sorted({Path(path) for path in directories}, key=str):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _remove_if_present(path):
    if path is None:
        return
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


def transactional_write_text(updates):
    """Publish a set of UTF-8 files together, rolling every target back on error.

    Each replacement is atomic at the filesystem level. The surrounding rollback
    journal makes a multi-file generation behave as a transaction for ordinary
    write/rename failures: either every changed target is published, or the prior
    bytes are restored.
    """
    requested = {}
    order = []
    for raw_path, content in updates:
        target = Path(raw_path).resolve()
        if not isinstance(content, str):
            raise TypeError(f"{target}: 待写内容必须是字符串")
        encoded = content.encode("utf-8")
        if target in requested:
            if requested[target] != encoded:
                raise RuleValidationError(f"发布清单对 {target} 包含相互冲突的内容")
            continue
        requested[target] = encoded
        order.append(target)

    entries = []
    replaced = []
    directories = set()
    try:
        for target in order:
            target.parent.mkdir(parents=True, exist_ok=True)
            directories.add(target.parent)
            existed = target.exists()
            previous = target.read_bytes() if existed else None
            if previous == requested[target]:
                continue

            mode = (target.stat().st_mode & 0o777) if existed else 0o644
            staged = _stage_bytes(target, requested[target], ".publish.tmp", mode)
            try:
                rollback = (
                    _stage_bytes(target, previous, ".rollback.tmp", mode)
                    if previous is not None
                    else None
                )
            except Exception:
                _remove_if_present(staged)
                raise
            entries.append(
                {
                    "target": target,
                    "staged": staged,
                    "rollback": rollback,
                    "existed": existed,
                    "keep_rollback": False,
                }
            )

        for entry in entries:
            os.replace(entry["staged"], entry["target"])
            entry["staged"] = None
            replaced.append(entry)
        _fsync_directories(directories)
    except Exception as publish_error:
        rollback_errors = []
        for entry in reversed(replaced):
            try:
                if entry["existed"]:
                    os.replace(entry["rollback"], entry["target"])
                    entry["rollback"] = None
                else:
                    _remove_if_present(entry["target"])
            except Exception as rollback_error:
                entry["keep_rollback"] = True
                rollback_errors.append(
                    f"{entry['target']} (保留恢复副本 {entry['rollback']}): {rollback_error}"
                )

        for entry in entries:
            _remove_if_present(entry["staged"])
            if not entry["keep_rollback"]:
                _remove_if_present(entry["rollback"])
        try:
            _fsync_directories(directories)
        except OSError as rollback_sync_error:
            rollback_errors.append(f"目录同步: {rollback_sync_error}")

        if rollback_errors:
            details = "; ".join(rollback_errors)
            raise OSError(f"批量发布失败且回滚不完整: {details}") from publish_error
        raise

    for entry in entries:
        _remove_if_present(entry["staged"])
        _remove_if_present(entry["rollback"])
    if entries:
        _fsync_directories(directories)
    return [entry["target"] for entry in entries]


def atomic_write_text(path, content):
    """Atomically replace one UTF-8 text file while preserving its mode."""
    transactional_write_text([(path, content)])


def semantic_config_fingerprint(content):
    """Ignore comments/blank lines when deciding whether a backup is meaningful."""
    active_lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return hashlib.sha256("\n".join(active_lines).encode("utf-8")).hexdigest()


# ================= 核心网络与降级函数 =================
def _validate_download_url(url, source_name):
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or hostname not in ALLOWED_SOURCE_HOSTS:
        raise RuleValidationError(
            f"{source_name}: 仅允许从受信任 HTTPS 主机下载，实际为 {url!r}"
        )


def _read_bounded_response(response, source_name):
    declared_length = response.headers.get("content-length")
    if declared_length:
        try:
            declared_size = int(declared_length)
        except ValueError as exc:
            raise RuleValidationError(f"{source_name}: Content-Length 不合法") from exc
        if declared_size < 0 or declared_size > MAX_SOURCE_BYTES:
            raise RuleValidationError(
                f"{source_name}: 响应体声明大小 {declared_size} 超过上限 {MAX_SOURCE_BYTES}"
            )

    chunks = []
    total_size = 0
    if hasattr(response, "iter_content"):
        iterator = response.iter_content(chunk_size=SOURCE_DOWNLOAD_CHUNK_SIZE)
    else:
        iterator = (response.content,)
    for chunk in iterator:
        if not chunk:
            continue
        total_size += len(chunk)
        if total_size > MAX_SOURCE_BYTES:
            raise RuleValidationError(
                f"{source_name}: 响应体超过上限 {MAX_SOURCE_BYTES} 字节"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _download_source(url, source_name):
    _validate_download_url(url, source_name)
    attempts = max(1, SOURCE_DOWNLOAD_ATTEMPTS)
    last_error = None

    for attempt in range(1, attempts + 1):
        response = None
        try:
            response = requests.get(
                url,
                timeout=(SOURCE_CONNECT_TIMEOUT_SECONDS, SOURCE_TIMEOUT_SECONDS),
                stream=True,
                allow_redirects=True,
            )
            final_url = getattr(response, "url", None) or url
            _validate_download_url(final_url, f"{source_name} 重定向结果")

            if response.status_code == 200:
                return (
                    _read_bounded_response(response, source_name),
                    response.headers.get("content-type", ""),
                )
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                raise requests.HTTPError(f"HTTP {response.status_code}")
            raise RuleValidationError(f"HTTP {response.status_code}")
        except requests.RequestException as exc:
            last_error = exc
            if attempt == attempts:
                raise
        finally:
            if response is not None and callable(getattr(response, "close", None)):
                response.close()

        time.sleep(SOURCE_RETRY_BACKOFF_SECONDS * attempt)

    raise last_error  # pragma: no cover - 循环保证不会到达此处


def fetch_or_fallback(
    url,
    cache_path,
    source_name,
    validator,
    pending_cache_updates=None,
):
    cache_path = Path(cache_path)
    cached_content = None
    cached_count = None

    if cache_path.exists():
        try:
            cached_content = read_text_strict(cache_path, f"{source_name} 本地缓存")
            cached_count = validator(cached_content, f"{source_name} 本地缓存")
        except (OSError, RuleValidationError) as exc:
            print(f"!> {source_name} 本地缓存无效: {exc}", file=sys.stderr)
            cached_content = None
            cached_count = None

    try:
        response_bytes, content_type = _download_source(url, source_name)
        online_content = _decode_utf8(response_bytes, source_name)
        validator(online_content, source_name, cached_count, content_type)
        if pending_cache_updates is None:
            atomic_write_text(cache_path, online_content)
        else:
            pending_cache_updates.append((cache_path, online_content))
        return True, online_content
    except (requests.RequestException, OSError, RuleValidationError) as exc:
        print(f"!> {source_name} 在线内容不可用: {exc}", file=sys.stderr)

    if cached_content is not None:
        print(f"-> {source_name} 使用最后一份有效本地缓存")
        return False, cached_content
    return False, None


def fetch_sources_parallel(specifications):
    """Fetch independent sources concurrently and preserve specification order."""
    specifications = list(specifications)
    if not specifications:
        return {}, []

    keys = [specification[0] for specification in specifications]
    if len(keys) != len(set(keys)):
        raise RuleValidationError("并行下载清单包含重复键")

    def fetch_one(specification):
        key, url, cache_path, source_name, validator = specification
        local_updates = []
        result = fetch_or_fallback(
            url,
            cache_path,
            source_name,
            validator,
            local_updates,
        )
        return key, result, local_updates

    future_by_key = {}
    worker_count = min(MAX_DOWNLOAD_WORKERS, len(specifications))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        for specification in specifications:
            future = executor.submit(fetch_one, specification)
            future_by_key[specification[0]] = future

        results = {}
        pending_updates = []
        for key in keys:
            returned_key, result, local_updates = future_by_key[key].result()
            results[returned_key] = result
            pending_updates.extend(local_updates)
    return results, pending_updates


def validate_generated_config(content, source_name="生成配置", min_rule_count=None):
    _reject_empty_or_html(content, source_name)
    min_rule_count = MIN_GENERATED_RULES if min_rule_count is None else min_rule_count

    sections = _section_matches(content)
    required_names = ["general", "rule", "url rewrite", "mitm"]
    required_matches = []
    for name in required_names:
        matches = [m for m in sections if m.group(1).strip().lower() == name]
        if len(matches) != 1:
            raise RuleValidationError(f"{source_name}: 需要且只能有一个 [{name}] 区块")
        required_matches.append(matches[0])
    if [m.start() for m in required_matches] != sorted(m.start() for m in required_matches):
        raise RuleValidationError(f"{source_name}: 配置区块顺序异常")

    rule_match = required_matches[1]
    next_section = required_matches[2]
    rule_block = content[rule_match.end():next_section.start()]
    active_rules = []
    final_indexes = []

    for line_number, raw_line in enumerate(rule_block.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = validate_routed_rule(line, f"{source_name} [Rule]", line_number)
        rule_type = parts[0].upper()
        if rule_type == "RULE-SET":
            raise RuleValidationError(
                f"{source_name} [Rule]:{line_number}: 最终配置禁止运行时 RULE-SET"
            )
        if rule_type == "FINAL":
            final_indexes.append(len(active_rules))
        active_rules.append(line)

    if len(active_rules) < min_rule_count:
        raise RuleValidationError(
            f"{source_name}: 主规则只有 {len(active_rules)} 条，低于安全下限 {min_rule_count}"
        )
    if len(final_indexes) != 1:
        raise RuleValidationError(f"{source_name}: FINAL 数量不是 1")
    if final_indexes[0] != len(active_rules) - 1:
        raise RuleValidationError(f"{source_name}: FINAL 不是 [Rule] 中最后一条有效规则")

    if active_rules.count(DONGQIUDI_AD_RULE) != 1:
        raise RuleValidationError(
            f"{source_name}: 懂球帝域名拦截规则数量不是 1"
        )

    rewrite_match = required_matches[2]
    mitm_match = required_matches[3]
    rewrite_block = content[
        _section_body_start(content, rewrite_match):mitm_match.start()
    ]
    rewrite_rules = [
        line.strip()
        for line in rewrite_block.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    for rewrite_rule in DONGQIUDI_REWRITE_RULES:
        if rewrite_rules.count(rewrite_rule) != 1:
            raise RuleValidationError(
                f"{source_name}: 懂球帝 URL Rewrite 规则数量不是 1: {rewrite_rule}"
            )

    following_sections = [
        match for match in sections if match.start() > mitm_match.start()
    ]
    mitm_end = min(
        (match.start() for match in following_sections),
        default=len(content),
    )
    mitm_block = content[_section_body_start(content, mitm_match):mitm_end]
    hostname_lines = [
        line for line in mitm_block.splitlines()
        if re.match(r"^hostname[ \t]*=", line.strip(), flags=re.IGNORECASE)
    ]
    if len(hostname_lines) != 1:
        raise RuleValidationError(
            f"{source_name}: [MITM] hostname 行数量不是 1"
        )
    mitm_hostnames = [
        hostname.strip().lower()
        for hostname in hostname_lines[0].split("=", 1)[1].split(",")
        if hostname.strip()
    ]
    for hostname in DONGQIUDI_MITM_HOSTNAMES:
        if mitm_hostnames.count(hostname) != 1:
            raise RuleValidationError(
                f"{source_name}: 懂球帝 MITM hostname 数量不是 1: {hostname}"
            )

    required_markers = [
        "# Claude SCCR2685 全家桶 (使用节点:",
        "# Apple & iCloud Services (DIRECT)",
        "# Claude SCCR2685 NTP 兜底 (使用节点:",
        "# Tonghuashun (DIRECT)",
        "# Dongqiudi Ads (REJECT)",
        "# OpenAI (使用节点:",
        "# GitHub Copilot & Codex (使用节点:",
        "# --- Johnshall 去广告与基础代理区块 ---",
        "# --- 国内常用 APP 及服务 (DIRECT) ---",
        "# 兜底规则",
    ]
    marker_positions = []
    for marker in required_markers:
        position = rule_block.find(marker)
        if position == -1:
            raise RuleValidationError(f"{source_name}: 缺少顺序标记 {marker}")
        marker_positions.append(position)
    if marker_positions != sorted(marker_positions):
        raise RuleValidationError(f"{source_name}: 主要规则区块顺序发生变化")

    marker_by_prefix = dict(zip(required_markers, marker_positions))
    claude_groups = build_claude_rule_groups()
    expected_priority = [
        attach_policy(line, claude_node)
        for line in (
            claude_groups["primary_priority"]
            + claude_groups["legacy_priority"]
            + claude_groups["official_priority"]
            + claude_groups["network"]
        )
    ]
    if active_rules[:len(expected_priority)] != expected_priority:
        raise RuleValidationError(
            f"{source_name}: Claude SCCR2685 域名/兼容/IP 规则未完整位于 [Rule] 最前"
        )

    ntp_rule = attach_policy(claude_groups["ntp"][0], claude_node)
    ntp_start = marker_by_prefix["# Claude SCCR2685 NTP 兜底 (使用节点:"]
    tonghuashun_start = marker_by_prefix["# Tonghuashun (DIRECT)"]
    ntp_block_rules = [
        line.strip()
        for line in rule_block[ntp_start:tonghuashun_start].splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if ntp_block_rules != [ntp_rule] or active_rules.count(ntp_rule) != 1:
        raise RuleValidationError(
            f"{source_name}: Claude SCCR2685 NTP 兜底缺失、重复或位置异常"
        )
    return len(active_rules)


def build_openai_provider(cache_dir, pending_cache_updates, generated_path):
    baseline_rules = local_openai_rule_lines(
        OPENAI_COMPATIBILITY_PATH,
        "OpenAI 固定兼容底座",
    )
    official_rules = local_openai_rule_lines(
        OPENAI_OFFICIAL_PATH,
        "OpenAI 官方兼容层",
    )

    source_results, source_updates = fetch_sources_parallel(
        [
            (
                "vps",
                openai_vps_url,
                cache_dir / "OpenAI_VPSDance.list",
                "OpenAI VPSDance",
                validate_vps_openai_content,
            ),
            (
                "v2fly",
                openai_v2fly_url,
                cache_dir / "OpenAI_v2fly.txt",
                "OpenAI v2fly",
                validate_v2fly_openai_content,
            ),
        ]
    )
    pending_cache_updates.extend(source_updates)

    vps_online, vps_content = source_results["vps"]
    if vps_content is None:
        raise RuleValidationError("OpenAI VPSDance 在线内容和本地缓存都不可用")
    vps_rules = [
        normalize_provider_rule(line, "OpenAI VPSDance")
        for line in provider_rule_lines(vps_content, "OpenAI VPSDance")
    ]

    v2fly_online, v2fly_content = source_results["v2fly"]
    if v2fly_content is None:
        raise RuleValidationError("OpenAI v2fly 在线内容和本地缓存都不可用")
    v2fly_rules = v2fly_openai_rule_lines(v2fly_content)

    merged_rules = merge_openai_rule_lines(
        baseline_rules,
        official_rules,
        vps_rules,
        v2fly_rules,
    )
    validate_merged_openai_rules(merged_rules, baseline_rules)
    rendered_provider = render_openai_provider(merged_rules)

    pending_cache_updates.append((cache_dir / "OpenAI.list", rendered_provider))
    pending_cache_updates.append((Path(generated_path), rendered_provider))

    digest = hashlib.sha256(rendered_provider.encode("utf-8")).hexdigest()
    source_modes = ", ".join(
        [
            f"VPSDance={'online' if vps_online else 'cache'}",
            f"v2fly={'online' if v2fly_online else 'cache'}",
        ]
    )
    print(
        "-> OpenAI 合并完成: "
        f"baseline={len(baseline_rules)}, official={len(official_rules)}, "
        f"VPSDance={len(vps_rules)}, v2fly={len(v2fly_rules)}, "
        f"merged={len(merged_rules)}, "
        f"sha256={digest}, {source_modes}"
    )
    return merged_rules


# ================= 规则生成逻辑 =================
def build_config(
    output_path=DEFAULT_OUTPUT_PATH,
    cache_dir=DEFAULT_CACHE_DIR,
    backup_dir=DEFAULT_BACKUP_DIR,
    now=None,
    openai_generated_path=None,
):
    output_path = Path(output_path)
    cache_dir = Path(cache_dir)
    backup_dir = Path(backup_dir) if backup_dir is not None else None
    if openai_generated_path is None:
        default_output = REPOSITORY_DIR / DEFAULT_OUTPUT_PATH
        if output_path.resolve() == default_output.resolve():
            openai_generated_path = OPENAI_GENERATED_PATH
        else:
            openai_generated_path = output_path.with_name("OpenAI.generated.list")
    cache_dir.mkdir(parents=True, exist_ok=True)
    now = now or datetime.datetime.now()
    pending_cache_updates = []

    print(f"[{now}] 开始构建规则...")

    # 1. 构建硬编码高优先级规则。Claude 域名必须是 [Rule] 的首批有效规则；
    # Apple 仍放在全局 NTP 兜底之前，避免 time.apple.com 被端口规则抢走。
    apple_rules_str = f"# Apple & iCloud Services (DIRECT) - {now.strftime('%Y-%m-%d')}\n"
    apple_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in apple_domains]) + "\n"
    apple_rules_str += "".join([f"DOMAIN-KEYWORD,{d},DIRECT\n" for d in apple_keywords]) + "\n"

    tonghuashun_rules_str = f"# Tonghuashun (DIRECT) - {now.strftime('%Y-%m-%d')}\n"
    tonghuashun_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in tonghuashun_domains]) + "\n"

    dongqiudi_rules_str = (
        "# Dongqiudi Ads (REJECT) - 懂球帝去广告\n"
        f"{DONGQIUDI_AD_RULE}\n\n"
    )

    # 2. 构建 Copilot & OpenAI 强制分流
    copilot_rules_str = f"# GitHub Copilot & Codex (使用节点: {openai_node})\n"
    copilot_rules_str += "".join([f"DOMAIN,{d},{openai_node}\n" for d in copilot_domains]) + "\n"

    openai_rules_str = f"# OpenAI (使用节点: {openai_node})\n"
    openai_rules = build_openai_provider(
        cache_dir,
        pending_cache_updates,
        openai_generated_path,
    )
    for line in openai_rules:
        openai_rules_str += f"{attach_policy(line, openai_node)}\n"
    openai_rules_str += "\n"

    claude_groups = build_claude_rule_groups()
    claude_rules_str = f"# Claude SCCR2685 全家桶 (使用节点: {claude_node})\n"
    claude_rules_str += "# SCCR2685 主规则（域名与关键词优先）\n"
    for line in claude_groups["primary_priority"]:
        claude_rules_str += f"{attach_policy(line, claude_node)}\n"
    claude_rules_str += "# 原有 Claude 兼容补充（SCCR2685 未逐字包含）\n"
    for line in claude_groups["legacy_priority"]:
        claude_rules_str += f"{attach_policy(line, claude_node)}\n"
    claude_rules_str += "# Anthropic 官方条件补充（npm/bun 安装共享 registry）\n"
    for line in claude_groups["official_priority"]:
        claude_rules_str += f"{attach_policy(line, claude_node)}\n"
    claude_rules_str += "# SCCR2685 Anthropic 自有 IP / ASN 兜底\n"
    for line in claude_groups["network"]:
        claude_rules_str += f"{attach_policy(line, claude_node)}\n"
    claude_rules_str += "\n"

    claude_ntp_rules_str = f"# Claude SCCR2685 NTP 兜底 (使用节点: {claude_node})\n"
    claude_ntp_rules_str += "# 全设备端口规则；置于 Apple 域名直连之后以保护 Apple NTP。\n"
    for line in claude_groups["ntp"]:
        claude_ntp_rules_str += f"{attach_policy(line, claude_node)}\n"
    claude_ntp_rules_str += "\n"

    core_results, core_updates = fetch_sources_parallel(
        [
            (
                "johnshall",
                johnshall_url,
                cache_dir / "johnshall_latest.conf",
                "Johnshall",
                validate_johnshall_content,
            ),
        ]
    )
    pending_cache_updates.extend(core_updates)

    # 3. 处理 Johnshall 基础与去广告规则
    _, j_content = core_results["johnshall"]
    if j_content is None:
        raise RuleValidationError("Johnshall 在线内容和本地缓存都不可用，保留现有配置")

    rule_match, next_section, _ = _johnshall_rule_block(j_content, "Johnshall")
    rule_body_start = _section_body_start(j_content, rule_match)
    before_rules = j_content[:rule_body_start]
    j_rules_raw = j_content[rule_body_start:next_section.start()]
    after_rules = j_content[next_section.start():]

    optimized_dns = "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query"
    before_rules, replacement_count = re.subn(
        r"(?m)^dns-server[ \t]*=[^\r\n]*",
        optimized_dns,
        before_rules,
    )
    if replacement_count != 1:
        raise RuleValidationError(f"Johnshall: dns-server 替换次数为 {replacement_count}，预期为 1")

    # Remove upstream entries that conflict with the explicit iCloud DIRECT policy above.
    upstream_apple_conflicts = {
        "DOMAIN-SUFFIX,icloud-cdn.icloud.com.akadns.net,Proxy",
        "DOMAIN-SUFFIX,www-cdn.icloud.com.akadns.net,Proxy",
        "DOMAIN-SUFFIX,metrics.icloud.com,Reject",
    }
    locally_owned_rules = {
        DONGQIUDI_AD_RULE.upper(),
    }
    j_rules_clean = "\n".join([
        line for line in j_rules_raw.splitlines()
        if line.strip().split(",", 1)[0].upper() not in {"FINAL", "MATCH"}
        and line.strip() not in upstream_apple_conflicts
        and line.strip().upper() not in locally_owned_rules
    ])

    after_rules = inject_url_rewrite_rules(
        after_rules,
        DONGQIUDI_REWRITE_RULES,
        "# Dongqiudi Ads - 懂球帝开屏/跳转广告",
        "Johnshall 后置区块",
    )
    after_rules = prepend_mitm_hostnames(
        after_rules,
        DONGQIUDI_MITM_HOSTNAMES,
        "Johnshall 后置区块",
    )

    # 4. 并行获取并内联国内直连规则，客户端只执行构建时校验过的内容。
    domestic_rules_str = "\n# --- 国内常用 APP 及服务 (DIRECT) ---\n"
    domestic_results, domestic_updates = fetch_sources_parallel(
        [
            (
                name,
                url,
                cache_dir / f"{name}.list",
                name,
                validate_provider_content,
            )
            for name, url in domestic_lists.items()
        ]
    )
    pending_cache_updates.extend(domestic_updates)

    for name in domestic_lists:
        is_dom_online, dom_content = domestic_results[name]
        if dom_content is None:
            raise RuleValidationError(f"{name} 在线内容和本地缓存都不可用，保留现有配置")
        source_name = name if is_dom_online else f"{name} 本地缓存"
        mode = "在线校验快照" if is_dom_online else "本地缓存快照"
        domestic_rules_str += f"# {name} ({mode}内联)\n"
        for line in provider_rule_lines(dom_content, source_name):
            domestic_rules_str += f"{attach_policy(line, 'DIRECT')}\n"

    # 5. 核心严格拼装顺序。SCCR2685 域名/IP 位于所有通用规则之前；
    # 全局 NTP 在 Apple 域名后，避免改变受保护的 Apple 时间服务策略。
    final_rules = (
        claude_rules_str
        + apple_rules_str
        + claude_ntp_rules_str
        + tonghuashun_rules_str
        + dongqiudi_rules_str
        + openai_rules_str
        + copilot_rules_str
        + "\n# --- Johnshall 去广告与基础代理区块 ---\n"
        + j_rules_clean
        + domestic_rules_str
        + f"\n\n# 兜底规则\nFINAL,{default_node}\n"
    )

    new_content = before_rules + final_rules + after_rules
    validate_generated_config(new_content)

    # 缓存、审计产物、可选备份和正式配置一次性发布；任一替换失败即回滚全部。
    publication = list(pending_cache_updates)
    previous_content = None
    if output_path.exists():
        previous_content = read_text_strict(output_path, str(output_path))
    semantic_change = (
        previous_content is None
        or semantic_config_fingerprint(previous_content)
        != semantic_config_fingerprint(new_content)
    )

    if backup_dir is not None and semantic_change:
        backup_path = backup_dir / f"custom_rules_{now.strftime('%Y%m%d_%H%M%S')}.conf"
        publication.append((backup_path, new_content))
    elif backup_dir is not None:
        print("-> 主规则语义未变化，跳过时间戳备份")
    publication.append((output_path, new_content))
    transactional_write_text(publication)

    print(f"[{datetime.datetime.now()}] 规则已成功重构并生成！")
    return new_content


def validate_config_file(path):
    content = read_text_strict(path)
    rule_count = validate_generated_config(content, str(path))
    print(f"配置校验通过: {path} ({rule_count} 条有效规则)")
    return rule_count


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="构建并校验 Shadowrocket 规则")
    parser.add_argument("--validate-config", metavar="PATH", help="只读校验指定配置，不访问网络或写文件")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="生成配置输出路径")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR), help="规则缓存目录")
    parser.add_argument("--backup-dir", default=str(DEFAULT_BACKUP_DIR), help="生成配置备份目录")
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="不生成时间戳备份（CI 可依赖 Git 历史）",
    )
    parser.add_argument(
        "--openai-generated",
        default=None,
        help="OpenAI 合并 provider 审计文件路径",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.validate_config:
            validate_config_file(args.validate_config)
        else:
            build_config(
                output_path=args.output,
                cache_dir=args.cache_dir,
                backup_dir=None if args.no_backup else args.backup_dir,
                openai_generated_path=args.openai_generated,
            )
    except (OSError, requests.RequestException, RuleValidationError) as exc:
        print(f"严重错误: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
