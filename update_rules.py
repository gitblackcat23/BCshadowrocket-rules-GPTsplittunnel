import argparse
import datetime
import ipaddress
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import requests


# ================= 基础配置 =================
default_node = "V3(vless+vision+reality)"
openai_node = "V3 Static Residential"
# 新增：Claude 专用固定线路（建议与 OpenAI 共用或单独指定你的纯净 IP 节点名称）
claude_node = "V3 Static Residential"

DEFAULT_CACHE_DIR = Path("backups/rules_cache")
DEFAULT_BACKUP_DIR = Path("backups")
DEFAULT_OUTPUT_PATH = Path("custom_shadowrocket_rules.conf")
SOURCE_TIMEOUT_SECONDS = 12
MIN_RULE_COUNT_RATIO = 0.5
MAX_RULE_COUNT_RATIO = 2.0
MIN_JOHNSHALL_RULES = 10_000
MIN_GENERATED_RULES = 10_000

# Audited active-rule counts from the repository's known-good caches at commit
# 85ef191. They provide a first-run safety baseline when a cache is missing or
# damaged; crossing the 50%-200% envelope requires an explicit baseline review.
SOURCE_BASELINE_RULE_COUNTS = {
    "OpenAI": 35,
    "Claude": 3,
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
    "IP-ASN",
}

GENERATED_RULE_TYPES = PROVIDER_RULE_TYPES | {
    "GEOIP",
    "RULE-SET",
    "FINAL",
}

# Johnshall historically may use MATCH as an upstream terminator; the generator
# intentionally removes MATCH/FINAL and writes its own single FINAL.
JOHNSHALL_RULE_TYPES = GENERATED_RULE_TYPES | {"MATCH"}


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

# OpenAI dependencies that must keep the same high-priority residential route
# even when the upstream RULE-SET is online, stale, or replaced by local cache.
openai_manual_domains = [
    "oaistatsig.com",
]

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

openai_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"
claude_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Claude/Claude.list"
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


def provider_rule_lines(content, source_name):
    lines = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            raise RuleValidationError(f"{source_name}:{line_number}: provider 列表不应包含配置区块")
        validate_provider_rule(line, source_name, line_number)
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


def _validate_cidr(target, location):
    if "/" not in target:
        raise RuleValidationError(f"{location}: CIDR 缺少前缀长度")
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise RuleValidationError(f"{location}: CIDR 格式不合法 {target!r}") from exc


def _validate_asn(target, location):
    candidate = target[2:] if target.upper().startswith("AS") else target
    if not candidate.isdigit() or not 0 < int(candidate) <= 4_294_967_295:
        raise RuleValidationError(f"{location}: ASN 格式或范围不合法 {target!r}")


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


def validate_provider_rule(line, source_name="规则源", line_number=None):
    location = f"{source_name}:{line_number}" if line_number is not None else source_name
    parts = [part.strip() for part in line.split(",")]
    if not parts or parts[0].upper() not in PROVIDER_RULE_TYPES:
        rule_type = parts[0] if parts else ""
        raise RuleValidationError(f"{location}: 不支持的规则类型 {rule_type!r}")
    if len(parts) < 2 or not parts[1]:
        raise RuleValidationError(f"{location}: 规则目标为空")

    rule_type = parts[0].upper()
    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "USER-AGENT"}:
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
        _validate_cidr(target, location)
    elif rule_type == "IP-ASN":
        _validate_asn(target, location)
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
    elif rule_type == "IP-CIDR":
        if len(parts) not in {3, 4}:
            raise RuleValidationError(f"{location}: IP-CIDR 字段数量不合法")
        _validate_cidr(parts[1], location)
        if len(parts) == 4 and parts[3].lower() != "no-resolve":
            raise RuleValidationError(f"{location}: IP-CIDR 可选字段只能是 no-resolve")
    elif rule_type == "IP-ASN":
        if len(parts) not in {3, 4}:
            raise RuleValidationError(f"{location}: IP-ASN 字段数量不合法")
        _validate_asn(parts[1], location)
        if len(parts) == 4 and parts[3].lower() != "no-resolve":
            raise RuleValidationError(f"{location}: IP-ASN 可选字段只能是 no-resolve")
    elif rule_type == "GEOIP":
        if len(parts) != 3 or not re.fullmatch(r"[A-Za-z]{2}", parts[1]):
            raise RuleValidationError(f"{location}: GEOIP 国家代码或字段数量不合法")
    elif rule_type == "RULE-SET":
        parsed_url = urlparse(parts[1])
        if len(parts) != 3 or parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise RuleValidationError(f"{location}: RULE-SET URL 或字段数量不合法")
    return parts


def validate_provider_content(content, source_name, baseline_count=None, content_type=""):
    _reject_empty_or_html(content, source_name, content_type)
    lines = provider_rule_lines(content, source_name)
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
    parts = validate_provider_rule(line)
    if not policy or "," in policy or "\n" in policy or "\r" in policy:
        raise RuleValidationError("策略名称为空或包含非法分隔符")
    return ",".join(parts[:2] + [policy] + parts[2:])


def atomic_write_text(path, content):
    """Atomically replace a UTF-8 text file without changing an existing file mode."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = (path.stat().st_mode & 0o777) if path.exists() else 0o644
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as temporary_file:
            temporary_file.write(content.encode("utf-8"))
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, path)
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


# ================= 核心网络与降级函数 =================
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
        response = requests.get(url, timeout=SOURCE_TIMEOUT_SECONDS)
        if response.status_code != 200:
            raise RuleValidationError(f"HTTP {response.status_code}")
        online_content = _decode_utf8(response.content, source_name)
        content_type = response.headers.get("content-type", "")
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

    required_markers = [
        "# Apple & iCloud Services (DIRECT)",
        "# Tonghuashun (DIRECT)",
        "# OpenAI (使用节点:",
        "# Claude 全家桶 (使用节点:",
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
    return len(active_rules)


# ================= 规则生成逻辑 =================
def build_config(
    output_path=DEFAULT_OUTPUT_PATH,
    cache_dir=DEFAULT_CACHE_DIR,
    backup_dir=DEFAULT_BACKUP_DIR,
    now=None,
):
    output_path = Path(output_path)
    cache_dir = Path(cache_dir)
    backup_dir = Path(backup_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    now = now or datetime.datetime.now()
    pending_cache_updates = []

    print(f"[{now}] 开始构建规则...")

    # 1. 构建硬编码极高优先级 (Apple & 同花顺)
    apple_rules_str = f"# Apple & iCloud Services (DIRECT) - {now.strftime('%Y-%m-%d')}\n"
    apple_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in apple_domains]) + "\n"
    apple_rules_str += "".join([f"DOMAIN-KEYWORD,{d},DIRECT\n" for d in apple_keywords]) + "\n"

    tonghuashun_rules_str = f"# Tonghuashun (DIRECT) - {now.strftime('%Y-%m-%d')}\n"
    tonghuashun_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in tonghuashun_domains]) + "\n"

    # 2. 构建 Copilot & OpenAI 强制分流
    copilot_rules_str = f"# GitHub Copilot & Codex (使用节点: {openai_node})\n"
    copilot_rules_str += "".join([f"DOMAIN,{d},{openai_node}\n" for d in copilot_domains]) + "\n"

    is_online, openai_content = fetch_or_fallback(
        openai_url,
        cache_dir / "OpenAI.list",
        "OpenAI",
        validate_provider_content,
        pending_cache_updates,
    )
    if openai_content is None:
        raise RuleValidationError("OpenAI 在线内容和本地缓存都不可用，保留现有配置")

    openai_rules_str = f"# OpenAI (使用节点: {openai_node})\n"
    openai_rules_str += "".join([
        f"DOMAIN-SUFFIX,{domain},{openai_node}\n"
        for domain in openai_manual_domains
    ])
    if is_online:
        openai_rules_str += f"RULE-SET,{openai_url},{openai_node}\n\n"
        print("-> OpenAI 规则库在线，使用 RULE-SET 订阅")
    else:
        print("!> OpenAI 规则库失联，触发本地纯文本接管")
        for line in provider_rule_lines(openai_content, "OpenAI 本地缓存"):
            openai_rules_str += f"{attach_policy(line, openai_node)}\n"
        openai_rules_str += "\n"

    # ================= Claude 无死角分流逻辑 =================
    is_cl_online, cl_content = fetch_or_fallback(
        claude_url,
        cache_dir / "Claude.list",
        "Claude",
        validate_provider_content,
        pending_cache_updates,
    )
    if cl_content is None:
        raise RuleValidationError("Claude 在线内容和本地缓存都不可用，保留现有配置")

    claude_rules_str = f"# Claude 全家桶 (使用节点: {claude_node})\n"

    # A. Claude 精确探针域名，放在更宽泛规则之前，避免被后续兜底规则吞掉。
    claude_exact_domains = [
        "api64.ipify.org",
    ]
    claude_rules_str += "".join([f"DOMAIN,{d},{claude_node}\n" for d in claude_exact_domains])

    # B. 核心 UA 匹配 (针对 CLI 和 App)
    claude_rules_str += f"USER-AGENT,Claude*,{claude_node}\n"
    claude_rules_str += f"USER-AGENT,anthropic*,{claude_node}\n"

    # C. 核心域名后缀 (Artifacts/Cowork 必备 + 新增极致防封补丁)
    claude_manual_domains = [
        # --- 原有保留 ---
        "claude.ai", "anthropic.com", "claudeusercontent.com", "statsigapi.net",
        # --- 新增：人机验证与前端静态依赖 (防卡加载) ---
        "hcaptcha.com", "recaptcha.net", "gstatic.com", "cloudflare-static.com",
        # --- 新增：高危遥测与后台统计 (防封核心) ---
        "statsig.com", "sentry.io", "segment.io", "datadoghq.com", "browser-intake-datadoghq.com",
        # --- 新增：支付与主控域名 ---
        "unlimited-pay.anthropic.com",
    ]
    claude_rules_str += "".join([f"DOMAIN-SUFFIX,{d},{claude_node}\n" for d in claude_manual_domains])

    # D. 新增精确匹配逻辑 (缩小遥测域名的误伤范围)
    claude_rules_str += f"DOMAIN,statsigapi.net,{claude_node}\n"

    # E. 原有及新增的关键字匹配
    claude_rules_str += f"DOMAIN-KEYWORD,claude,{claude_node}\n"
    claude_rules_str += f"DOMAIN-KEYWORD,anthropic,{claude_node}\n"

    # F. 订阅 Rule-Set (补充库中可能存在的其他域名)
    if is_cl_online:
        claude_rules_str += f"RULE-SET,{claude_url},{claude_node}\n"
        print("-> Claude 规则库在线，使用 RULE-SET 订阅")
    else:
        print("!> Claude 规则库失联，使用本地缓存内联接管")
        for line in provider_rule_lines(cl_content, "Claude 本地缓存"):
            claude_rules_str += f"{attach_policy(line, claude_node)}\n"
    claude_rules_str += "\n"
    # =================================================================

    # 3. 处理 Johnshall 基础与去广告规则
    _, j_content = fetch_or_fallback(
        johnshall_url,
        cache_dir / "johnshall_latest.conf",
        "Johnshall",
        validate_johnshall_content,
        pending_cache_updates,
    )
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
    j_rules_clean = "\n".join([
        line for line in j_rules_raw.splitlines()
        if line.strip().split(",", 1)[0].upper() not in {"FINAL", "MATCH"}
        and line.strip() not in upstream_apple_conflicts
    ])

    # 4. 构建国内直连 RULE-SET
    domestic_rules_str = "\n# --- 国内常用 APP 及服务 (DIRECT) ---\n"
    for name, url in domestic_lists.items():
        is_dom_online, dom_content = fetch_or_fallback(
            url,
            cache_dir / f"{name}.list",
            name,
            validate_provider_content,
            pending_cache_updates,
        )
        if dom_content is None:
            raise RuleValidationError(f"{name} 在线内容和本地缓存都不可用，保留现有配置")
        if is_dom_online:
            domestic_rules_str += f"RULE-SET,{url},DIRECT\n"
        else:
            domestic_rules_str += f"# {name} (降级使用本地缓存内联)\n"
            for line in provider_rule_lines(dom_content, f"{name} 本地缓存"):
                domestic_rules_str += f"{attach_policy(line, 'DIRECT')}\n"

    # 5. 核心严格拼装顺序 (Claude 规则紧跟 OpenAI)
    final_rules = (
        apple_rules_str
        + tonghuashun_rules_str
        + openai_rules_str
        + claude_rules_str
        + copilot_rules_str
        + "\n# --- Johnshall 去广告与基础代理区块 ---\n"
        + j_rules_clean
        + domestic_rules_str
        + f"\n\n# 兜底规则\nFINAL,{default_node}\n"
    )

    new_content = before_rules + final_rules + after_rules
    validate_generated_config(new_content)

    # No online response reaches a cache until the complete generated config has
    # passed validation, closing gaps between source parsing and transformation.
    for cache_path, cache_content in pending_cache_updates:
        atomic_write_text(cache_path, cache_content)

    # 先成功写入新的独立备份，再原子替换正式配置；正式配置永远不会半写入。
    backup_path = backup_dir / f"custom_rules_{now.strftime('%Y%m%d_%H%M%S')}.conf"
    atomic_write_text(backup_path, new_content)
    atomic_write_text(output_path, new_content)

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
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.validate_config:
            validate_config_file(args.validate_config)
        else:
            build_config(args.output, args.cache_dir, args.backup_dir)
    except (OSError, requests.RequestException, RuleValidationError) as exc:
        print(f"严重错误: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
