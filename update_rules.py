import requests
import datetime
import sys
import os
import re

# ================= 基础配置 =================
default_node = "V3(vless+vision+reality)"
openai_node = "V3 Static Residential"
# 新增：Claude 专用固定线路（建议与 OpenAI 共用或单独指定你的纯净 IP 节点名称）
claude_node = "V3 Static Residential" 

# 确保备份与缓存目录存在
cache_dir = 'backups/rules_cache'
if not os.path.exists(cache_dir):
    os.makedirs(cache_dir)

# 硬编码高优先级直连域名
apple_domains = [
    'apple.com', 'apple.cn', 'apple-cloudkit.com', 'apple-livephotoskit.com',
    'icloud.com', 'icloud.com.cn', 'icloud-content.com', 'me.com',
    'files.apple.com', 'ws.icloud.com', 'com.apple.ubiquity.bulletin', 'com.apple.photos',
    'identity.apple.com', 'gs.apple.com', 'albert.apple.com', 'gdmf.apple.com',
    'setup.icloud.com', 'configuration.apple.com', 'itunes.com', 'mzstatic.com',
    'cdn-apple.com', 'aaplimg.com', 'static.ips.apple.com', 'apps.apple.com',
    'p30-buy.itunes.apple.com', 'books.itunes.apple.com', 'secure.store.apple.com',
    'news-assets.apple.com', 'streaming.apple.com', 'music.apple.com', 'tv.apple.com',
    'search.itunes.apple.com', 'push.apple.com', '1-courier.push.apple.com',
    '2-courier.push.apple.com', '3-courier.push.apple.com', '4-courier.push.apple.com',
    '5-courier.push.apple.com', 'captive.apple.com', 'deviceenrollment.apple.com',
    'deviceservices-external.apple.com', 'iprofiles.apple.com', 'sq-device.apple.com',
    'tbsc.apple.com', 'time.apple.com', 'time-ios.apple.com', 'time-macos.apple.com',
    'gsa.apple.com', 'iadsdk.apple.com', 'metrics.apple.com', 'wallet.apple.com',
    'weather-data.apple.com', 'api.weather.com', 'siri.apple.com', 'locationd.apple.com',
    'icloud-api.apple.com', 'mask.icloud.com', 'mask-h2.icloud.com', 'gateway.icloud.com',
]

tonghuashun_domains = [
    '10jqka.com.cn', 'hexin.cn', 'data.10jqka.com.cn', 't.10jqka.com.cn',
    'news.10jqka.com.cn', 'q.10jqka.com.cn', 'basic.10jqka.com.cn', 'moni.10jqka.com.cn',
    'upass.10jqka.com.cn', 'user.10jqka.com.cn', 'search.10jqka.com.cn', '5188.money.10jqka.com.cn',
]

copilot_domains = [
    'api.githubcopilot.com',
    'copilot-proxy.githubusercontent.com',
    'copilot-telemetry.githubusercontent.com',
    'origin-tracker.githubusercontent.com',
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
    "115": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/115/115.list"
}

# ================= 核心网络与降级函数 =================
def fetch_or_fallback(url, cache_path):
    try:
        response = requests.get(url, timeout=12)
        if response.status_code == 200:
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            return True, response.text
    except Exception:
        pass
    
    if os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            return False, f.read()
    return False, None

# ================= 规则生成逻辑 =================
try:
    print(f"[{datetime.datetime.now()}] 开始构建规则...")

    # 1. 构建硬编码极高优先级 (Apple & 同花顺)
    apple_rules_str = f"# Apple & iCloud Services (DIRECT) - {datetime.datetime.now().strftime('%Y-%m-%d')}\n"
    apple_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in apple_domains]) + "\n"
    
    tonghuashun_rules_str = f"# Tonghuashun (DIRECT) - {datetime.datetime.now().strftime('%Y-%m-%d')}\n"
    tonghuashun_rules_str += "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in tonghuashun_domains]) + "\n"

    # 2. 构建 Copilot & OpenAI 强制分流
    copilot_rules_str = f"# GitHub Copilot & Codex (使用节点: {openai_node})\n"
    copilot_rules_str += "".join([f"DOMAIN,{d},{openai_node}\n" for d in copilot_domains]) + "\n"

    openai_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"
    is_online, openai_content = fetch_or_fallback(openai_url, os.path.join(cache_dir, "OpenAI.list"))
    
    openai_rules_str = f"# OpenAI (使用节点: {openai_node})\n"
    if is_online:
        openai_rules_str += f"RULE-SET,{openai_url},{openai_node}\n\n"
        print("-> OpenAI 规则库在线，使用 RULE-SET 订阅")
    else:
        print("!> OpenAI 规则库失联，触发本地纯文本接管")
        if openai_content:
            for line in openai_content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    openai_rules_str += f"{line},{openai_node}\n"
        else:
            # 极限兜底 (已按照你的要求完美修复)
            openai_rules_str += f"DOMAIN-KEYWORD,openai,{openai_node}\nDOMAIN-SUFFIX,openai.com,{openai_node}\n"
        openai_rules_str += "\n"

    # ================= [新增部分] Claude 无死角分流逻辑 =================
    claude_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Claude/Claude.list"
    is_cl_online, cl_content = fetch_or_fallback(claude_url, os.path.join(cache_dir, "Claude.list"))
    
    claude_rules_str = f"# Claude 全家桶 (使用节点: {claude_node})\n"
    # A. 核心 UA 匹配 (针对 CLI 和 App)
    claude_rules_str += f"USER-AGENT,Claude*,{claude_node}\n"
    claude_rules_str += f"USER-AGENT,anthropic*,{claude_node}\n"
    
    # B. 核心域名后缀 (Artifacts/Cowork 必备 + 新增极致防封补丁)
    claude_manual_domains = [
        # --- 原有保留 ---
        'claude.ai', 'anthropic.com', 'claudeusercontent.com', 'statsigapi.net',
        # --- 新增：人机验证与前端静态依赖 (防卡加载) ---
        'hcaptcha.com', 'recaptcha.net', 'gstatic.com', 'cloudflare-static.com',
        # --- 新增：高危遥测与后台统计 (防封核心) ---
        'statsig.com', 'sentry.io', 'segment.io', 'datadoghq.com', 'browser-intake-datadoghq.com',
        # --- 新增：支付与主控域名 ---
        'unlimited-pay.anthropic.com'
    ]
    claude_rules_str += "".join([f"DOMAIN-SUFFIX,{d},{claude_node}\n" for d in claude_manual_domains])
    
    # 新增精确匹配逻辑 (缩小遥测域名的误伤范围)
    claude_rules_str += f"DOMAIN,statsigapi.net,{claude_node}\n"
    
    # 原有及新增的关键字匹配
    claude_rules_str += f"DOMAIN-KEYWORD,claude,{claude_node}\n"
    claude_rules_str += f"DOMAIN-KEYWORD,anthropic,{claude_node}\n"

    # C. 订阅 Rule-Set (补充库中可能存在的其他域名)
    if is_cl_online:
        claude_rules_str += f"RULE-SET,{claude_url},{claude_node}\n"
        print("-> Claude 规则库在线，使用 RULE-SET 订阅")
    else:
        print("!> Claude 规则库失联，使用手动硬编码规则接管")
    claude_rules_str += "\n"
    # =================================================================

    # 3. 处理 Johnshall 基础与去广告规则
    johnshall_url = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"
    is_j_online, j_content = fetch_or_fallback(johnshall_url, os.path.join(cache_dir, "johnshall_latest.conf"))
    if not j_content:
        raise Exception("致命错误: Johnshall 规则拉取失败且无本地缓存。")

    rule_start = j_content.find('[Rule]')
    rule_end = j_content.find('[', rule_start + 1)
    if rule_end == -1: rule_end = len(j_content)

    before_rules = j_content[:rule_start + 7]
    j_rules_raw = j_content[rule_start + 7:rule_end]
    after_rules = j_content[rule_end:]

    optimized_dns = "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query, 119.29.29.29"
    before_rules = re.sub(r'dns-server\s*=\s*.*', optimized_dns, before_rules)

    j_rules_clean = "\n".join([line for line in j_rules_raw.splitlines() if not line.startswith('FINAL,') and not line.startswith('MATCH,')])

    # 4. 构建国内直连 RULE-SET
    domestic_rules_str = "\n# --- 国内常用 APP 及服务 (DIRECT) ---\n"
    for name, url in domestic_lists.items():
        is_dom_online, dom_content = fetch_or_fallback(url, os.path.join(cache_dir, f"{name}.list"))
        if is_dom_online:
            domestic_rules_str += f"RULE-SET,{url},DIRECT\n"
        else:
            if dom_content:
                domestic_rules_str += f"# {name} (降级使用本地缓存内联)\n"
                for line in dom_content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domestic_rules_str += f"{line},DIRECT\n"

    # 5. 核心严格拼装顺序 (Claude 规则紧跟 OpenAI)
    final_rules = (
        apple_rules_str + 
        tonghuashun_rules_str + 
        openai_rules_str + 
        claude_rules_str +  # <<< Claude 插入此处
        copilot_rules_str + 
        "\n# --- Johnshall 去广告与基础代理区块 ---\n" +
        j_rules_clean +
        domestic_rules_str +
        f"\n\n# 兜底规则\nFINAL,{default_node}\n"
    )

    new_content = before_rules + final_rules + after_rules

    # ================= 写入文件 =================
    with open('custom_shadowrocket_rules.conf', 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    backup_path = f'backups/custom_rules_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.conf'
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
        
    print(f"[{datetime.datetime.now()}] 规则已成功重构并生成！")

except Exception as e:
    print(f"严重错误: {e}", file=sys.stderr)
    sys.exit(1)
