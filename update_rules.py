import requests
import datetime
import sys
import os

# 创建备份目录
if not os.path.exists('backups'):
    os.makedirs('backups')

# Apple 和 iCloud 服务的域名列表，确保它们走直连
apple_domains = [
    # --- Apple Core, Account & iCloud Sync ---
    'apple.com',
    'apple.cn',
    'apple-cloudkit.com',
    'apple-livephotoskit.com',
    'icloud.com',
    'icloud.com.cn',
    'icloud-content.com',
    'me.com',
    'files.apple.com',
    'ws.icloud.com',
    'com.apple.ubiquity.bulletin',
    'com.apple.photos',

    # --- Authentication & Setup ---
    'identity.apple.com',
    'gs.apple.com',
    'albert.apple.com',
    'gdmf.apple.com',
    'setup.icloud.com',
    'configuration.apple.com',

    # --- Content, App Store & Updates ---
    'itunes.com',
    'mzstatic.com',
    'cdn-apple.com',
    'aaplimg.com',
    'static.ips.apple.com',
    'apps.apple.com',
    'p30-buy.itunes.apple.com',
    'books.itunes.apple.com',
    'secure.store.apple.com',
    'news-assets.apple.com',
    'streaming.apple.com',
    'music.apple.com',
    'tv.apple.com',
    'search.itunes.apple.com',

    # --- Push Notification (APNs) ---
    'push.apple.com',
    '1-courier.push.apple.com',
    '2-courier.push.apple.com',
    '3-courier.push.apple.com',
    '4-courier.push.apple.com',
    '5-courier.push.apple.com',

    # --- System, Device & Other Services ---
    'captive.apple.com',
    'deviceenrollment.apple.com',
    'deviceservices-external.apple.com',
    'iprofiles.apple.com',
    'sq-device.apple.com',
    'tbsc.apple.com',
    'time.apple.com',
    'time-ios.apple.com',
    'time-macos.apple.com',
    'gsa.apple.com',
    'iadsdk.apple.com',
    'metrics.apple.com',
    'wallet.apple.com',
    'weather-data.apple.com',
    'api.weather.com',
    'siri.apple.com',
    'locationd.apple.com',
    'icloud-api.apple.com',
    
    # --- iCloud Private Relay & Mask ---
    'mask.icloud.com',
    'mask-h2.icloud.com',
    'gateway.icloud.com',
]

# --- 同花顺相关域名，确保它们走直连 ---
tonghuashun_domains = [
    '10jqka.com.cn',
    'hexin.cn',
    'data.10jqka.com.cn',
    't.10jqka.com.cn',
    'news.10jqka.com.cn',
    'q.10jqka.com.cn',
    'basic.10jqka.com.cn',
    'moni.10jqka.com.cn',
    'upass.10jqka.com.cn',
    'user.10jqka.com.cn',
    'search.10jqka.com.cn',
    '5188.money.10jqka.com.cn',
]

# --- 新增: GitHub Copilot / OpenAI Codex 相关域名，强制走 OpenAI 节点 ---
copilot_domains = [
    'api.githubcopilot.com',
    'copilot-proxy.githubusercontent.com',
    'copilot-telemetry.githubusercontent.com',
    'origin-tracker.githubusercontent.com',
]

try:
    # 下载Johnshall规则
    johnshall_url = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"
    try:
        johnshall_response = requests.get(johnshall_url, timeout=15)
        if johnshall_response.status_code == 200:
            johnshall_content = johnshall_response.text
            
            # 创建备份
            with open('backups/johnshall_latest.conf', 'w', encoding='utf-8') as f:
                f.write(johnshall_content)
            print("Johnshall规则已更新并备份")
        else:
            raise Exception(f"Johnshall规则返回状态码: {johnshall_response.status_code}")
    except Exception as e:
        print(f"下载Johnshall规则失败: {e}")
        # 使用备份文件
        if os.path.exists('backups/johnshall_latest.conf'):
            with open('backups/johnshall_latest.conf', 'r', encoding='utf-8') as f:
                johnshall_content = f.read()
            print("使用Johnshall规则备份")
        else:
            raise Exception("没有Johnshall规则备份可用")

    # 下载OpenAI规则
    openai_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"
    try:
        openai_response = requests.get(openai_url, timeout=15)
        if openai_response.status_code == 200:
            openai_content = openai_response.text
            
            # 创建备份
            with open('backups/openai_latest.list', 'w', encoding='utf-8') as f:
                f.write(openai_content)
            print("OpenAI规则已更新并备份")
        else:
            raise Exception(f"OpenAI规则返回状态码: {openai_response.status_code}")
    except Exception as e:
        print(f"下载OpenAI规则失败: {e}")
        # 使用备份文件
        if os.path.exists('backups/openai_latest.list'):
            with open('backups/openai_latest.list', 'r', encoding='utf-8') as f:
                openai_content = f.read()
            print("使用OpenAI规则备份")
        else:
            # 使用硬编码的OpenAI规则作为最后的备份
            openai_content = """# OpenAI
DOMAIN-SUFFIX,openai.com
DOMAIN-SUFFIX,ai.com
DOMAIN-SUFFIX,auth0.com
DOMAIN-KEYWORD,openai
DOMAIN,chat.openai.com
DOMAIN,platform.openai.com
DOMAIN,openaiapi-site.azureedge.net
IP-CIDR,24.199.123.28/32,no-resolve"""
            print("使用硬编码的OpenAI规则")
    
    # 定义节点名称
    default_node = "V3(vless+vision+reality)"
    openai_node = "V3 Static Residential"

    # 处理规则内容
    try:
        rule_section_start = johnshall_content.find('[Rule]')
        if rule_section_start == -1:
            raise Exception("在Johnshall规则中找不到[Rule]部分")
            
        rule_section_end = johnshall_content.find('[', rule_section_start + 1)
        if rule_section_end == -1:
            # 如果找不到下一个section，就取到文件末尾
            rule_section_end = len(johnshall_content)

        before_rules = johnshall_content[:rule_section_start + 7]  # 包含[Rule]和换行符
        rules = johnshall_content[rule_section_start + 7:rule_section_end]
        after_rules = johnshall_content[rule_section_end:]

        # --- 生成Apple & iCloud 直连规则 ---
        apple_rules_str = "# Apple & iCloud Services (DIRECT) - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in apple_domains:
            apple_rules_str += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        apple_rules_str += "\n"
        
        # --- 生成同花顺直连规则 ---
        tonghuashun_rules_str = "# Tonghuashun (DIRECT) - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in tonghuashun_domains:
            tonghuashun_rules_str += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        tonghuashun_rules_str += "\n"

        # --- 新增：生成 GitHub Copilot 分流规则 ---
        copilot_rules_str = "# GitHub Copilot & Codex (使用节点: " + openai_node + ") - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in copilot_domains:
            # 注意：这里使用 DOMAIN 精确匹配，防止误杀其他无关的 github 流量
            copilot_rules_str += f"DOMAIN,{domain},{openai_node}\n"
        copilot_rules_str += "\n"

        # 插入OpenAI规则和设置默认节点
        openai_rules_str = "# OpenAI Rules (使用节点: " + openai_node + ") - 更新于" + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        
        # 使用RULE-SET方式或直接嵌入规则
        if openai_content.startswith("DOMAIN") or openai_content.startswith("# OpenAI"):
            # 直接嵌入规则
            lines = openai_content.strip().split('\n')
            for line in lines:
                if line and not line.startswith('#'):
                    openai_rules_str += line + "," + openai_node + "\n"
        else:
            # 使用RULE-SET方式
            openai_rules_str += "RULE-SET," + openai_url + "," + openai_node + "\n"
        
        # 组合所有规则：Apple直连 -> 同花顺直连 -> Copilot分流 -> OpenAI分流 -> 原始规则
        new_rules = apple_rules_str + tonghuashun_rules_str + copilot_rules_str + openai_rules_str + "\n# 原始规则\n" + rules

        # 替换FINAL规则
        if "FINAL," in new_rules:
            new_rules = new_rules.replace("FINAL,PROXY", "FINAL," + default_node)
            new_rules = new_rules.replace("FINAL,DIRECT", "FINAL," + default_node)
        else:
            new_rules += "\nFINAL," + default_node + "\n"

        # 生成新配置
        new_content = before_rules + new_rules + after_rules
    except Exception as e:
        print(f"处理规则内容时出错: {e}")
        # --- 创建包含Apple、同花顺和Copilot的最小化备用配置 ---
        apple_fallback_rules = ""
        for domain in apple_domains:
            apple_fallback_rules += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        
        tonghuashun_fallback_rules = ""
        for domain in tonghuashun_domains:
            tonghuashun_fallback_rules += f"DOMAIN-SUFFIX,{domain},DIRECT\n"

        copilot_fallback_rules = ""
        for domain in copilot_domains:
            copilot_fallback_rules += f"DOMAIN,{domain},{openai_node}\n"

        new_content = f"""[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
dns-server = system
ipv6 = false
update-url = https://raw.githubusercontent.com/gitblackcat23/BCshadowrocket-rules-GPTsplittunnel/main/custom_shadowrocket_rules.conf

[Rule]
# Apple & iCloud Services (DIRECT to fix sync issues)
{apple_fallback_rules}
# Tonghuashun (DIRECT)
{tonghuashun_fallback_rules}
# GitHub Copilot & Codex (Proxy)
{copilot_fallback_rules}
# OpenAI Rules (使用节点: {openai_node}) - 更新于{datetime.datetime.now().strftime("%Y-%m-%d")}
DOMAIN-SUFFIX,openai.com,{openai_node}
DOMAIN-SUFFIX,ai.com,{openai_node}
DOMAIN-SUFFIX,auth0.com,{openai_node}
DOMAIN-KEYWORD,openai,{openai_node}
DOMAIN,chat.openai.com,{openai_node}
DOMAIN,platform.openai.com,{openai_node}
DOMAIN,openaiapi-site.azureedge.net,{openai_node}
IP-CIDR,24.199.123.28/32,{openai_node},no-resolve

# 其他所有流量
FINAL,{default_node}

[Host]
localhost = 127.0.0.1
"""
        print("创建了包含Apple、同花顺直连以及Copilot分流的最小化备用配置")

    # 写入文件
    with open('custom_shadowrocket_rules.conf', 'w', encoding='utf-8') as f:
        f.write(new_content)
        
    # 同时创建备份
    backup_path = f'backups/custom_rules_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.conf'
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"规则已更新并备份到 {backup_path}")
        
except Exception as e:
    print(f"错误: {e}", file=sys.stderr)
    # 如果出现错误，尝试恢复最近的有效配置
    try:
        # 找到最新的备份文件
        backup_files = [f for f in os.listdir('backups') if f.startswith('custom_rules_')]
        if backup_files:
            latest_backup = max(backup_files)
            with open(f'backups/{latest_backup}', 'r', encoding='utf-8') as f:
                backup_content = f.read()
            
            with open('custom_shadowrocket_rules.conf', 'w', encoding='utf-8') as f:
                f.write(backup_content)
            print(f"从备份 {latest_backup} 恢复了配置")
        else:
            print("没有找到可用的备份文件")
    except Exception as recovery_error:
        print(f"尝试恢复配置时出错: {recovery_error}")
