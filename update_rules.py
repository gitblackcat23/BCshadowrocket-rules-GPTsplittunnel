import requests
import datetime
import sys
import os

# 创建备份目录
if not os.path.exists('backups'):
    os.makedirs('backups')

# Apple 和 iCloud 服务的域名列表，确保它们走直连
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

# 同花顺相关域名，确保它们走直连
tonghuashun_domains = [
    '10jqka.com.cn', 'hexin.cn', 'data.10jqka.com.cn', 't.10jqka.com.cn',
    'news.10jqka.com.cn', 'q.10jqka.com.cn', 'basic.10jqka.com.cn', 'moni.10jqka.com.cn',
    'upass.10jqka.com.cn', 'user.10jqka.com.cn', 'search.10jqka.com.cn', '5188.money.10jqka.com.cn',
]

# GitHub Copilot / OpenAI Codex 相关域名，强制走 OpenAI 节点
copilot_domains = [
    'api.githubcopilot.com',
    'copilot-proxy.githubusercontent.com',
    'copilot-telemetry.githubusercontent.com',
    'origin-tracker.githubusercontent.com',
]

# --- 新增：国内常用 APP 及服务 Rule-Set 集合（强制直连） ---
domestic_direct_rules_str = """
# --- 社交与资讯 ---
#微信
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeChat/WeChat.list,DIRECT
#微信输入法
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeType/WeType.list,DIRECT
#知乎
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Zhihu/Zhihu.list,DIRECT
#微博
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Weibo/Weibo.list,DIRECT
#豆瓣
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DouBan/DouBan.list,DIRECT
#字节跳动
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ByteDance/ByteDance.list,DIRECT

# --- 影音娱乐 ---
#抖音
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DouYin/DouYin.list,DIRECT
#BiliBili
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/BiliBili/BiliBili.list,DIRECT
#小红书
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XiaoHongShu/XiaoHongShu.list,DIRECT
#网易云音乐
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/NetEaseMusic/NetEaseMusic.list,DIRECT
#喜马拉雅
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Himalaya/Himalaya.list,DIRECT

# --- 购物与生活 ---
#京东
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/JingDong/JingDong.list,DIRECT
#拼多多
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Pinduoduo/Pinduoduo.list,DIRECT
#闲鱼
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XianYu/XianYu.list,DIRECT
#什么值得买
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/SMZDM/SMZDM.list,DIRECT
#美团
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/MeiTuan/MeiTuan.list,DIRECT
#菜鸟裹裹
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CaiNiao/CaiNiao.list,DIRECT

# --- 金融与支付 ---
#支付宝
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AliPay/AliPay.list,DIRECT
#招商银行
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CMB/CMB.list,DIRECT
#中国工商银行
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ICBC/ICBC.list,DIRECT
#建设银行
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/CCB/CCB.list,DIRECT
#东方财富
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/EastMoney/EastMoney.list,DIRECT

# --- 交通与工具 ---
#滴滴
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/DiDi/DiDi.list,DIRECT
#携程
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/XieCheng/XieCheng.list,DIRECT
#12306
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/12306/12306.list,DIRECT
#百度
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Baidu/Baidu.list,DIRECT
#中国移动
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaMobile/ChinaMobile.list,DIRECT
#中国电信
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaTelecom/ChinaTelecom.list,DIRECT
#115
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/115/115.list,DIRECT
"""

try:
    # 下载Johnshall规则
    johnshall_url = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"
    try:
        johnshall_response = requests.get(johnshall_url, timeout=15)
        if johnshall_response.status_code == 200:
            johnshall_content = johnshall_response.text
            with open('backups/johnshall_latest.conf', 'w', encoding='utf-8') as f:
                f.write(johnshall_content)
            print("Johnshall规则已更新并备份")
        else:
            raise Exception(f"Johnshall规则返回状态码: {johnshall_response.status_code}")
    except Exception as e:
        print(f"下载Johnshall规则失败: {e}")
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
            with open('backups/openai_latest.list', 'w', encoding='utf-8') as f:
                f.write(openai_content)
            print("OpenAI规则已更新并备份")
        else:
            raise Exception(f"OpenAI规则返回状态码: {openai_response.status_code}")
    except Exception as e:
        print(f"下载OpenAI规则失败: {e}")
        if os.path.exists('backups/openai_latest.list'):
            with open('backups/openai_latest.list', 'r', encoding='utf-8') as f:
                openai_content = f.read()
            print("使用OpenAI规则备份")
        else:
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
            rule_section_end = len(johnshall_content)

        before_rules = johnshall_content[:rule_section_start + 7]
        rules = johnshall_content[rule_section_start + 7:rule_section_end]
        after_rules = johnshall_content[rule_section_end:]

        # 生成Apple & iCloud 直连规则
        apple_rules_str = "# Apple & iCloud Services (DIRECT) - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in apple_domains:
            apple_rules_str += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        apple_rules_str += "\n"
        
        # 生成同花顺直连规则
        tonghuashun_rules_str = "# Tonghuashun (DIRECT) - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in tonghuashun_domains:
            tonghuashun_rules_str += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        tonghuashun_rules_str += "\n"

        # 生成 GitHub Copilot 分流规则
        copilot_rules_str = "# GitHub Copilot & Codex (使用节点: " + openai_node + ") - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in copilot_domains:
            copilot_rules_str += f"DOMAIN,{domain},{openai_node}\n"
        copilot_rules_str += "\n"

        # 生成 OpenAI 规则
        openai_rules_str = "# OpenAI Rules (使用节点: " + openai_node + ") - 更新于" + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        if openai_content.startswith("DOMAIN") or openai_content.startswith("# OpenAI"):
            lines = openai_content.strip().split('\n')
            for line in lines:
                if line and not line.startswith('#'):
                    openai_rules_str += line + "," + openai_node + "\n"
        else:
            openai_rules_str += "RULE-SET," + openai_url + "," + openai_node + "\n"
        
        # 核心拼装：Apple直连 -> 同花顺直连 -> 国内App/云盘直连 -> Copilot分流 -> OpenAI分流 -> 原始兜底规则
        new_rules = apple_rules_str + tonghuashun_rules_str + domestic_direct_rules_str + copilot_rules_str + openai_rules_str + "\n# 原始兜底规则\n" + rules

        # 替换FINAL规则
        if "FINAL," in new_rules:
            new_rules = new_rules.replace("FINAL,PROXY", "FINAL," + default_node)
            new_rules = new_rules.replace("FINAL,DIRECT", "FINAL," + default_node)
        else:
            new_rules += "\nFINAL," + default_node + "\n"

        new_content = before_rules + new_rules + after_rules
        
    except Exception as e:
        print(f"处理规则内容时出错: {e}")
        # 创建包含所有直连规则的最小化备用配置，防止断网
        apple_fallback_rules = "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in apple_domains])
        tonghuashun_fallback_rules = "".join([f"DOMAIN-SUFFIX,{d},DIRECT\n" for d in tonghuashun_domains])
        copilot_fallback_rules = "".join([f"DOMAIN,{d},{openai_node}\n" for d in copilot_domains])

        new_content = f"""[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
dns-server = system
ipv6 = false
update-url = https://raw.githubusercontent.com/gitblackcat23/BCshadowrocket-rules-GPTsplittunnel/main/custom_shadowrocket_rules.conf

[Rule]
# Apple & iCloud Services (DIRECT)
{apple_fallback_rules}
# Tonghuashun (DIRECT)
{tonghuashun_fallback_rules}
# Domestic Apps & 115 Drive (DIRECT)
{domestic_direct_rules_str}
# GitHub Copilot & Codex (Proxy)
{copilot_fallback_rules}
# OpenAI Rules (Proxy)
DOMAIN-SUFFIX,openai.com,{openai_node}
DOMAIN-SUFFIX,ai.com,{openai_node}
DOMAIN-KEYWORD,openai,{openai_node}
IP-CIDR,24.199.123.28/32,{openai_node},no-resolve

FINAL,{default_node}

[Host]
localhost = 127.0.0.1
"""
        print("创建了包含全部直连和分流规则的最小化备用配置")

    # 写入文件并备份
    with open('custom_shadowrocket_rules.conf', 'w', encoding='utf-8') as f:
        f.write(new_content)
        
    backup_path = f'backups/custom_rules_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.conf'
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"规则已更新并备份到 {backup_path}")
        
except Exception as e:
    print(f"错误: {e}", file=sys.stderr)
    try:
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
