import requests
import datetime
import sys
import os

# 创建备份目录
if not os.path.exists('backups'):
    os.makedirs('backups')

# Apple 和 iCloud 服务的域名列表，确保它们走直连
# (这是一个合并优化后的版本，确保苹果核心服务、iCloud、App Store 和推送服务稳定快速)
apple_domains = [
    # Apple Core & iCloud - 核心服务、认证与同步
    'apple.com',
    'apple.cn',                          # 新增: 苹果中国区服务
    'apple-cloudkit.com',
    'apple-livephotoskit.com',
    'icloud.com',
    'icloud.com.cn',
    'icloud-content.com',                # 新增: iCloud 内容服务
    'me.com',                            # 新增: MobileMe/iCloud 邮箱等
    'identity.apple.com',                # 账户认证
    'gs.apple.com',                      # 设备激活与验证
    'albert.apple.com',                  # iTunes 认证
    'gdmf.apple.com',                    # 设备管理

    # Content, App Store & Updates - 内容、应用商店和软件更新
    'itunes.com',
    'mzstatic.com',                      # 新增: App Store 和 iTunes 内容资源
    'cdn-apple.com',                     # Apple 的主要内容分发网络(CDN)
    'aaplimg.com',                       # 新增: 苹果图片/资源 CDN
    'static.ips.apple.com',
    'apps.apple.com',                    # 显式添加，确保优先级

    # Push Notification - APNs 推送服务
    'push.apple.com',
    '1-courier.push.apple.com',          # 新增: 推送服务器
    '2-courier.push.apple.com',          # 新增
    '3-courier.push.apple.com',          # 新增
    '4-courier.push.apple.com',          # 新增
    '5-courier.push.apple.com',          # 新增

    # System & Device Services - 系统网络与设备服务
    'captive.apple.com',                 # 用于检测Wi-Fi登录页
    'deviceenrollment.apple.com',        # 设备注册管理
    'deviceservices-external.apple.com',
    'iprofiles.apple.com',
    'sq-device.apple.com',
    'tbsc.apple.com',
    'time.apple.com',                    # 时间同步服务
    'time-ios.apple.com',
    'time-macos.apple.com',

    # iCloud Private Relay & Mask - 隐私中继相关
    'mask.icloud.com',
    'mask-h2.icloud.com',
    'gateway.icloud.com',                # 新增: iCloud 网关
    'setup.icloud.com',                  # 新增: iCloud 设置
]

# --- 新增: 同花顺相关域名，确保它们走直连 ---
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
    # --- 修正规则：强制将冲突的Apple CDN规则从Proxy改为DIRECT ---
print("正在修正原始规则中的Apple CDN代理冲突...")
apple_cdn_proxy_rules_to_fix = [
    'adcdownload.apple.com.akadns.net',
    'appldnld.g.aaplimg.com',
    'cds-cdn.v.aaplimg.com',
    'cds.apple.com.akadns.net',
    'cl1-cdn.origin-apple.com.akadns.net',
    'cl3-cdn.origin-apple.com.akadns.net',
    'cl4-cdn.origin-apple.com.akadns.net',
    'cl5-cdn.origin-apple.com.akadns.net',
    'clientflow.apple.com.akadns.net',
    'configuration.apple.com.akadns.net',
    'dd-cdn.origin-apple.com.akadns.net',
    'cdn.apple-mapkit.com',
    'gspe19-cn.ls-apple.com.akadns.net',
    'gs-loc-cn.apple.com',
    'icloud-cdn.icloud.com.akadns.net',
    'init-p01md-lb.push-apple.com.akadns.net',
    'init-p01st-lb.push-apple.com.akadns.net',
    'init-s01st-lb.push-apple.com.akadns.net',
    'itunes-apple.com.akadns.net',
    'mesu-china.apple.com.akadns.net',
    'mesu-cdn.apple.com.akadns.net',
    'ocsp-lb.apple.com.akadns.net',
    'oscdn.origin-apple.com.akadns.net',
    'pancake.cdn-apple.com.akadns.net',
    'prod-support.apple-support.akadns.net',
    'stocks-sparkline-lb.apple.com.akadns.net',
    'store.storeimages.apple.com.akadns.net',
    'support-china.apple-support.akadns.net',
    'swcatalog-cdn.apple.com.akadns.net',
    'swdist.apple.com.akadns.net',
    'swscan-cdn.apple.com.akadns.net',
    'valid.origin-apple.com.akadns.net',
    'phobos.apple.com'
]

for domain in apple_cdn_proxy_rules_to_fix:
    rule_to_find = f"DOMAIN-SUFFIX,{domain},Proxy"
    rule_to_replace = f"DOMAIN-SUFFIX,{domain},DIRECT"
    if rule_to_find in johnshall_content:
        johnshall_content = johnshall_content.replace(rule_to_find, rule_to_replace)
        print(f"  - 已修正: {domain} -> DIRECT")
print("Apple CDN代理冲突修正完成。")
# --- 修正结束 ---

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

        # --- 新增Apple & iCloud 直连规则 ---
        apple_rules_str = "# Apple & iCloud Services (DIRECT to fix sync issues) - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in apple_domains:
            apple_rules_str += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        apple_rules_str += "\n"
        
        # --- 新增同花顺直连规则 ---
        tonghuashun_rules_str = "# Tonghuashun (DIRECT) - " + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        for domain in tonghuashun_domains:
            tonghuashun_rules_str += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        tonghuashun_rules_str += "\n"

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
        
        # 组合所有规则：Apple直连 -> 同花顺直连 -> OpenAI -> 原始规则
        new_rules = apple_rules_str + tonghuashun_rules_str + openai_rules_str + "\n# 原始规则\n" + rules

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
        # --- 创建包含Apple和同花顺直连规则的最小化备用配置 ---
        apple_fallback_rules = ""
        for domain in apple_domains:
            apple_fallback_rules += f"DOMAIN-SUFFIX,{domain},DIRECT\n"
        
        tonghuashun_fallback_rules = ""
        for domain in tonghuashun_domains:
            tonghuashun_fallback_rules += f"DOMAIN-SUFFIX,{domain},DIRECT\n"

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
        print("创建了包含Apple和同花顺直连规则的最小化备用配置")

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
