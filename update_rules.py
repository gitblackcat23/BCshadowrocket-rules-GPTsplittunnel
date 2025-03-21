import requests
import datetime
import sys
import os

# 创建备份目录
if not os.path.exists('backups'):
    os.makedirs('backups')

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

        # 插入OpenAI规则和设置默认节点
        new_rules = "# OpenAI Rules (使用节点: " + openai_node + ") - 更新于" + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
        
        # 使用RULE-SET方式或直接嵌入规则
        if openai_content.startswith("DOMAIN") or openai_content.startswith("# OpenAI"):
            # 直接嵌入规则
            lines = openai_content.strip().split('\n')
            for line in lines:
                if line and not line.startswith('#'):
                    new_rules += line + "," + openai_node + "\n"
        else:
            # 使用RULE-SET方式
            new_rules += "RULE-SET," + openai_url + "," + openai_node + "\n\n"
        
        new_rules += "# 原始规则\n" + rules

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
        # 使用基本模板创建一个最小化但有效的配置
        new_content = """[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
dns-server = system
ipv6 = false
update-url = https://raw.githubusercontent.com/gitblackcat23/BCshadowrocket-rules-GPTsplittunnel/main/custom_shadowrocket_rules.conf

[Rule]
# OpenAI Rules (使用节点: """ + openai_node + """) - 更新于""" + datetime.datetime.now().strftime("%Y-%m-%d") + """
DOMAIN-SUFFIX,openai.com,""" + openai_node + """
DOMAIN-SUFFIX,ai.com,""" + openai_node + """
DOMAIN-SUFFIX,auth0.com,""" + openai_node + """
DOMAIN-KEYWORD,openai,""" + openai_node + """
DOMAIN,chat.openai.com,""" + openai_node + """
DOMAIN,platform.openai.com,""" + openai_node + """
DOMAIN,openaiapi-site.azureedge.net,""" + openai_node + """
IP-CIDR,24.199.123.28/32,""" + openai_node + """,no-resolve

# 其他所有流量
FINAL,""" + default_node + """

[Host]
localhost = 127.0.0.1
"""
        print("创建了最小化但有效的配置")

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
