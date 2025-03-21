import requests
import datetime
import sys

try:
    # 原有代码...
    
    # 下载Johnshall规则
    johnshall_url = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"
    johnshall_content = requests.get(johnshall_url).text

    # 下载OpenAI规则
    openai_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"
    openai_content = requests.get(openai_url).text

    # 其余保持不变...
    
except Exception as e:
    print(f"错误: {e}", file=sys.stderr)
    sys.exit(1)

import requests
import datetime

# 下载Johnshall规则
johnshall_url = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf"
johnshall_content = requests.get(johnshall_url).text

# 下载OpenAI规则
openai_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"
openai_content = requests.get(openai_url).text

# 定义节点名称
default_node = "V3(vless+vision+reality)"
openai_node = "V3 Static Residential"

# 处理规则内容
rule_section_start = johnshall_content.find('[Rule]')
rule_section_end = johnshall_content.find('[', rule_section_start + 1)

before_rules = johnshall_content[:rule_section_start + 7]  # 包含[Rule]和换行符
rules = johnshall_content[rule_section_start + 7:rule_section_end]
after_rules = johnshall_content[rule_section_end:]

# 插入OpenAI规则和设置默认节点
new_rules = "# OpenAI Rules (使用节点: " + openai_node + ") - 更新于" + datetime.datetime.now().strftime("%Y-%m-%d") + "\n"
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

# 写入文件
with open('custom_shadowrocket_rules.conf', 'w', encoding='utf-8') as f:
    f.write(new_content)
