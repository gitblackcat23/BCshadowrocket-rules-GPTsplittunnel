import requests
import datetime
import sys
import os
import re

# ================= 基础配置 =================
default_node = "V3(vless+vision+reality)"
openai_node = "V3 Static Residential"
# Claude 专用固定线路
claude_node = "V3 Static Residential" 

# 确保备份与缓存目录存在
cache_dir = 'backups/rules_cache'
if not os.path.exists(cache_dir):
    os.makedirs(cache_dir)

# ================= 核心防御改动 =================
# 将备忘录和 iCloud 同步的关键域名置顶，确保最高匹配优先级，防止被 apple.com 宽泛匹配拦截
apple_domains = [
    'apple-cloudkit.com',    # 备忘录及数据同步核心通道
    'push.apple.com',        # 苹果底层推送与唤醒服务
    'icloud.com',            # iCloud 核心与附件服务
    'apple.com', 'apple.cn', 'apple-livephotoskit.com',
    'icloud.com.cn', 'icloud-content.com', 'me.com',
    'files.apple.com', 'ws.icloud.com', 'com.apple.ubiquity.bulletin', 'com.apple.photos',
    'identity.apple.com', 'gs.apple.com', 'albert.apple.com', 'gdmf.apple.com',
    'setup.icloud.com', 'configuration.apple.com', 'itunes.com', 'mzstatic.com',
    'cdn-apple.com', 'aaplimg.com', 'static.ips.apple.com', 'apps.apple.com',
    'p30-buy.itunes.apple.com', 'books.itunes.apple.com', 'secure.store.apple.com',
    'news-assets.apple.com', 'static.gc.apple.com', 'app-site-association.cdn-apple.com'
]

# 通用函数：获取远程内容或使用本地缓存
def fetch_or_fallback(url, cache_path):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            with open(cache_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            return True, response.text
    except Exception as e:
        print(f"警告: 无法获取 {url}, 尝试使用缓存. 错误: {e}")
    
    if os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            return False, f.read()
    return False, None

# ================= 核心逻辑 =================

# 1. 读取原始模版（从 custom_shadowrocket_rules.conf 读取）
if not os.path.exists('custom_shadowrocket_rules.conf'):
    print("错误: 找不到 custom_shadowrocket_rules.conf 模版文件")
    sys.exit(1)

with open('custom_shadowrocket_rules.conf', 'r', encoding='utf-8') as f:
    content = f.read()

# 定位 [Rule] 标记
rule_marker = "[Rule]"
if rule_marker not in content:
    print("错误: 配置文件中找不到 [Rule] 标记")
    sys.exit(1)

parts = content.split(rule_marker)
before_rules = parts[0] + rule_marker + "\n"
# 丢弃原有规则，重新生成全新纯净的分流列表
after_rules = "" 

# 2. 生成苹果核心规则区块 (最高优先级)
apple_rules_str = "\n# --- 苹果核心系统及服务 (DIRECT) ---\n"
for domain in apple_domains:
    apple_rules_str += f"DOMAIN-SUFFIX,{domain},DIRECT\n"

# 3. 准备其他规则区块
# 同花顺 (DIRECT)
tonghuashun_rules_str = "\n# --- 同花顺 (DIRECT) ---\n"
tonghuashun_list_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Ths/Ths.list"
_, ths_content = fetch_or_fallback(tonghuashun_list_url, os.path.join(cache_dir, "Ths.list"))
if ths_content:
    tonghuashun_rules_str += f"RULE-SET,{tonghuashun_list_url},DIRECT\n"

# OpenAI (PROXY)
openai_rules_str = "\n# --- OpenAI (PROXY) ---\n"
openai_list_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"
_, ai_content = fetch_or_fallback(openai_list_url, os.path.join(cache_dir, "OpenAI.list"))
if ai_content:
    openai_rules_str += f"RULE-SET,{openai_list_url},{openai_node}\n"

# Claude (PROXY)
claude_rules_str = "\n# --- Claude (PROXY) ---\n"
claude_list_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Claude/Claude.list"
_, claude_content = fetch_or_fallback(claude_list_url, os.path.join(cache_dir, "Claude.list"))
if claude_content:
    claude_rules_str += f"RULE-SET,{claude_list_url},{claude_node}\n"

# Copilot (PROXY)
copilot_rules_str = "\n# --- Copilot (PROXY) ---\n"
copilot_list_url = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Copilot/Copilot.list"
_, copilot_content = fetch_or_fallback(copilot_list_url, os.path.join(cache_dir, "Copilot.list"))
if copilot_content:
    copilot_rules_str += f"RULE-SET,{copilot_list_url},{openai_node}\n"

# 4. 获取 Johnshall 的基础规则并清理其原有的 Apple 规则（避免冲突）
j_url = "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/master/custom_shadowrocket_rules.conf"
_, j_content = fetch_or_fallback(j_url, os.path.join(cache_dir, "johnshall.conf"))

j_rules_clean = ""
if j_content:
    # 提取 [Rule] 之后的内容
    j_rule_part = j_content.split("[Rule]")[-1].split("FINAL")[0]
    # 智能过滤：剔除远程规则中关于 Apple 和 iCloud 的重复规则，防止干扰我们置顶的直连规则
    for line in j_rule_part.splitlines():
        if "apple" not in line.lower() and "icloud" not in line.lower() and line.strip():
            j_rules_clean += line + "\n"

# 国内服务 (DIRECT)
domestic_lists = {
    "Alipay": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Alipay/Alipay.list",
    "WeChat": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/WeChat/WeChat.list"
}
domestic_rules_str = "\n# --- 国内常用应用及服务 (DIRECT) ---\n"
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

# 5. 核心严格拼装顺序
final_rules = (
    apple_rules_str + 
    tonghuashun_rules_str +
    openai_rules_str + 
    claude_rules_str + 
    copilot_rules_str + 
    "\n# --- 基础代理与去广告区块 ---\n" +
    j_rules_clean +
    domestic_rules_str +
    f"\n\n# 兜底规则\nFINAL,{default_node}\n"
)

new_content = before_rules + final_rules + after_rules

# ================= 写入文件 =================
with open('custom_shadowrocket_rules.conf', 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"同步规则更新完成! 备忘录核心同步规则已置顶。更新时间: {datetime.datetime.now()}")
