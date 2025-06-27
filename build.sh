#!/bin/bash

# 脚本出错时立即退出
set -e

echo "🚀 开始构建规则..."

# -----------------
# 1. 定义规则源和目标路径
# -----------------
# 直连规则列表
DIRECT_LISTS=(
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Apple/Apple.list"
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaMax/ChinaMax_No_IPv6.list"
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Lan/Lan.list"
)

# 代理规则列表
PROXY_LISTS=(
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list"
)

# 拒绝/广告规则列表
REJECT_LIST="https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/master/Johnshall_ADBlock_File_For_Shadowrocket.conf"

# 本地存放目录
SOURCE_DIR="./source"
DIRECT_DIR="$SOURCE_DIR/direct"
PROXY_DIR="$SOURCE_DIR/proxy"
REJECT_DIR="$SOURCE_DIR/reject"
FINAL_RULES_FILE="BCshadowrocket.conf"

# 创建目录
mkdir -p $DIRECT_DIR $PROXY_DIR $REJECT_DIR

# -----------------
# 2. 下载所有规则列表
# -----------------
echo "📥 正在下载规则列表..."

# 下载直连列表
for url in "${DIRECT_LISTS[@]}"; do
    filename=$(basename "$url")
    curl -L --connect-timeout 10 --retry 3 -o "$DIRECT_DIR/$filename" "$url"
    # 检查文件是否下载成功且非空
    if [ ! -s "$DIRECT_DIR/$filename" ]; then
        echo "::error::下载失败或文件为空: $url"
        exit 1
    fi
done

# 下载代理列表
for url in "${PROXY_LISTS[@]}"; do
    filename=$(basename "$url")
    curl -L --connect-timeout 10 --retry 3 -o "$PROXY_DIR/$filename" "$url"
    if [ ! -s "$PROXY_DIR/$filename" ]; then
        echo "::error::下载失败或文件为空: $url"
        exit 1
    fi
done

# 下载广告列表
curl -L --connect-timeout 10 --retry 3 -o "$REJECT_DIR/ADBlock.list" "$REJECT_LIST"
if [ ! -s "$REJECT_DIR/ADBlock.list" ]; then
    echo "::error::下载失败或文件为空: $REJECT_LIST"
    exit 1
fi

echo "✅ 所有规则列表下载完成。"

# -----------------
# 3. 合并规则到最终文件
# -----------------
echo "🛠️ 正在合并规则..."

# 创建一个临时文件来存放所有规则
TEMP_RULES=$(mktemp)

# 处理直连规则
echo -e "\n# DIRECT Rules" >> $TEMP_RULES
for file in $DIRECT_DIR/*.list; do
    # awk 在每一行后面添加 ",DIRECT"，并处理CRLF换行符
    awk 'NF > 0 {print $0 ",DIRECT"}' "$file" | sed 's/\r$//' >> $TEMP_RULES
done

# 处理代理规则
echo -e "\n# PROXY Rules" >> $TEMP_RULES
for file in $PROXY_DIR/*.list; do
    # awk 在每一行后面添加 ",V3 Static Residential"
    awk 'NF > 0 {print $0 ",V3 Static Residential"}' "$file" | sed 's/\r$//' >> $TEMP_RULES
done

# 处理广告/拒绝规则 (从Johnshall的文件中提取[Rule]部分)
echo -e "\n# REJECT Rules (from Johnshall)" >> $TEMP_RULES
# 使用awk提取[Rule]和下一个[]之间的内容
awk '/\[Rule\]/{f=1;next} /\[/{f=0} f' "$REJECT_DIR/ADBlock.list" | sed 's/\r$//' >> $TEMP_RULES

echo "✅ 规则合并完成。"

# -----------------
# 4. 生成最终的配置文件
# -----------------
echo "📝 正在生成最终配置文件: $FINAL_RULES_FILE"

# 读取模板，替换占位符
# 使用 mktemp 创建临时文件以避免特殊字符问题
RULES_CONTENT=$(cat $TEMP_RULES)
BUILD_TIME=$(date -u +"%Y-%m-%d %H:%M:%S")

# 使用 sed 进行替换
sed -e "/# {{RULES_CONTENT}}/r $TEMP_RULES" -e "/# {{RULES_CONTENT}}/d" "template.conf" > temp_conf
sed "s/{{BUILD_TIME}}/$BUILD_TIME/g" temp_conf > $FINAL_RULES_FILE

# 清理临时文件
rm $TEMP_RULES temp_conf

echo "🎉 构建成功！"
