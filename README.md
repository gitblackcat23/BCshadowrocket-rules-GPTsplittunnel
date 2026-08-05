# BCshadowrocket-rules-GPTsplittunnel

本项目通过 GitHub Actions 自动整合规则集，设置了个人日常使用的 Shadowrocket 参数，仅供作者个人使用。

## OpenAI 双源每日生成策略

- 每日抓取 [blackmatrix7 OpenAI Shadowrocket 规则](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Shadowrocket/OpenAI)和 [MetaCubeX OpenAI geosite JSON](https://github.com/MetaCubeX/meta-rules-dat/blob/sing/geo/geosite/openai.json)，经严格解析、范围审计、规范化和去重后生成当天规则。
- 两个来源分别保存 last-known-good 缓存；删库、断网、错误页、异常缩减、格式漂移或策略冲突时，按来源回退缓存并继续生成当天配置。
- 固定兼容底座与原有节点策略必须完整保留；共享 Vultr `IP-ASN,20473` 固定从合并结果剔除，公共后缀和未经审核的高影响规则也会被拒绝。
- 动态候选会与 Apple/iCloud、Johnshall DIRECT/Reject 和国内 DIRECT 快照做冲突审计。每天 08:08 构建，08:10 使用同一套严格验证器监控关键在线源。

## 项目引用

本项目借鉴和使用了以下开源项目的代码和规则：

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) - 提供基础规则集
- [blackmatrix7/ios_rule_script OpenAI](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Shadowrocket/OpenAI) - 提供每日 OpenAI Shadowrocket 动态来源
- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat/blob/sing/geo/geosite/openai.json) - 提供每日 OpenAI geosite JSON 动态来源
- [Public Suffix List](https://publicsuffix.org/) - 提供动态 `DOMAIN-SUFFIX` 范围安全校验依据
- [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules)与 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) - 提供现有 OpenAI 固定兼容底座的历史审计依据
- [Net.Coffee Claude Code 域名分流规则](https://ip.net.coffee/claude/site.html) - 提供 SCCR2685 的原始候选内容
- [Anthropic Claude Code 网络要求](https://code.claude.com/docs/en/corporate-proxy)
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
- [fmz200/wool_scripts](https://github.com/fmz200/wool_scripts)
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)

特此感谢以上项目的开发者们！

## 免责声明

- 本项目仅供个人学习和研究使用，不得用于商业或非法用途
- 使用本项目生成的规则配置时，请遵守当地法律法规
- 项目作者不对使用本项目引起的任何问题负责
- 如有侵权，请联系我删除相关内容
