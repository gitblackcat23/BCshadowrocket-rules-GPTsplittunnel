# BCshadowrocket-rules-GPTsplittunnel

本项目通过 GitHub Actions 自动整合规则集，设置了个人日常使用的 Shadowrocket 参数，仅供作者个人使用。除 OpenAI 分流增强外，原有基础规则、Claude 分流和国内应用规则的生成方式保持不变。

## OpenAI 分流策略

OpenAI 规则采用“本地宽兼容基线 + 多源增量”的保守策略，优先避免漏分流：

- 本地宽兼容基线来自审定时的 VPSDance 与 blackmatrix OpenAI 规则并集。基线固定保存在本仓库，不会因为任一上游以后删除规则而自动缩减；blackmatrix OpenAI 不再作为每日生产源或监控源。
- 每日生产增量来自 [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules)、[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) 和 OpenAI 官方 [`chatgpt-voice.json`](https://openai.com/chatgpt-voice.json)。经过格式、数量和关键内容校验后才会合并。
- 宽基线唯一明确排除 `IP-ASN,20473,no-resolve`，因为 AS20473 是范围过大的共享托管网络，并非 OpenAI 专属。其余已审定的宽规则、OpenAI 网络段和旧兼容规则继续保留。
- 生成结果写入 `rules/openai/` 供审计，并直接内联到最终配置；Shadowrocket 运行时不再从第三方下载 OpenAI `RULE-SET`，确保客户端使用的就是构建时已校验的版本。
- 每个动态来源都有独立的 last-known-good（最后已知可用）缓存。在线内容不可用或校验失败时继续使用对应缓存；只有完整配置通过最终校验后，才更新配置和缓存。

ChatGPT Voice 的媒体 IP 由 OpenAI 官方 JSON 动态生成。Voice 首选 `UDP/3478`，不可用时可回退到 `TCP/443`；所选住宅节点及代理协议仍须支持 UDP 转发，否则仅增加规则不能保证最佳语音体验。

[DDcat2025/openai-shadowrocket-rules](https://github.com/DDcat2025/openai-shadowrocket-rules) 仅作为转换实现参考，不是生产数据源、运行时依赖或更新链路的一部分。

## 项目引用

本项目借鉴和使用了以下开源项目的代码和规则：

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) - 提供基础规则集
- [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) - 提供 OpenAI Shadowrocket 增量规则
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) - 提供 OpenAI 核心域名增量
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) - 提供 Claude、国内应用等既有规则，并作为本地 OpenAI 兼容基线的历史来源
- [OpenAI ChatGPT Voice IP ranges](https://openai.com/chatgpt-voice.json) - 提供 Voice 媒体服务器动态 IP 前缀

特此感谢以上项目的开发者们！

## 免责声明

- 本项目仅供个人学习和研究使用，不得用于商业或非法用途
- 使用本项目生成的规则配置时，请遵守当地法律法规
- 项目作者不对使用本项目引起的任何问题负责
- 如有侵权，请联系我删除相关内容
