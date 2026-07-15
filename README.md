# BCshadowrocket-rules-GPTsplittunnel

本项目通过 GitHub Actions 自动整合规则集，设置了个人日常使用的 Shadowrocket 参数，仅供作者个人使用。生成器会下载、校验并内联动态规则，最终配置不依赖客户端运行时再次下载第三方 `RULE-SET`。

## 生成器安全模型

- OpenAI、Claude 和 29 个国内应用源都会先经过格式、数量与内容校验，再把同一份已校验字节内联到最终配置；在线源异常时使用各自的 last-known-good 缓存。最终校验会拒绝任何残留的运行时 `RULE-SET`。
- 独立来源采用有界并发下载，并限制为仓库声明的 HTTPS 主机，同时设置连接/读取超时、有限重试和 16 MiB 响应体上限。
- 所有缓存、OpenAI 审计产物、可选备份和正式配置在最终校验通过后批量发布；任一文件替换失败都会回滚本批次已经替换的文件。
- 本地直接运行默认仅在有效规则语义发生变化时创建时间戳备份；仅注释或日期变化不会增加备份。可用 `python update_rules.py --no-backup` 禁用备份。
- 定时更新任务使用 `--no-backup`，由 Git 历史承担 CI 版本追溯，避免仓库中的时间戳备份无限增长；既有历史备份不会被生成器自动删除。
- push 和 pull request 会运行只读 CI（单元测试和现有配置校验）；定时任务仍负责联网更新规则及缓存。

## OpenAI 分流策略

OpenAI 规则采用“本地宽兼容基线 + 多源增量”的保守策略，优先避免漏分流：

- 本地宽兼容基线来自审定时的 VPSDance 与 blackmatrix OpenAI 规则并集。基线固定保存在本仓库，不会因为任一上游以后删除规则而自动缩减；blackmatrix OpenAI 不再作为每日生产源或监控源。
- 每日生产增量来自 [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) 和 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)。经过格式、数量和关键内容校验后才会合并。
- 宽基线唯一明确排除 `IP-ASN,20473,no-resolve`，因为 AS20473 是范围过大的共享托管网络，并非 OpenAI 专属。其余已审定的宽规则、OpenAI 网络段和旧兼容规则继续保留。
- 生成结果写入 `rules/openai/` 供审计，并直接内联到最终配置；Shadowrocket 运行时不再从第三方下载 OpenAI `RULE-SET`，确保客户端使用的就是构建时已校验的版本。
- 每个动态来源都有独立的 last-known-good（最后已知可用）缓存。在线内容不可用或校验失败时继续使用对应缓存；只有完整配置通过最终校验后，才更新配置和缓存。

ChatGPT Voice 继续由 VPSDance 与 v2fly 的 `chatgpt.livekit.cloud`、`host.livekit.cloud`、`turn.livekit.cloud` 等 Advanced Voice/LiveKit 域名覆盖，并保留固定兼容基线中的既有规则。由于住宅节点不支持 UDP，本项目不再导入面向防火墙放行的 `chatgpt-voice.json` 动态媒体 IP，避免把 `UDP/3478` 强制送入无法转发 UDP 的节点。

[DDcat2025/openai-shadowrocket-rules](https://github.com/DDcat2025/openai-shadowrocket-rules) 仅作为转换实现参考，不是生产数据源、运行时依赖或更新链路的一部分。

## 项目引用

本项目借鉴和使用了以下开源项目的代码和规则：

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) - 提供基础规则集
- [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) - 提供 OpenAI Shadowrocket 增量规则
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) - 提供 OpenAI 核心域名增量
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) - 提供 Claude、国内应用等既有规则，并作为本地 OpenAI 兼容基线的历史来源

特此感谢以上项目的开发者们！

## 免责声明

- 本项目仅供个人学习和研究使用，不得用于商业或非法用途
- 使用本项目生成的规则配置时，请遵守当地法律法规
- 项目作者不对使用本项目引起的任何问题负责
- 如有侵权，请联系我删除相关内容
