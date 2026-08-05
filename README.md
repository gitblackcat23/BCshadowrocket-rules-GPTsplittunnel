# BCshadowrocket-rules-GPTsplittunnel

本项目通过 GitHub Actions 自动整合规则集，设置了个人日常使用的 Shadowrocket 参数，仅供作者个人使用。生成器会下载、校验并内联动态规则，最终配置不依赖客户端运行时再次下载第三方 `RULE-SET`。

## 生成器安全模型

- OpenAI 和 29 个国内应用动态源都会先经过格式、数量与内容校验，再把同一份已校验字节内联到最终配置；在线源异常时使用各自的 last-known-good 缓存。Claude 改用仓库内固定的 SCCR2685 主规则与原有兼容补充，并以数量、去重和 SHA-256 摘要防止静默缩减。最终校验会拒绝任何残留的运行时 `RULE-SET`。
- 独立来源采用有界并发下载，并限制为仓库声明的 HTTPS 主机，同时设置连接/读取超时、有限重试和 16 MiB 响应体上限。
- 所有缓存、OpenAI 审计产物、可选备份和正式配置在最终校验通过后批量发布；任一文件替换失败都会回滚本批次已经替换的文件。
- 本地直接运行默认仅在有效规则语义发生变化时创建时间戳备份；仅注释或日期变化不会增加备份。可用 `python update_rules.py --no-backup` 禁用备份。
- 定时更新任务使用 `--no-backup`，由 Git 历史承担 CI 版本追溯，避免仓库中的时间戳备份无限增长；既有历史备份不会被生成器自动删除。
- push 和 pull request 会运行只读 CI（单元测试和现有配置校验）；每天北京时间 08:08 的定时任务会先执行单元测试，再由 `python update_rules.py --no-backup` 生成 `custom_shadowrocket_rules.conf`，用同一脚本复验后才自动提交配置、缓存和审计产物。测试会锁定这条每日生成链路。

## Claude SCCR2685 分流策略

Claude 规则采用“固定 SCCR2685 主规则 + 原有兼容补充 + 官方条件补充”的可审计策略：

- `rules/claude/sccr2685.list` 固定保存附件中可合并的 39 条 SCCR2685 规则；独立配置里的 `FINAL,DIRECT` 不会导入，因为综合配置只能保留原有唯一 `FINAL`。
- `rules/claude/legacy-extra.list` 保存旧 Claude 区块中 SCCR2685 未逐字包含的 15 条兼容规则。另按 [Anthropic 官方网络要求](https://code.claude.com/docs/en/corporate-proxy)加入 npm/bun 安装所需的共享主机 `registry.npmjs.org`，最终 Claude 集合共 55 条且无文本重复。
- 生成器把 SCCR2685、原有兼容规则、官方补充和 Anthropic 自有 IP/ASN 全部固定到 `V3 Static Residential`，并要求它们成为 `[Rule]` 最前面的有效规则，高于 Johnshall 通用规则、`GEOIP` 和最终兜底。
- `DST-PORT,123` 是影响全设备的 NTP 端口规则。它保留 SCCR2685 的具体内容，但放在 Apple 域名直连之后，避免覆盖受保护的 Apple 时间服务；NTP 同步时间基准，并不会返回代理地区的时区。
- SCCR2685 包含 Sentry、Statsig、Intercom、Datadog 等 OpenAI 也会使用的共享基础设施。生成器要求 Claude 与 OpenAI 当前使用同一节点；若以后节点配置分离，会拒绝生成并要求先完成共享规则审计。
- Claude 不再每日下载 blackmatrix7 的三条动态列表；历史缓存仍保留作审计，但不再参与生成。固定来源内容、生成顺序、策略、SCCR2685 完整性和每日 GitHub Actions 入口均有自动化回归测试。

## 项目引用

本项目借鉴和使用了以下开源项目的代码和规则：

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) - 提供基础规则集
- [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) - 提供 OpenAI Shadowrocket 增量规则
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) - 提供 OpenAI 核心域名增量，并用于核对 SCCR2685 的 Anthropic 域名展开
- [Net.Coffee Claude Code 域名分流规则](https://ip.net.coffee/claude/site.html) - 提供 SCCR2685 的原始候选内容
- [Anthropic Claude Code 网络要求](https://code.claude.com/docs/en/corporate-proxy) - 提供当前 Claude Code 官方主机与条件依赖核对
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) - 提供国内应用动态源、Claude 历史兼容来源，并作为本地 OpenAI 兼容基线的历史来源
- [fmz200/wool_scripts](https://github.com/fmz200/wool_scripts) - 提供懂球帝广告域名、URL Rewrite 与 MITM 规则参考
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) - 提供懂球帝新旧广告入口的交叉验证

特此感谢以上项目的开发者们！

## 免责声明

- 本项目仅供个人学习和研究使用，不得用于商业或非法用途
- 使用本项目生成的规则配置时，请遵守当地法律法规
- 项目作者不对使用本项目引起的任何问题负责
- 如有侵权，请联系我删除相关内容
