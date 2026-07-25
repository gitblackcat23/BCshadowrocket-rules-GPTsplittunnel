# BCshadowrocket-rules-GPTsplittunnel

本项目通过 GitHub Actions 自动整合规则集，设置了个人日常使用的 Shadowrocket 参数，仅供作者个人使用。生成器会下载、校验并内联动态规则，最终配置不依赖客户端运行时再次下载第三方 `RULE-SET`。

## 生成器安全模型

- OpenAI、Claude 和 29 个国内应用源都会先经过格式、数量与内容校验，再把同一份已校验字节内联到最终配置；在线源异常时使用各自的 last-known-good 缓存。最终校验会拒绝任何残留的运行时 `RULE-SET`。
- 独立来源采用有界并发下载，并限制为仓库声明的 HTTPS 主机，同时设置连接/读取超时、有限重试和 16 MiB 响应体上限。
- 所有缓存、OpenAI 审计产物、可选备份和正式配置在最终校验通过后批量发布；任一文件替换失败都会回滚本批次已经替换的文件。
- 本地直接运行默认仅在有效规则语义发生变化时创建时间戳备份；仅注释或日期变化不会增加备份。可用 `python update_rules.py --no-backup` 禁用备份。
- 定时更新任务使用 `--no-backup`，由 Git 历史承担 CI 版本追溯，避免仓库中的时间戳备份无限增长；既有历史备份不会被生成器自动删除。
- push 和 pull request 会运行只读 CI（单元测试和现有配置校验）；定时任务仍负责联网更新规则及缓存。


## 项目引用

本项目借鉴和使用了以下开源项目的代码和规则：

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever) - 提供基础规则集
- [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) - 提供 OpenAI Shadowrocket 增量规则
- [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) - 提供 OpenAI 核心域名增量
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) - 提供 Claude、国内应用等既有规则，并作为本地 OpenAI 兼容基线的历史来源
- [fmz200/wool_scripts](https://github.com/fmz200/wool_scripts) - 提供懂球帝广告域名、URL Rewrite 与 MITM 规则参考
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) - 提供懂球帝新旧广告入口的交叉验证

特此感谢以上项目的开发者们！

## 免责声明

- 本项目仅供个人学习和研究使用，不得用于商业或非法用途
- 使用本项目生成的规则配置时，请遵守当地法律法规
- 项目作者不对使用本项目引起的任何问题负责
- 如有侵权，请联系我删除相关内容
