# Project Working Rules

These rules apply to every change in this repository.

## Approval and GitHub handoff

- After modifying the repository, proactively report whether changes are uncommitted and ask the user whether to commit and push them to GitHub.
- Never commit or push without the user's explicit approval.
- For new routing or ad-blocking candidates found through research, present the proposed rules, evidence, expected benefit, and compatibility risk before editing; wait for the user's approval.

## Regression safety

- Preserve unrelated user work and keep every change narrowly scoped.
- Before handoff, inspect the complete diff, run `git diff --check`, run the full unit-test suite, validate the generated Shadowrocket configuration, and confirm that generated output changed only as intended.
- Treat a generated configuration as part of the product: verify rule syntax, section placement, deduplication, policy, MITM hostnames, and preservation across generator reruns.
- If a requested change could alter existing routing behavior outside its stated scope, stop and obtain explicit approval before proceeding.

## Protected standalone routing

- Standalone routing for iCloud/Apple, ChatGPT/OpenAI, and Claude/Anthropic is protected.
- Without explicit, specific permission, never delete, reduce, rewrite, reorder, repolicy, refactor, or otherwise modify those rules, their generator inputs, or their validation coverage.
- Apply the same protection to other services that the repository intentionally keeps as standalone routing sections, including Codex and GitHub Copilot where present.
- If another change overlaps or conflicts with a protected section, leave it unchanged and ask the user how to proceed.
