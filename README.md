---
created: 2026-05-18T00:17:31Z
branch: main
author: monorepo-split
status: active
split-from-monorepo-at: b3ccd5c7
split-from-monorepo-tag: pre-split-v0.4.0
archived-monorepo: https://github.com/CitrateNetwork/citrate-monorepo-archive
agentile-archive: https://github.com/CitrateNetwork/citrate-agentile-archive
---

# citrate-sdk-js

Canonical TypeScript SDK for Citrate Network (@citratelabs/sdk)

## Repository context

This repo was split from the **Citrate monorepo** on 2026-05-18. For the full history of decisions, sprints, audits, remediations, and ADRs that led to the split, see:

- **Monorepo archive**: https://github.com/CitrateNetwork/citrate-monorepo-archive — pre-split source + history (frozen)
- **Agentile archive**: https://github.com/CitrateNetwork/citrate-agentile-archive — methodology corpus (rules, planset, sprints, audits)

The source paths inside the pre-split monorepo were:

```
--path citrate_v0.01.1/sdks/javascript/citrate-js/ --path-rename citrate_v0.01.1/sdks/javascript/citrate-js/:
```

## Releases

This repo versions **independently** from other CitrateNetwork repos. See GitHub Releases for tagged versions.

## Contributing

This repo inherits the operating rules from `CitrateNetwork/citrate-agentile-archive/rules/CORE_RULES.md`. The Agentile framework's 13 non-negotiable rules apply uniformly across all CitrateNetwork repos.

## License

Inherits from the monorepo. See [`LICENSE`](LICENSE) if present, or the [monorepo archive](https://github.com/CitrateNetwork/citrate-monorepo-archive/blob/main/LICENSE).
## Open source and access

This repository is public. Citrate open sources the whole chain and application layer before mainnet, in January 2027; until then most of the core is access-by-request, as a security practice, not secrecy. Approved contributors receive privileged access to every repository except the private repos of clients and employees. Request access at [citrate.ai/contact](https://citrate.ai/contact) or email `hello@citrate.ai`. Full policy: <https://docs.citrate.ai/start/open-source>.
