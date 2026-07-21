# NTIP API contracts

`openapi/ntip-v1.yaml` is the canonical v0.2 management API contract. The
dashboard and Zig HTTP implementation must conform to it; v0.2 does not promise
this surface as a general-purpose external automation API.

`openapi/ntip-bootstrap-v1.yaml` is the separate, cookie-independent public
Node bootstrap contract. It covers only generated installer scripts, strict
invitation redemption, and NGINX-owned immutable release assets. It must never
inherit the management session or same-origin mutation model.

Generation produces JSON, TypeScript schemas, and `openapi-fetch` clients for
both documents. `src/generated/openapi.json` remains the byte-for-byte artifact
embedded by `ntip-api` for `/api/v1/openapi.json`; the public bootstrap JSON is
generated separately as `src/generated/bootstrap-openapi.json`. YAML parsing is
not part of either production service path.

Do not edit anything under `src/generated` directly.
Regenerate them from the repository root:

```sh
bun run contracts:generate
```

The contract validation includes OpenAPI 3.1 validation plus NTIP-specific
security and compatibility rules. CI should run:

```sh
bun install --frozen-lockfile
bun run contracts:validate
bun run contracts:check
bun run typecheck
bun run test
```

`contracts:check` is non-mutating and fails when generated artifacts differ
from the canonical YAML.
