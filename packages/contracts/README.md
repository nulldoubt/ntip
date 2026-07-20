# NTIP API contracts

`openapi/ntip-v1.yaml` is the canonical v0.2 management API contract. The
dashboard and Zig HTTP implementation must conform to it; v0.2 does not promise
this surface as a general-purpose external automation API.

Generation also produces `src/generated/openapi.json`, the byte-for-byte
artifact embedded by `ntip-api` for `/api/v1/openapi.json`. YAML parsing is not
part of the production service.

Do not edit `src/generated/schema.ts` or `src/generated/client.ts` directly.
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
