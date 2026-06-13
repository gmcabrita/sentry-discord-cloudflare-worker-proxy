# Sentry → Discord Cloudflare Worker proxy

Thin Cloudflare Worker that accepts Sentry internal integration webhooks, verifies the optional Sentry signature, converts the payload to Discord embeds, and forwards it to a Discord webhook.

## Setup

### 1. Discord webhook

Discord channel → **Edit Channel** → **Integrations** → **Webhooks** → **New Webhook** → copy URL.

### 2. Cloudflare secrets

```sh
pnpm install
pnpm wrangler secret put DISCORD_WEBHOOK_RUN_GMC
pnpm wrangler secret put SENTRY_WEBHOOK_SECRET
```

Use the Discord webhook URL for `DISCORD_WEBHOOK_RUN_GMC`.

Routing uses `DISCORD_WEBHOOK_ROUTE_MAP` in `wrangler.jsonc`:

```jsonc
"vars": {
  "DISCORD_WEBHOOK_ROUTE_MAP": {
    "run-gmc": "DISCORD_WEBHOOK_RUN_GMC"
  }
}
```

Add another route later by editing the non-secret map and adding only the new secret:

```jsonc
"vars": {
  "DISCORD_WEBHOOK_ROUTE_MAP": {
    "run-gmc": "DISCORD_WEBHOOK_RUN_GMC",
    "other-project": "DISCORD_WEBHOOK_OTHER_PROJECT"
  }
}
```

```sh
pnpm wrangler secret put DISCORD_WEBHOOK_OTHER_PROJECT
```

Every Sentry project must have an explicit route.

Use the Sentry internal integration **Client Secret** for `SENTRY_WEBHOOK_SECRET`. If you do not set this secret, the Worker accepts unsigned requests.

### 3. Deploy

```sh
pnpm wrangler whoami
pnpm deploy
```

Worker health check:

```sh
curl https://<worker-name>.<account>.workers.dev/healthz
```

### 4. Sentry internal integration

Sentry org settings → **Developer Settings** → **Custom Integrations** → **Create Internal Integration**.

Recommended settings:

- Webhook URL: `https://<worker-name>.<account>.workers.dev/`
- Permissions: minimal needed for chosen events, usually project read
- Webhooks: enable issue and/or event alert notifications

Then add the integration as an action in Sentry alert rules if using alert notifications.

## Local dev

```sh
pnpm dev
```

Use a local test payload:

```sh
curl -X POST http://localhost:8787 \
  -H 'content-type: application/json' \
  -H 'sentry-hook-resource: issue' \
  -d '{"action":"created","data":{"issue":{"shortId":"API-1","title":"Test error","level":"error","project":{"slug":"api"},"permalink":"https://sentry.io/issues/1/"}}}'
```

## Test

```sh
pnpm test
pnpm typecheck
pnpm cf-typegen
```
