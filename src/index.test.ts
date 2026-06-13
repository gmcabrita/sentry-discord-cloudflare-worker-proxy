import { describe, expect, it } from "vitest";
import { isValidSentrySignature, parseDiscordRouteMap, selectDiscordWebhookUrl, sentryToDiscord } from "./index";

describe("sentryToDiscord", () => {
  it("maps issue webhooks to Discord embeds", () => {
    const payload = {
      action: "created",
      data: {
        issue: {
          shortId: "API-123",
          title: "TypeError: failed to fetch",
          culprit: "GET /api/items",
          permalink: "https://example.sentry.io/issues/123/",
          project: {
            slug: "api"
          },
          level: "error",
          status: "unresolved",
          count: 42,
          userCount: 7,
          lastSeen: "2026-06-13T08:00:00Z"
        }
      }
    };

    const discord = sentryToDiscord(payload, "issue");

    expect(discord.content).toBe("");
    expect(discord.embeds[0]?.title).toBe("TypeError");
    expect(discord.embeds[0]?.description).toBe("failed to fetch\n\n**API-123 • <t:1781337600:f>**");
    expect(discord.embeds[0]?.url).toBe("https://example.sentry.io/issues/123/");
    expect(discord.embeds[0]?.color).toBe(0xe74c3c);
    expect(discord.embeds[0]?.fields).toEqual([]);
  });

  it("maps event alert webhooks", () => {
    const payload = {
      action: "triggered",
      data: {
        triggered_rule: "High error rate",
        event: {
          title: "Unhandled RuntimeError",
          message: "Cannot read properties of undefined",
          web_url: "https://example.sentry.io/issues/456/events/abc/",
          project_slug: "frontend",
          level: "warning",
          environment: "production",
          timestamp: "2026-06-13T08:15:00Z"
        }
      }
    };

    const discord = sentryToDiscord(payload, "event_alert");

    expect(discord.content).toBe("");
    expect(discord.embeds[0]?.title).toBe("Unhandled RuntimeError");
    expect(discord.embeds[0]?.description).toBe(
      "Cannot read properties of undefined\n\n**frontend via High error rate • <t:1781338500:f>**"
    );
    expect(discord.embeds[0]?.color).toBe(0xf1c40f);
    expect(discord.embeds[0]?.fields).toEqual([]);
  });
});

describe("Discord routing", () => {
  it("routes by project to configured secret name", () => {
    const routeMap = parseDiscordRouteMap({
      "run-gmc": "DISCORD_WEBHOOK_RUN_GMC"
    });
    const payload = {
      data: {
        issue: {
          project: {
            slug: "run-gmc"
          },
          title: "Test"
        }
      }
    };

    expect(
      selectDiscordWebhookUrl(payload, routeMap, {
        DISCORD_WEBHOOK_RUN_GMC: "https://discord.com/api/webhooks/run-gmc"
      })
    ).toBe("https://discord.com/api/webhooks/run-gmc");
  });

  it("requires a route for the Sentry project", () => {
    const routeMap = parseDiscordRouteMap({
      "run-gmc": "DISCORD_WEBHOOK_RUN_GMC"
    });
    const payload = {
      data: {
        issue: {
          project: {
            slug: "unknown"
          },
          title: "Test"
        }
      }
    };

    expect(
      selectDiscordWebhookUrl(payload, routeMap, {
        DISCORD_WEBHOOK_RUN_GMC: "https://discord.com/api/webhooks/run-gmc"
      })
    ).toBeUndefined();
  });

  it("parses string route maps", () => {
    const routeMap = parseDiscordRouteMap('{"run-gmc":"DISCORD_WEBHOOK_RUN_GMC"}');

    expect(routeMap.kind).toBe("valid");
  });

  it("rejects invalid secret names", () => {
    const routeMap = parseDiscordRouteMap({
      "run-gmc": "WRONG_SECRET"
    });

    expect(routeMap.kind).toBe("invalid");
  });

  it("ignores invalid route URLs", () => {
    const routeMap = parseDiscordRouteMap({
      "run-gmc": "DISCORD_WEBHOOK_RUN_GMC"
    });
    const payload = {
      data: {
        issue: {
          project: {
            slug: "run-gmc"
          },
          title: "Test"
        }
      }
    };

    expect(
      selectDiscordWebhookUrl(payload, routeMap, {
        DISCORD_WEBHOOK_RUN_GMC: "not a URL"
      })
    ).toBeUndefined();
  });
});

describe("isValidSentrySignature", () => {
  it("validates HMAC-SHA256 signatures", async () => {
    const valid = await isValidSentrySignature(
      "The quick brown fox jumps over the lazy dog",
      "key",
      "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );

    expect(valid).toBe(true);
  });

  it("rejects invalid signatures", async () => {
    const valid = await isValidSentrySignature("body", "secret", "sha256=bad");

    expect(valid).toBe(false);
  });
});
