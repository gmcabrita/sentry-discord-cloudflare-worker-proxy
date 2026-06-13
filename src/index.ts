export interface Env extends CloudflareBindings {
  SENTRY_WEBHOOK_SECRET?: string;
  [key: string]: unknown;
}

type JsonRecord = Record<string, unknown>;

type Severity = "fatal" | "error" | "warning" | "info" | "debug" | "unknown";

interface DiscordField {
  name: string;
  value: string;
  inline?: boolean;
}

interface DiscordEmbed {
  title: string;
  description?: string;
  url?: string;
  color: number;
  fields: DiscordField[];
  timestamp?: string;
  footer?: {
    text: string;
  };
}

interface DiscordWebhookPayload {
  username: string;
  content: string;
  embeds: DiscordEmbed[];
  allowed_mentions: {
    parse: [];
  };
}

interface SentryNotification {
  action: string | undefined;
  resource: string | undefined;
  title: string;
  description: string | undefined;
  url: string | undefined;
  shortId: string | undefined;
  project: string | undefined;
  environment: string | undefined;
  level: Severity;
  status: string | undefined;
  rule: string | undefined;
  culprit: string | undefined;
  count: string | undefined;
  users: string | undefined;
  timestamp: string | undefined;
}

type DiscordRouteMap =
  | {
      kind: "valid";
      routes: ReadonlyMap<string, string>;
    }
  | {
      kind: "invalid";
    };

const DISCORD_SUCCESS_STATUSES = new Set([200, 204]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/healthz") {
      return jsonResponse({ ok: true });
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "method_not_allowed" }, 405);
    }

    const body = await request.text();

    if (env.SENTRY_WEBHOOK_SECRET) {
      const signature = request.headers.get("sentry-hook-signature");

      if (!signature) {
        return jsonResponse({ error: "missing_sentry_signature" }, 401);
      }

      const isValid = await isValidSentrySignature(body, env.SENTRY_WEBHOOK_SECRET, signature);

      if (!isValid) {
        return jsonResponse({ error: "invalid_sentry_signature" }, 401);
      }
    }

    const parsed = parseJson(body);

    if (parsed === undefined) {
      return jsonResponse({ error: "invalid_json" }, 400);
    }

    const routeMap = parseDiscordRouteMap(env.DISCORD_WEBHOOK_ROUTE_MAP);

    if (routeMap.kind === "invalid") {
      return jsonResponse({ error: "invalid_discord_webhook_route_map" }, 500);
    }

    const discordWebhookUrl = selectDiscordWebhookUrl(parsed, routeMap, env);

    if (!discordWebhookUrl) {
      return jsonResponse({ error: "missing_discord_webhook_route" }, 500);
    }

    const discordPayload = sentryToDiscord(parsed, request.headers.get("sentry-hook-resource"));
    const discordResponse = await fetch(discordWebhookUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(discordPayload)
    });

    if (!DISCORD_SUCCESS_STATUSES.has(discordResponse.status)) {
      return jsonResponse(
        {
          error: "discord_webhook_failed",
          status: discordResponse.status,
          retryAfter: discordResponse.headers.get("retry-after")
        },
        502
      );
    }

    return jsonResponse({ ok: true }, 202);
  }
};

export function sentryToDiscord(payload: unknown, resourceHeader: string | null = null): DiscordWebhookPayload {
  const notification = extractSentryNotification(payload, resourceHeader);
  const fields = buildFields(notification);
  const embed: DiscordEmbed = {
    title: truncate(notification.title, 256),
    color: colorFor(notification.level, notification.action),
    fields,
    footer: {
      text: "Sentry"
    }
  };

  if (notification.description) {
    embed.description = truncate(notification.description, 4096);
  }

  if (notification.url) {
    embed.url = notification.url;
  }

  if (notification.timestamp) {
    embed.timestamp = notification.timestamp;
  }

  return {
    username: "Sentry",
    content: truncate(buildContent(notification), 2000),
    embeds: [embed],
    allowed_mentions: {
      parse: []
    }
  };
}

export async function isValidSentrySignature(
  body: string,
  secret: string,
  signatureHeader: string
): Promise<boolean> {
  const expected = await hmacSha256Hex(secret, body);
  const actual = normalizeSignature(signatureHeader);

  return constantTimeHexEqual(actual, expected);
}

export function parseDiscordRouteMap(value: unknown): DiscordRouteMap {
  if (value === undefined) {
    return {
      kind: "valid",
      routes: new Map()
    };
  }

  const parsed = typeof value === "string" ? parseJson(value) : value;

  if (!isRecord(parsed)) {
    return {
      kind: "invalid"
    };
  }

  const routes = new Map<string, string>();

  for (const [project, secretName] of Object.entries(parsed)) {
    const normalizedProject = normalizeRouteKey(project);

    if (!normalizedProject || typeof secretName !== "string" || !isDiscordWebhookSecretName(secretName)) {
      return {
        kind: "invalid"
      };
    }

    routes.set(normalizedProject, secretName);
  }

  return {
    kind: "valid",
    routes
  };
}

export function selectDiscordWebhookUrl(
  payload: unknown,
  routeMap: DiscordRouteMap,
  env: Record<string, unknown>
): string | undefined {
  if (routeMap.kind === "invalid") {
    return undefined;
  }

  const notification = extractSentryNotification(payload, null);
  const projectSecretName = notification.project
    ? routeMap.routes.get(normalizeRouteKey(notification.project))
    : undefined;
  return secretValue(env, projectSecretName);
}

function extractSentryNotification(payload: unknown, resourceHeader: string | null): SentryNotification {
  const root = isRecord(payload) ? payload : undefined;
  const data = root ? getRecord(root, "data") : undefined;
  const issue = data ? getRecord(data, "issue") : undefined;
  const event = data ? getRecord(data, "event") : undefined;
  const primary = issue ?? event ?? data ?? root;
  const action = root ? getString(root, "action") : undefined;
  const resource = resourceHeader ?? (root ? getString(root, "resource") : undefined);
  const title =
    (primary ? getString(primary, "title") : undefined) ??
    (primary ? getString(primary, "message") : undefined) ??
    (primary ? getString(primary, "value") : undefined) ??
    (issue ? metadataValue(issue) : undefined) ??
    "Sentry notification";
  const description =
    (primary ? getString(primary, "culprit") : undefined) ??
    (event ? getString(event, "message") : undefined) ??
    (issue ? metadataValue(issue) : undefined);
  const url = firstValidUrl([
    primary ? getString(primary, "permalink") : undefined,
    primary ? getString(primary, "web_url") : undefined,
    primary ? getString(primary, "issue_url") : undefined,
    primary ? getString(primary, "url") : undefined,
    event ? getString(event, "web_url") : undefined,
    issue ? getString(issue, "permalink") : undefined
  ]);
  const project =
    (primary ? getNestedString(primary, ["project", "slug"]) : undefined) ??
    (primary ? getNestedString(primary, ["project", "name"]) : undefined) ??
    (primary ? getString(primary, "project") : undefined) ??
    (event ? getString(event, "project_slug") : undefined);
  const environment =
    (primary ? getString(primary, "environment") : undefined) ??
    (event ? getTagValue(event, "environment") : undefined) ??
    (issue ? getTagValue(issue, "environment") : undefined);
  const level = parseSeverity(
    (primary ? getString(primary, "level") : undefined) ??
      (event ? getTagValue(event, "level") : undefined) ??
      (issue ? getTagValue(issue, "level") : undefined)
  );

  return {
    action,
    resource,
    title,
    description: description === title ? undefined : description,
    url,
    shortId:
      (primary ? getString(primary, "shortId") : undefined) ??
      (primary ? getString(primary, "short_id") : undefined) ??
      (primary ? getString(primary, "issue") : undefined) ??
      (primary ? getString(primary, "groupID") : undefined),
    project,
    environment,
    level,
    status: primary ? getString(primary, "status") : undefined,
    rule: data ? getString(data, "triggered_rule") ?? getString(data, "triggeredRule") : undefined,
    culprit: primary ? getString(primary, "culprit") : undefined,
    count: primary ? getStringish(primary, "count") ?? getStringish(primary, "timesSeen") : undefined,
    users: primary ? getStringish(primary, "userCount") ?? getStringish(primary, "user_count") : undefined,
    timestamp:
      (primary ? getString(primary, "lastSeen") : undefined) ??
      (primary ? getString(primary, "timestamp") : undefined) ??
      (event ? getString(event, "datetime") : undefined)
  };
}

function buildContent(notification: SentryNotification): string {
  const emoji = emojiFor(notification.level, notification.action);
  const action = notification.action ? ` ${notification.action}` : "";
  const resource = notification.resource ? ` ${notification.resource}` : "";
  const id = notification.shortId ? `${notification.shortId}: ` : "";

  return `${emoji} Sentry${resource}${action}: ${id}${notification.title}`;
}

function buildFields(notification: SentryNotification): DiscordField[] {
  const fields: DiscordField[] = [];

  addField(fields, "Project", notification.project, true);
  addField(fields, "Environment", notification.environment, true);
  addField(fields, "Level", notification.level === "unknown" ? undefined : notification.level, true);
  addField(fields, "Status", notification.status, true);
  addField(fields, "Rule", notification.rule, false);
  addField(fields, "Culprit", notification.culprit, false);
  addField(fields, "Events", notification.count, true);
  addField(fields, "Users", notification.users, true);

  return fields;
}

function addField(fields: DiscordField[], name: string, value: string | undefined, inline: boolean): void {
  if (!value) {
    return;
  }

  fields.push({
    name: truncate(name, 256),
    value: truncate(value, 1024),
    inline
  });
}

function colorFor(level: Severity, action: string | undefined): number {
  if (action === "resolved") {
    return 0x2f9e44;
  }

  switch (level) {
    case "fatal":
    case "error":
      return 0xe03131;
    case "warning":
      return 0xf08c00;
    case "info":
      return 0x1971c2;
    case "debug":
      return 0x7048e8;
    case "unknown":
      return 0x868e96;
  }
}

function emojiFor(level: Severity, action: string | undefined): string {
  if (action === "resolved") {
    return "✅";
  }

  switch (level) {
    case "fatal":
    case "error":
      return "🚨";
    case "warning":
      return "⚠️";
    case "info":
      return "ℹ️";
    case "debug":
      return "🔎";
    case "unknown":
      return "📣";
  }
}

function parseSeverity(value: string | undefined): Severity {
  switch (value) {
    case "fatal":
    case "error":
    case "warning":
    case "info":
    case "debug":
      return value;
    default:
      return "unknown";
  }
}

function parseJson(body: string): unknown | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    return parsed;
  } catch {
    return undefined;
  }
}

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8"
    }
  });
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

function getRecord(record: JsonRecord, key: string): JsonRecord | undefined {
  const value = record[key];

  return isRecord(value) ? value : undefined;
}

function getString(record: JsonRecord, key: string): string | undefined {
  const value = record[key];

  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function getStringish(record: JsonRecord, key: string): string | undefined {
  const value = record[key];

  if (typeof value === "string" && value.length > 0) {
    return value;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return undefined;
}

function getNestedString(record: JsonRecord, path: readonly string[]): string | undefined {
  let current: JsonRecord | undefined = record;

  for (const segment of path.slice(0, -1)) {
    if (!current) {
      return undefined;
    }

    current = getRecord(current, segment);
  }

  const last = path[path.length - 1];

  return current && last ? getString(current, last) : undefined;
}

function metadataValue(record: JsonRecord): string | undefined {
  const metadata = getRecord(record, "metadata");

  if (!metadata) {
    return undefined;
  }

  return getString(metadata, "value") ?? getString(metadata, "title") ?? getString(metadata, "type");
}

function getTagValue(record: JsonRecord, key: string): string | undefined {
  const tags = record.tags;

  if (isRecord(tags)) {
    return getStringish(tags, key);
  }

  if (!isUnknownArray(tags)) {
    return undefined;
  }

  for (const tag of tags) {
    if (isUnknownArray(tag)) {
      const tagKey = tag[0];
      const tagValue = tag[1];

      if (tagKey === key && (typeof tagValue === "string" || typeof tagValue === "number")) {
        return String(tagValue);
      }
    }

    if (isRecord(tag)) {
      const tagKey = getString(tag, "key") ?? getString(tag, "name");
      const tagValue = getStringish(tag, "value");

      if (tagKey === key && tagValue) {
        return tagValue;
      }
    }
  }

  return undefined;
}

function firstValidUrl(values: readonly (string | undefined)[]): string | undefined {
  for (const value of values) {
    if (value && isHttpUrl(value)) {
      return value;
    }
  }

  return undefined;
}

function secretValue(env: Record<string, unknown>, secretName: string | undefined): string | undefined {
  if (!secretName) {
    return undefined;
  }

  const value = env[secretName];

  return typeof value === "string" && isHttpUrl(value) ? value : undefined;
}

function normalizeRouteKey(value: string): string {
  return value.trim().toLowerCase();
}

function isDiscordWebhookSecretName(value: string): boolean {
  return /^DISCORD_WEBHOOK_[A-Z0-9_]+$/.test(value);
}

function isHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function truncate(value: string, limit: number): string {
  if (value.length <= limit) {
    return value;
  }

  return `${value.slice(0, Math.max(0, limit - 1))}…`;
}

async function hmacSha256Hex(secret: string, body: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );
  const digest = await crypto.subtle.sign("HMAC", key, encoder.encode(body));

  return bytesToHex(new Uint8Array(digest));
}

function normalizeSignature(signature: string): string {
  const value = signature.trim().toLowerCase();

  return value.startsWith("sha256=") ? value.slice("sha256=".length) : value;
}

function constantTimeHexEqual(left: string, right: string): boolean {
  if (!isHex(left) || !isHex(right) || left.length !== right.length) {
    return false;
  }

  let diff = 0;

  for (let index = 0; index < left.length; index += 1) {
    diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return diff === 0;
}

function isHex(value: string): boolean {
  return /^[\da-f]+$/.test(value);
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";

  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }

  return hex;
}
