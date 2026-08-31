import {
  CreateMcpServerRequestSchema,
  deriveMcpServerAuthType,
  ServerParameters,
} from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import {
  buildAuthorizationHeaderValue,
  buildHttpTransportHeaders,
} from "./auth-headers";

// Helper to create minimal ServerParameters
function makeServer(
  overrides: Partial<ServerParameters> = {},
): ServerParameters {
  return {
    uuid: "11111111-1111-1111-1111-111111111111",
    name: "test-server",
    description: "",
    type: "STREAMABLE_HTTP",
    created_at: new Date().toISOString(),
    status: "active",
    stderr: "inherit" as const,
    url: "http://example.com/mcp",
    headers: {},
    ...overrides,
  };
}

describe("buildAuthorizationHeaderValue", () => {
  it("encodes Basic credentials as base64 of user:password", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BASIC",
        basic_username: "alice",
        basic_password: "s3cret",
      }),
    );

    // base64("alice:s3cret")
    expect(value).toBe("Basic YWxpY2U6czNjcmV0");
  });

  it("encodes non-ASCII Basic credentials as UTF-8, not latin-1", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BASIC",
        basic_username: "иван",
        basic_password: "пароль123",
      }),
    );

    // base64(utf8("иван:пароль123")) — a latin-1 encoding would either
    // throw or produce a different, unusable string.
    expect(value).toBe("Basic 0LjQstCw0L060L/QsNGA0L7Qu9GMMTIz");
  });

  it("allows an empty Basic password", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BASIC",
        basic_username: "bob",
        basic_password: "",
      }),
    );

    // base64("bob:") — RFC 7617 permits an empty password
    expect(value).toBe("Basic Ym9iOg==");
  });

  it("returns undefined for BASIC without a username", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BASIC",
        basic_username: "",
        basic_password: "s3cret",
      }),
    );

    expect(value).toBeUndefined();
  });

  it("returns a Bearer header for BEARER auth", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({ auth_type: "BEARER", bearerToken: "token-123" }),
    );

    expect(value).toBe("Bearer token-123");
  });

  it("treats a bearer token with no auth_type as BEARER for backwards compatibility", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({ bearerToken: "legacy-token" }),
    );

    expect(value).toBe("Bearer legacy-token");
  });

  it("returns undefined when auth_type is NONE even if a bearer token is stored", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({ auth_type: "NONE", bearerToken: "token-123" }),
    );

    expect(value).toBeUndefined();
  });

  it("returns undefined when no credentials are configured", () => {
    expect(buildAuthorizationHeaderValue(makeServer())).toBeUndefined();
  });

  it("ignores Basic credentials when auth_type is BEARER", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BEARER",
        bearerToken: "token-123",
        basic_username: "alice",
        basic_password: "s3cret",
      }),
    );

    expect(value).toBe("Bearer token-123");
  });

  it("ignores the bearer token when auth_type is BASIC", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BASIC",
        bearerToken: "token-123",
        basic_username: "alice",
        basic_password: "s3cret",
      }),
    );

    expect(value).toBe("Basic YWxpY2U6czNjcmV0");
  });

  it("prefers an OAuth access token over a configured bearer token", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BEARER",
        bearerToken: "token-123",
        oauth_tokens: { access_token: "oauth-token", token_type: "Bearer" },
      }),
    );

    expect(value).toBe("Bearer oauth-token");
  });

  it("prefers an OAuth access token over Basic credentials", () => {
    const value = buildAuthorizationHeaderValue(
      makeServer({
        auth_type: "BASIC",
        basic_username: "alice",
        basic_password: "s3cret",
        oauth_tokens: { access_token: "oauth-token", token_type: "Bearer" },
      }),
    );

    expect(value).toBe("Bearer oauth-token");
  });
});

describe("buildHttpTransportHeaders", () => {
  it("merges custom headers with the generated Authorization header", () => {
    const headers = buildHttpTransportHeaders(
      makeServer({
        headers: { "X-Tenant": "acme" },
        auth_type: "BASIC",
        basic_username: "alice",
        basic_password: "s3cret",
      }),
    );

    expect(headers).toEqual({
      "X-Tenant": "acme",
      Authorization: "Basic YWxpY2U6czNjcmV0",
    });
  });

  it("overrides a custom Authorization header when Basic auth is configured", () => {
    const headers = buildHttpTransportHeaders(
      makeServer({
        headers: { Authorization: "Basic c3RhbGU6Y3JlZHM=" },
        auth_type: "BASIC",
        basic_username: "alice",
        basic_password: "s3cret",
      }),
    );

    expect(headers.Authorization).toBe("Basic YWxpY2U6czNjcmV0");
  });

  it("keeps a hand-written Authorization header when no auth is configured", () => {
    // The pre-existing escape hatch for Basic auth: users hand-encoded
    // credentials into a custom header. That must keep working.
    const headers = buildHttpTransportHeaders(
      makeServer({
        headers: { Authorization: "Basic YWxpY2U6czNjcmV0" },
      }),
    );

    expect(headers.Authorization).toBe("Basic YWxpY2U6czNjcmV0");
  });

  it("returns an empty object when there are no headers and no auth", () => {
    expect(buildHttpTransportHeaders(makeServer())).toEqual({});
  });
});

describe("deriveMcpServerAuthType", () => {
  it("returns the explicit auth type when the caller supplies one", () => {
    expect(
      deriveMcpServerAuthType({ auth_type: "NONE", bearerToken: "token-123" }),
    ).toBe("NONE");
  });

  it("infers BEARER from a bearer token when auth_type is omitted", () => {
    // API clients written before auth_type existed post only bearerToken.
    expect(deriveMcpServerAuthType({ bearerToken: "token-123" })).toBe(
      "BEARER",
    );
  });

  it("infers BASIC from a username when auth_type is omitted", () => {
    expect(deriveMcpServerAuthType({ basic_username: "alice" })).toBe("BASIC");
  });

  it("infers NONE when no credentials are supplied", () => {
    expect(deriveMcpServerAuthType({})).toBe("NONE");
  });

  it("ignores blank credentials", () => {
    expect(
      deriveMcpServerAuthType({ bearerToken: "", basic_username: "   " }),
    ).toBe("NONE");
  });
});

describe("CreateMcpServerRequestSchema auth validation", () => {
  const base = {
    name: "test-server",
    type: "STREAMABLE_HTTP" as const,
    url: "https://example.com/mcp",
  };

  it("defaults auth_type to BEARER when only a bearer token is given", () => {
    const parsed = CreateMcpServerRequestSchema.parse({
      ...base,
      bearerToken: "token-123",
    });

    expect(parsed.auth_type).toBe("BEARER");
  });

  it("defaults auth_type to BASIC when only Basic credentials are given", () => {
    const parsed = CreateMcpServerRequestSchema.parse({
      ...base,
      basic_username: "alice",
      basic_password: "s3cret",
    });

    expect(parsed.auth_type).toBe("BASIC");
  });

  it("rejects ambiguous credentials rather than silently picking one", () => {
    const result = CreateMcpServerRequestSchema.safeParse({
      ...base,
      bearerToken: "token-123",
      basic_username: "alice",
      basic_password: "s3cret",
    });

    expect(result.success).toBe(false);
  });

  it("accepts both credential sets when auth_type disambiguates them", () => {
    const parsed = CreateMcpServerRequestSchema.parse({
      ...base,
      auth_type: "BASIC" as const,
      bearerToken: "token-123",
      basic_username: "alice",
      basic_password: "s3cret",
    });

    expect(parsed.auth_type).toBe("BASIC");
  });
});
