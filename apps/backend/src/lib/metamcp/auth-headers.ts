import { McpServerAuthType, ServerParameters } from "@repo/zod-types";

/**
 * Encodes HTTP Basic credentials per RFC 7617.
 *
 * The `user-id:password` pair is encoded as UTF-8 before base64 so that
 * non-ASCII credentials survive the round trip; encoding as latin-1 would
 * mangle them (RFC 7617 §2.1).
 */
export const encodeBasicCredentials = (
  username: string,
  password: string,
): string => Buffer.from(`${username}:${password}`, "utf8").toString("base64");

/**
 * Resolves the effective auth type for a server.
 *
 * `auth_type` is authoritative when set. It is only absent for callers that
 * predate the column (for example an API client that still posts just
 * `bearerToken`), in which case a stored bearer token implies BEARER — the
 * behaviour those callers had before this field existed.
 */
const resolveAuthType = (
  serverParams: Pick<ServerParameters, "auth_type" | "bearerToken">,
): McpServerAuthType => {
  if (serverParams.auth_type) {
    return serverParams.auth_type;
  }
  return serverParams.bearerToken ? "BEARER" : "NONE";
};

/**
 * Builds the `Authorization` header value MetaMCP sends to a downstream
 * SSE / Streamable HTTP server, or `undefined` when MetaMCP should not set
 * one at all.
 *
 * Precedence, highest first:
 *  1. An upstream OAuth access token, when an OAuth session has one.
 *  2. `auth_type: "BEARER"` — the configured bearer token.
 *  3. `auth_type: "BASIC"` — the configured username and password.
 *  4. Nothing, which leaves any hand-written `Authorization` entry in the
 *     server's custom headers untouched.
 *
 * Steps 1, 2 and 4 preserve the behaviour that existed before Basic auth was
 * a first-class option; step 3 is the new case.
 */
export const buildAuthorizationHeaderValue = (
  serverParams: ServerParameters,
): string | undefined => {
  const oauthAccessToken = serverParams.oauth_tokens?.access_token;
  if (oauthAccessToken) {
    return `Bearer ${oauthAccessToken}`;
  }

  switch (resolveAuthType(serverParams)) {
    case "BEARER":
      return serverParams.bearerToken
        ? `Bearer ${serverParams.bearerToken}`
        : undefined;
    case "BASIC":
      // A username is required; an empty password is legal (RFC 7617 §2).
      return serverParams.basic_username
        ? `Basic ${encodeBasicCredentials(
            serverParams.basic_username,
            serverParams.basic_password ?? "",
          )}`
        : undefined;
    default:
      return undefined;
  }
};

/**
 * Builds the outgoing header set for the HTTP-based transports: the server's
 * custom headers, with the resolved `Authorization` header layered on top.
 *
 * Shared by the SSE and Streamable HTTP branches of `createMetaMcpClient` so
 * the two cannot drift apart.
 */
export const buildHttpTransportHeaders = (
  serverParams: ServerParameters,
): Record<string, string> => {
  const headers: Record<string, string> = {
    ...(serverParams.headers || {}),
  };

  const authorization = buildAuthorizationHeaderValue(serverParams);
  if (authorization) {
    headers["Authorization"] = authorization;
  }

  return headers;
};
