import {
  TX_COOKIE,
  deleteTransactionByCookie,
  findTransactionByCookie,
  getEnvValue,
  getProviderConfig,
  getRedirectUri,
  hashCookieValue,
  isValidProvider,
  jsonResponse,
  parseCookies,
  serializeCookie,
  unsupportedProviderResponse,
  writeSessionCookie,
} from "../../lib/oauth.js";

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return atob(normalized + pad);
}

function jsonFromBase64Url(value) {
  const raw = base64UrlDecode(value);
  return JSON.parse(raw);
}

async function readJsonSafe(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

async function verifyGoogleIdToken({ idToken, clientId, nonce, expectedIssuer }) {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid_google_jwt");
  }

  const [headerSegment, payloadSegment, signatureSegment] = parts;
  const header = jsonFromBase64Url(headerSegment);
  if (header.alg !== "RS256") {
    throw new Error("invalid_google_algorithm");
  }

  const discoveryResponse = await fetch("https://accounts.google.com/.well-known/openid-configuration");
  if (!discoveryResponse.ok) {
    throw new Error("google_discovery_failed");
  }

  const discovery = await readJsonSafe(discoveryResponse);
  if (!discovery.jwks_uri) {
    throw new Error("google_jwks_missing");
  }

  const jwksResponse = await fetch(discovery.jwks_uri);
  if (!jwksResponse.ok) {
    throw new Error("google_jwks_failed");
  }

  const jwks = await readJsonSafe(jwksResponse);
  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk) {
    throw new Error("google_key_not_found");
  }

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );

  const signingInput = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  const signature = new Uint8Array(base64UrlDecode(signatureSegment).split("").map((char) => char.charCodeAt(0)));
  const verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signingInput);
  if (!verified) {
    throw new Error("google_signature_invalid");
  }

  const payload = jsonFromBase64Url(payloadSegment);
  const currentEpoch = Math.floor(Date.now() / 1000);

  if (payload.iss !== expectedIssuer) {
    throw new Error("google_issuer_invalid");
  }

  if (payload.aud !== clientId) {
    throw new Error("google_audience_invalid");
  }

  if (Number(payload.exp) <= currentEpoch) {
    throw new Error("google_token_expired");
  }

  if (Number(payload.iat) > currentEpoch) {
    throw new Error("google_token_not_yet_valid");
  }

  if (payload.nonce !== nonce) {
    throw new Error("google_nonce_invalid");
  }

  return {
    issuer: payload.iss,
    subject: payload.sub,
    name: payload.name || payload.email || "Google User",
    email: payload.email || null,
  };
}

async function createGithubSession({ accessToken, clientId, clientSecret, provider, tx }) {
  const userResponse = await fetch("https://api.github.com/user", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      "User-Agent": "oauth-pages-demo",
    },
  });

  if (!userResponse.ok) {
    throw new Error("github_user_failed");
  }

  const userData = await readJsonSafe(userResponse);
  if (typeof userData.id !== "number") {
    throw new Error("github_user_id_missing");
  }

  const grantResponse = await fetch(`https://api.github.com/applications/${clientId}/grant`, {
    method: "DELETE",
    headers: {
      Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      "User-Agent": "oauth-pages-demo",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ access_token: accessToken }),
  });

  if (grantResponse.status !== 204) {
    throw new Error("github_revoke_failed");
  }

  return {
    provider,
    issuer: "https://github.com",
    subject: String(userData.id),
    name: userData.name || userData.login || "GitHub User",
    email: userData.email || null,
    createdAt: Date.now(),
    tx,
  };
}

export async function onRequestGet({ request, params, env }) {
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return unsupportedProviderResponse();
  }

  const config = getProviderConfig(provider);
  const search = new URL(request.url).searchParams;
  const error = search.get("error");
  const code = search.get("code");
  const state = search.get("state");

  if (error || !code || !state) {
    return jsonResponse({ error: "invalid_callback" }, 400);
  }

  const cookies = parseCookies(request.headers.get("Cookie") ?? "");
  const txCookie = cookies[TX_COOKIE];

  if (!txCookie) {
    return jsonResponse({ error: "missing_transaction_cookie" }, 400);
  }

  const tx = await findTransactionByCookie(env, txCookie);
  if (!tx || tx.provider !== provider) {
    return jsonResponse({ error: "transaction_not_found" }, 400);
  }

  const expectedStateHash = tx.stateHash;
  const actualStateHash = await hashCookieValue(state);

  if (actualStateHash !== expectedStateHash) {
    return jsonResponse({ error: "invalid_state" }, 400);
  }

  await deleteTransactionByCookie(env, txCookie);

  const tokenBody = new URLSearchParams({
    client_id: getEnvValue(env, config.clientIdVar),
    client_secret: getEnvValue(env, config.clientSecretVar),
    code,
    grant_type: "authorization_code",
    redirect_uri: getRedirectUri(request, provider),
    code_verifier: tx.codeVerifier,
  });

  const tokenResponse = await fetch(config.tokenUrl, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenBody,
  });

  const tokenData = await readJsonSafe(tokenResponse);
  const accessToken = tokenData.access_token;

  if (!tokenResponse.ok || !accessToken) {
    return jsonResponse({ error: "token_exchange_failed" }, 400);
  }

  let profile;

  try {
    if (provider === "google") {
      const tokenType = String(tokenData.token_type || "").trim();
      if (tokenType && !/^Bearer$/i.test(tokenType)) {
        throw new Error("google token_type_invalid");
      }

      const idToken = tokenData.id_token;
      if (!idToken || typeof idToken !== "string") {
        throw new Error("google_id_token_missing");
      }

      const googleIdentity = await verifyGoogleIdToken({
        idToken,
        clientId: getEnvValue(env, config.clientIdVar),
        nonce: tx.nonce,
        expectedIssuer: "https://accounts.google.com",
      });

      profile = {
        provider,
        issuer: googleIdentity.issuer,
        subject: googleIdentity.subject,
        name: googleIdentity.name,
        email: googleIdentity.email,
        createdAt: Date.now(),
      };
    } else if (provider === "github") {
      const tokenType = String(tokenData.token_type || "").trim();
      if (!/^Bearer$/i.test(tokenType)) {
        throw new Error("github_token_type_invalid");
      }

      profile = await createGithubSession({
        accessToken,
        clientId: getEnvValue(env, config.clientIdVar),
        clientSecret: getEnvValue(env, config.clientSecretVar),
        provider,
        tx,
      });
    }
  } catch (error) {
    return jsonResponse({ error: `identity_validation_failed:${provider}` }, 400);
  }

  const publicBaseUrl = getEnvValue(env, "PUBLIC_BASE_URL") || "/";
  const headers = new Headers({
    Location: publicBaseUrl,
  });

  headers.append("Set-Cookie", await writeSessionCookie(env, profile));
  headers.append(
    "Set-Cookie",
    serializeCookie(TX_COOKIE, "", {
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      maxAge: 0,
    }),
  );

  return new Response(null, { status: 302, headers });
}
