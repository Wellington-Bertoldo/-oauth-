export const SESSION_COOKIE = "__Host-session";
export const TX_COOKIE = "__Host-oauth-tx";

export const PROVIDERS = {
  google: {
    name: "google",
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    clientIdVar: "GOOGLE_CLIENT_ID",
    clientSecretVar: "GOOGLE_CLIENT_SECRET",
    scope: "openid email profile",
  },
  github: {
    name: "github",
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userInfoUrl: "https://api.github.com/user",
    clientIdVar: "GITHUB_CLIENT_ID",
    clientSecretVar: "GITHUB_CLIENT_SECRET",
    scope: "",
  },
};

function getRuntimeStore(env, key) {
  if (!env || typeof env !== "object") {
    return new Map();
  }

  if (!env.__oauth_runtime_store) {
    env.__oauth_runtime_store = {};
  }

  if (!env.__oauth_runtime_store[key]) {
    env.__oauth_runtime_store[key] = new Map();
  }

  return env.__oauth_runtime_store[key];
}

function bytesToBase64Url(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function randomBase64Url(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

export async function sha256Base64Url(value) {
  const encoded = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return bytesToBase64Url(digest);
}

export async function createCodeChallenge(codeVerifier) {
  return sha256Base64Url(codeVerifier);
}

export async function hashCookieValue(value) {
  return sha256Base64Url(String(value));
}

export function isValidProvider(provider) {
  return Boolean(provider && PROVIDERS[provider]);
}

export function getProviderConfig(provider) {
  return PROVIDERS[provider] ?? null;
}

export function parseCookies(rawCookie = "") {
  const cookies = {};

  if (!rawCookie) {
    return cookies;
  }

  for (const chunk of rawCookie.split(";")) {
    const entry = chunk.trim();
    if (!entry) continue;

    const separatorIndex = entry.indexOf("=");
    if (separatorIndex === -1) {
      cookies[entry] = "";
      continue;
    }

    const key = entry.slice(0, separatorIndex);
    const value = decodeURIComponent(entry.slice(separatorIndex + 1));
    cookies[key] = value;
  }

  return cookies;
}

export function serializeCookie(name, value, options = {}) {
  const {
    path = "/",
    httpOnly = true,
    sameSite = "Lax",
    secure = false,
    maxAge,
  } = options;

  let cookie = `${name}=${value}; Path=${path}; SameSite=${sameSite}`;

  if (httpOnly) {
    cookie += "; HttpOnly";
  }

  if (secure) {
    cookie += "; Secure";
  }

  if (maxAge !== undefined) {
    cookie += `; Max-Age=${maxAge}`;
  }

  return cookie;
}

export async function createTransactionRecord({ env, provider, txCookie, state, codeVerifier, nonce, expiresAt }) {
  const txHash = await hashCookieValue(txCookie);
  const stateHash = await hashCookieValue(state);
  const nonceHash = nonce ? await hashCookieValue(nonce) : null;

  const record = {
    provider,
    txHash,
    stateHash,
    nonceHash,
    codeVerifier,
    expiresAt,
  };

  const db = env && env.DB ? env.DB : null;
  if (db && typeof db.prepare === "function") {
    try {
      await db.prepare("INSERT INTO oauth_transaction (id, provider, state_hash, nonce_hash, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(txHash, provider, stateHash, nonceHash, codeVerifier, expiresAt)
        .run();
    } catch {
      // fallback to runtime store if the table is not available yet
    }
  }

  getRuntimeStore(env, "transactions").set(txHash, record);
  return record;
}

export async function findTransactionByCookie(env, txCookie) {
  if (!txCookie) {
    return null;
  }

  const txHash = await hashCookieValue(txCookie);
  const db = env && env.DB ? env.DB : null;

  if (db && typeof db.prepare === "function") {
    try {
      const row = await db.prepare("SELECT * FROM oauth_transaction WHERE id = ? AND expires_at > ?")
        .bind(txHash, Date.now())
        .first();
      if (row) {
        return row;
      }
    } catch {
      // fallback
    }
  }

  const tx = getRuntimeStore(env, "transactions").get(txHash);
  if (!tx) {
    return null;
  }

  if (Date.now() > tx.expiresAt) {
    getRuntimeStore(env, "transactions").delete(txHash);
    return null;
  }

  return tx;
}

export async function deleteTransactionByCookie(env, txCookie) {
  if (!txCookie) {
    return;
  }

  const txHash = await hashCookieValue(txCookie);
  const db = env && env.DB ? env.DB : null;
  if (db && typeof db.prepare === "function") {
    try {
      await db.prepare("DELETE FROM oauth_transaction WHERE id = ?").bind(txHash).run();
    } catch {
      // ignored when the table is absent during local development
    }
  }

  getRuntimeStore(env, "transactions").delete(txHash);
}

export async function readSession(request, env) {
  const rawCookie = request.headers.get("Cookie") ?? "";
  const cookies = parseCookies(rawCookie);
  const value = cookies[SESSION_COOKIE];

  if (!value) {
    return null;
  }

  const digest = await hashCookieValue(value);
  const db = env && env.DB ? env.DB : null;

  if (db && typeof db.prepare === "function") {
    try {
      const row = await db.prepare("SELECT * FROM oauth_session WHERE id = ? AND expires_at > ?")
        .bind(digest, Date.now())
        .first();
      if (row) {
        return row;
      }
    } catch {
      // fallback
    }
  }

  const session = getRuntimeStore(env, "sessions").get(digest);
  if (!session) {
    return null;
  }

  if (Date.now() > session.expiresAt) {
    getRuntimeStore(env, "sessions").delete(digest);
    return null;
  }

  return session;
}

export async function writeSessionCookie(env, session) {
  const sessionId = randomBase64Url();
  const digest = await hashCookieValue(sessionId);
  const expiresAt = Date.now() + 8 * 60 * 60 * 1000;
  const record = { ...session, expiresAt, id: digest };

  const db = env && env.DB ? env.DB : null;
  if (db && typeof db.prepare === "function") {
    try {
      await db.prepare("INSERT INTO oauth_session (id, provider, issuer, subject, name, email, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(digest, record.provider, record.issuer, record.subject, record.name, record.email, expiresAt)
        .run();
    } catch {
      // local fallback
    }
  }

  getRuntimeStore(env, "sessions").set(digest, record);

  return serializeCookie(SESSION_COOKIE, sessionId, {
    path: "/",
    httpOnly: true,
    sameSite: "Strict",
    secure: true,
    maxAge: 8 * 60 * 60,
  });
}

export async function deleteSessionByCookie(env, rawCookieValue) {
  if (!rawCookieValue) {
    return;
  }

  const digest = await hashCookieValue(rawCookieValue);
  const db = env && env.DB ? env.DB : null;
  if (db && typeof db.prepare === "function") {
    try {
      await db.prepare("DELETE FROM oauth_session WHERE id = ?").bind(digest).run();
    } catch {
      // ignored when table is absent during local development
    }
  }

  getRuntimeStore(env, "sessions").delete(digest);
}

export function getRedirectUri(request, provider) {
  const origin = new URL(request.url).origin;
  return `${origin}/oauth/callback/${provider}`;
}

export function jsonResponse(body, status = 200, headers = {}) {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Content-Type", "application/json; charset=utf-8");
  responseHeaders.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers: responseHeaders });
}

export function unsupportedProviderResponse() {
  return new Response("Not Found", { status: 404, headers: { "Cache-Control": "no-store" } });
}

export function getEnvValue(env, key) {
  if (!env) return "";
  return env[key] ?? env[key.toUpperCase()] ?? env[key.toLowerCase()] ?? "";
}
