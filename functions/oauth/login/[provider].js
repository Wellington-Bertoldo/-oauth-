import {
  TX_COOKIE,
  createCodeChallenge,
  createTransactionRecord,
  getEnvValue,
  getProviderConfig,
  getRedirectUri,
  isValidProvider,
  randomBase64Url,
  serializeCookie,
  unsupportedProviderResponse,
} from "../../lib/oauth.js";

export async function onRequestGet({ request, params, env }) {
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return unsupportedProviderResponse();
  }

  const config = getProviderConfig(provider);
  const clientId = getEnvValue(env, config.clientIdVar);
  const txCookie = randomBase64Url();
  const state = randomBase64Url();
  const codeVerifier = randomBase64Url();
  const codeChallenge = await createCodeChallenge(codeVerifier);
  const nonce = provider === "google" ? randomBase64Url() : null;
  const expiresAt = Date.now() + 600 * 1000;
  const redirectUri = getRedirectUri(request, provider);
  const authUrl = new URL(config.authUrl);

  await createTransactionRecord({
    env,
    provider,
    txCookie,
    state,
    codeVerifier,
    nonce,
    expiresAt,
  });

  authUrl.searchParams.set("client_id", clientId || "");
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", config.scope);
    authUrl.searchParams.set("nonce", nonce);
    authUrl.searchParams.set("access_type", "offline");
    authUrl.searchParams.set("prompt", "select_account");
  }

  const headers = new Headers({
    Location: authUrl.toString(),
    "Cache-Control": "no-store",
  });

  headers.append(
    "Set-Cookie",
    serializeCookie(TX_COOKIE, txCookie, {
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
      secure: true,
      maxAge: 600,
    }),
  );

  return new Response(null, { status: 302, headers });
}
