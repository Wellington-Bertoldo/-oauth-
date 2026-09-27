import { SESSION_COOKIE, TX_COOKIE, deleteSessionByCookie, jsonResponse, parseCookies, serializeCookie } from "../lib/oauth.js";

export async function onRequestPost({ request, env }) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "method_not_allowed" }, 405, { "Cache-Control": "no-store" });
  }

  const origin = request.headers.get("Origin") ?? "";
  const publicBaseUrl = (env && env.PUBLIC_BASE_URL) || "";
  if (origin !== publicBaseUrl) {
    return jsonResponse({ error: "forbidden" }, 403, { "Cache-Control": "no-store" });
  }

  const sessionCookieValue = parseCookies(request.headers.get("Cookie") ?? "")[SESSION_COOKIE];
  if (sessionCookieValue) {
    await deleteSessionByCookie(env, sessionCookieValue);
  }

  const headers = new Headers({
    "Cache-Control": "no-store",
  });

  headers.append(
    "Set-Cookie",
    serializeCookie(SESSION_COOKIE, "", {
      path: "/",
      httpOnly: true,
      sameSite: "Strict",
      secure: true,
      maxAge: 0,
    }),
  );

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

  return jsonResponse({ ok: true }, 200, headers);
}
