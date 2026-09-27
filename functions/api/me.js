import { jsonResponse, readSession } from "../lib/oauth.js";

export async function onRequestGet({ request, env }) {
  const session = await readSession(request, env);

  if (!session) {
    return jsonResponse({ error: "unauthorized" }, 401, { "Cache-Control": "no-store" });
  }

  return jsonResponse(
    {
      provider: session.provider,
      issuer: session.issuer || null,
      subject: session.subject || null,
      name: session.name,
      email: session.email || null,
    },
    200,
    { "Cache-Control": "no-store" },
  );
}
