import {
  sha256Base64url,
} from "../_shared/crypto.js";

import {
  getCookie,
  SESSION_COOKIE,
  clearSessionCookie,
} from "../_shared/cookies.js";

export async function onRequestPost(context) {
  const origin =
    context.request.headers.get("Origin");

  if (origin !== context.env.PUBLIC_BASE_URL) {
    return new Response("Forbidden", {
      status: 403,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const sessionCookie = getCookie(
    context.request,
    SESSION_COOKIE
  );

  if (sessionCookie) {
    const sessionHash =
      await sha256Base64url(sessionCookie);

    await context.env.DB
      .prepare("DELETE FROM sessions WHERE id_hash = ?")
      .bind(sessionHash)
      .run();
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Set-Cookie": clearSessionCookie(),
      "Cache-Control": "no-store",
    },
  });
}