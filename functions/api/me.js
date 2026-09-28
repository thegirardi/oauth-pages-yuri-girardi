import { sha256Base64url } from "../_shared/crypto.js";
import { getCookie, SESSION_COOKIE } from "../_shared/cookies.js";

export async function onRequestGet(context) {
  try {
    const sessionCookie = getCookie(
      context.request,
      SESSION_COOKIE
    );

    if (!sessionCookie) {
      return new Response(null, {
        status: 401,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    const idHash = await sha256Base64url(sessionCookie);

    const session = await context.env.DB
      .prepare(`
        SELECT issuer, subject, email, display_name, expires_at
        FROM sessions
        WHERE id_hash = ?
      `)
      .bind(idHash)
      .first();

    if (!session) {
      return new Response(null, {
        status: 401,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    const now = Math.floor(Date.now() / 1000);

    if (session.expires_at <= now) {
      await context.env.DB
        .prepare("DELETE FROM sessions WHERE id_hash = ?")
        .bind(idHash)
        .run();

      return new Response(null, {
        status: 401,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    return Response.json(
      {
        issuer: session.issuer,
        subject: session.subject,
        email: session.email,
        displayName: session.display_name,
      },
      {
        headers: {
          "Cache-Control": "no-store",
        },
      }
    );
  } catch {
    return new Response(null, {
      status: 500,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }
}