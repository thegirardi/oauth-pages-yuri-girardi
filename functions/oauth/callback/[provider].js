import {
  sha256Base64url,
  randomToken,
} from "../../_shared/crypto.js";

import {
  getCookie,
  SESSION_COOKIE,
  clearTransactionCookie,
  setSessionCookie,
} from "../../_shared/cookies.js";

import {
  getProvider,
} from "../../_shared/providers.js";

import {
  validateGoogleIdToken,
} from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const providerName = context.params.provider;
  const provider = getProvider(providerName);

  if (!provider) {
    return new Response("Not Found", {
      status: 404,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const url = new URL(context.request.url);

  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (error || !code || !state) {
    return new Response("OAuth authentication failed", {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const transactionCookie = getCookie(
    context.request,
    "__Host-oauth-tx"
  );

  if (!transactionCookie) {
    return new Response("OAuth transaction missing", {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const transactionHash =
    await sha256Base64url(transactionCookie);

  const transaction = await context.env.DB
    .prepare(`
      SELECT
        id_hash,
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
      FROM oauth_transactions
      WHERE id_hash = ?
    `)
    .bind(transactionHash)
    .first();

  if (!transaction) {
    return new Response("OAuth transaction invalid", {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const now = Math.floor(Date.now() / 1000);

  if (
    transaction.expires_at <= now ||
    transaction.provider !== providerName
  ) {
    await context.env.DB
      .prepare(
        "DELETE FROM oauth_transactions WHERE id_hash = ?"
      )
      .bind(transactionHash)
      .run();

    return new Response("OAuth transaction expired", {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const stateHash = await sha256Base64url(state);

  if (stateHash !== transaction.state_hash) {
    await context.env.DB
      .prepare(
        "DELETE FROM oauth_transactions WHERE id_hash = ?"
      )
      .bind(transactionHash)
      .run();

    return new Response("Invalid OAuth state", {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  // A transação deve ser removida antes da conclusão do fluxo.
  await context.env.DB
    .prepare(
      "DELETE FROM oauth_transactions WHERE id_hash = ?"
    )
    .bind(transactionHash)
    .run();

  const clientId =
    providerName === "google"
      ? context.env.GOOGLE_CLIENT_ID
      : context.env.GITHUB_CLIENT_ID;

  const clientSecret =
    providerName === "google"
      ? context.env.GOOGLE_CLIENT_SECRET
      : context.env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return new Response("Server configuration error", {
      status: 500,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const redirectUri =
    `${context.env.PUBLIC_BASE_URL}/oauth/callback/${providerName}`;

  const tokenBody = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: transaction.code_verifier,
  });

  const tokenResponse = await fetch(
    provider.tokenEndpoint,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: tokenBody.toString(),
    }
  );

  if (!tokenResponse.ok) {
    return new Response("Token exchange failed", {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const tokenData = await tokenResponse.json();

  let identity;

  if (providerName === "google") {
    if (!tokenData.id_token) {
      return new Response("Missing identity token", {
        status: 400,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    identity = await validateGoogleIdToken(
      tokenData.id_token,
      context.env.GOOGLE_CLIENT_ID,
      transaction.nonce
    );
  } else {
    if (
      !tokenData.access_token ||
      String(tokenData.token_type).toLowerCase() !== "bearer"
    ) {
      return new Response("Invalid GitHub token", {
        status: 400,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    const profileResponse = await fetch(
      "https://api.github.com/user",
      {
        headers: {
          Authorization:
            `Bearer ${tokenData.access_token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "User-Agent": "oauth-pages-lab",
        },
      }
    );

    if (!profileResponse.ok) {
      return new Response("GitHub profile request failed", {
        status: 400,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    const profile = await profileResponse.json();

    if (!Number.isInteger(profile.id)) {
      return new Response("Invalid GitHub identity", {
        status: 400,
        headers: {
          "Cache-Control": "no-store",
        },
      });
    }

    identity = {
      issuer: "https://github.com",
      subject: String(profile.id),
      email: profile.email ?? null,
      displayName: profile.name ?? profile.login ?? null,
    };

    const revokeResponse = await fetch(
      `https://api.github.com/applications/${encodeURIComponent(
        context.env.GITHUB_CLIENT_ID
      )}/grant`,
      {
        method: "DELETE",
        headers: {
          Authorization:
            "Basic " +
            btoa(
              `${context.env.GITHUB_CLIENT_ID}:${context.env.GITHUB_CLIENT_SECRET}`
            ),
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "X-GitHub-Api-Version": "2026-03-10",
          "User-Agent": "oauth-pages-lab",
        },
        body: JSON.stringify({
          access_token: tokenData.access_token,
        }),
      }
    );

    if (revokeResponse.status !== 204) {
      return new Response(
        "GitHub authorization revocation failed",
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
          },
        }
      );
    }
  }

  const session = randomToken();
  const sessionHash =
    await sha256Base64url(session);

  const sessionExpiresAt = now + 28800;

  await context.env.DB
    .prepare(`
      INSERT INTO sessions
      (
        id_hash,
        issuer,
        subject,
        email,
        display_name,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      sessionHash,
      identity.issuer,
      identity.subject,
      identity.email,
      identity.displayName,
      sessionExpiresAt,
      now
    )
    .run();

  // IMPORTANTE:
  // cada cookie precisa ser enviado como um Set-Cookie separado.
  const headers = new Headers();

  headers.set(
    "Location",
    context.env.PUBLIC_BASE_URL
  );

  headers.append(
    "Set-Cookie",
    clearTransactionCookie()
  );

  headers.append(
    "Set-Cookie",
    setSessionCookie(session)
  );

  headers.set(
    "Cache-Control",
    "no-store"
  );

  return new Response(null, {
    status: 302,
    headers,
  });
}