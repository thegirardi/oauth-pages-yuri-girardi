import {
  randomToken,
  sha256Base64url,
  codeChallenge,
} from "../../_shared/crypto.js";

import {
  setTransactionCookie,
} from "../../_shared/cookies.js";

import {
  getProvider,
} from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const providerName = context.params.provider;

  const provider = getProvider(providerName);

  if (!provider) {
    return new Response("Not Found", { status: 404 });
  }

  const env = context.env;

  const baseUrl = env.PUBLIC_BASE_URL;

  const clientId =
    providerName === "google"
      ? env.GOOGLE_CLIENT_ID
      : env.GITHUB_CLIENT_ID;

  if (!baseUrl || !clientId) {
    return new Response("Server configuration error", {
      status: 500,
    });
  }

  const codeVerifier = randomToken();
  const state = randomToken();
  const transaction = randomToken();

  const nonce =
    providerName === "google"
      ? randomToken()
      : null;

  const stateHash = await sha256Base64url(state);
  const transactionHash = await sha256Base64url(transaction);
  const challenge = await codeChallenge(codeVerifier);

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 600;

  await env.DB
    .prepare(`
      INSERT INTO oauth_transactions
      (
        id_hash,
        provider,
        state_hash,
        nonce,
        code_verifier,
        expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .bind(
      transactionHash,
      providerName,
      stateHash,
      nonce,
      codeVerifier,
      expiresAt
    )
    .run();

  const redirectUri =
    `${baseUrl}/oauth/callback/${providerName}`;

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  if (providerName === "google") {
    params.set("scope", "openid email profile");
    params.set("nonce", nonce);
  }

  const authorizationUrl =
    `${provider.authorizationEndpoint}?${params.toString()}`;

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizationUrl,
      "Set-Cookie": setTransactionCookie(transaction),
      "Cache-Control": "no-store",
    },
  });
}