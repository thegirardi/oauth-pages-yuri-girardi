const GOOGLE_ISSUER = "https://accounts.google.com";
const DISCOVERY_URL =
  "https://accounts.google.com/.well-known/openid-configuration";

function base64urlDecode(value) {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function decodeJsonPart(value) {
  const bytes = base64urlDecode(value);
  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function validateGoogleIdToken(idToken, expectedClientId, expectedNonce) {
  const parts = idToken.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid ID token");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const header = decodeJsonPart(encodedHeader);
  const payload = decodeJsonPart(encodedPayload);

  if (header.alg !== "RS256") {
    throw new Error("Invalid signing algorithm");
  }

  if (!header.kid) {
    throw new Error("Missing key id");
  }

  const discoveryResponse = await fetch(DISCOVERY_URL);

  if (!discoveryResponse.ok) {
    throw new Error("Unable to obtain OIDC configuration");
  }

  const discovery = await discoveryResponse.json();

  if (discovery.issuer !== GOOGLE_ISSUER) {
    throw new Error("Invalid issuer configuration");
  }

  const jwksResponse = await fetch(discovery.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error("Unable to obtain JWKS");
  }

  const jwks = await jwksResponse.json();

  const jwk = jwks.keys.find(
    (key) => key.kid === header.kid && key.kty === "RSA"
  );

  if (!jwk) {
    throw new Error("Signing key not found");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["verify"]
  );

  const data = new TextEncoder().encode(
    `${encodedHeader}.${encodedPayload}`
  );

  const signature = base64urlDecode(encodedSignature);

  const validSignature = await crypto.subtle.verify(
    {
      name: "RSASSA-PKCS1-v1_5",
    },
    publicKey,
    signature,
    data
  );

  if (!validSignature) {
    throw new Error("Invalid ID token signature");
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== GOOGLE_ISSUER) {
    throw new Error("Invalid issuer");
  }

  if (payload.aud !== expectedClientId) {
    throw new Error("Invalid audience");
  }

  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new Error("Expired ID token");
  }

  if (typeof payload.iat !== "number" || payload.iat > now + 300) {
    throw new Error("Invalid issued-at time");
  }

  if (payload.nonce !== expectedNonce) {
    throw new Error("Invalid nonce");
  }

  if (!payload.sub) {
    throw new Error("Missing subject");
  }

  return {
    issuer: GOOGLE_ISSUER,
    subject: String(payload.sub),
    email: payload.email ?? null,
    displayName: payload.name ?? null,
  };
}