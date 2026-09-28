const TX_COOKIE = "__Host-oauth-tx";
const SESSION_COOKIE = "__Host-session";

export function setTransactionCookie(value) {
  return `${TX_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}

export function clearTransactionCookie() {
  return `${TX_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function setSessionCookie(value) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export function getCookie(request, name) {
  const header = request.headers.get("Cookie");

  if (!header) {
    return null;
  }

  const cookies = header.split(";");

  for (const cookie of cookies) {
    const [key, ...parts] = cookie.trim().split("=");

    if (key === name) {
      return parts.join("=");
    }
  }

  return null;
}

export { TX_COOKIE, SESSION_COOKIE };