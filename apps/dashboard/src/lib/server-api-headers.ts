const sessionCookieName = "__Host-ntip_session";

/**
 * Build the deliberately small header set for the dashboard's trusted
 * loopback hop to ntip-api.
 *
 * ntip-api workers own one HTTP/1.1 connection at a time. Server Components
 * can issue more concurrent reads than the configured worker count, so an
 * idle keep-alive connection must not pin a worker while another connection
 * waits in the admission queue. Loopback connection setup is bounded and
 * inexpensive; close each internal connection after its response.
 */
export function internalApiHeaders(session: string | undefined): Headers {
  const headers = new Headers({ Accept: "application/json", Connection: "close" });

  // Never reflect the browser cookie jar wholesale into the privileged
  // loopback hop.
  if (session !== undefined && !/[;\r\n]/.test(session)) {
    headers.set("Cookie", `${sessionCookieName}=${session}`);
  }

  return headers;
}
