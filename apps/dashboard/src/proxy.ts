import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

const forbiddenPreviewCookies = [
  "__prerender_bypass",
  "__next_preview_data",
] as const;

/**
 * NTIP does not expose Next Draft Mode or Preview Mode. Next still requires
 * compatibility values in its production manifest, so reject their cookies
 * before any route, static asset, or Server Component can observe them.
 */
export function proxy(request: NextRequest): NextResponse {
  if (!forbiddenPreviewCookies.some((name) => request.cookies.has(name))) {
    return NextResponse.next();
  }

  const response = new NextResponse("Next preview modes are unavailable.\n", {
    status: 400,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
  for (const name of forbiddenPreviewCookies) response.cookies.delete(name);
  return response;
}
