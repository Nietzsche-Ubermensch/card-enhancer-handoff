import { assertSameSiteRequest, CrossSiteRequestError } from "./isolation.server";
import { getSessionUser } from "./verify.server";

/** Require an authenticated session for billable or user-specific API routes. */
export async function requireApiUser(): Promise<Response | null> {
  try {
    assertSameSiteRequest();
  } catch (e) {
    if (e instanceof CrossSiteRequestError) {
      return Response.json({ ok: false, error: "Forbidden" }, { status: 403 });
    }
  }
  try {
    const user = await getSessionUser();
    if (user) return null;
  } catch {
    // Authentication failures must not leave paid endpoints open.
  }
  return Response.json({ ok: false, error: "Unauthorized" }, { status: 401 });
}
