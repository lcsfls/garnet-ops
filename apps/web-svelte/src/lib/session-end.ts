/**
 * Leaving the signed-in app. Both ways go through a full page load to the sign-in page, so
 * every query, live stream and piece of state of the old session is gone at once instead of
 * failing one by one with "not signed in" while the app is still on screen.
 */

/** Pages a signed-out visitor belongs on: a 401 there is the expected answer. */
const PUBLIC_PATHS = ["/sign-in", "/setup", "/invite", "/two-factor", "/enroll", "/no-access"];

let signedIn = false;
let leaving = false;

/** Called once the API confirmed a session; only then does a later 401 mean it has ended. */
export function markSignedIn(): void {
  signedIn = true;
}

function onPublicPage(): boolean {
  const path = window.location.pathname;
  return PUBLIC_PATHS.some((p) => path === p || path.startsWith(`${p}/`));
}

/**
 * The API answered 401 although this page had a session: it expired, was signed out in another
 * tab, or was ended from the account page or by an admin. Go to the sign-in page and say so.
 */
export function sessionEnded(): void {
  if (!signedIn || leaving || typeof window === "undefined" || onPublicPage()) return;
  leaving = true;
  window.location.assign("/sign-in?ended=1");
}

/** Signs out and loads the sign-in page, also when the sign-out request itself fails. */
export async function signOutAndLeave(signOut: () => Promise<unknown>): Promise<void> {
  leaving = true;
  try {
    await signOut();
  } catch {
    // The session may already be gone; the sign-in page is the right place either way.
  }
  window.location.assign("/sign-in");
}
