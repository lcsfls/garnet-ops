import { redirect } from "@sveltejs/kit";

/** The pages of 0.0.3 were at /exposure; website monitoring is back at /websites (ADR 0033), so old links still lead there. */
export function load({ params, url }) {
  redirect(308, `/websites${params.rest ? `/${params.rest}` : ""}${url.search}`);
}
