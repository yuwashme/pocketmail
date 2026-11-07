import { EmailMessage } from "cloudflare:email";

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname !== "/send" || request.method !== "POST")
      return new Response(null, { status: 404 });
    const supplied = request.headers.get("authorization") ?? "";
    const expected = "Bearer " + env.SUBMIT_TOKEN;
    const encoder = new TextEncoder();
    const actualBytes = encoder.encode(supplied);
    const expectedBytes = encoder.encode(expected);
    if (!env.SUBMIT_TOKEN || actualBytes.length !== expectedBytes.length ||
        !crypto.subtle.timingSafeEqual(actualBytes, expectedBytes))
      return new Response(null, { status: 403 });
    const from = request.headers.get("x-envelope-from");
    const to = request.headers.get("x-envelope-to");
    const length = Number(request.headers.get("content-length"));
    if (!Number.isSafeInteger(length) || length <= 0 || length > 25 * 1024 * 1024)
      return new Response(null, { status: 413 });
    if (!env.ALLOWED_SENDER || from !== env.ALLOWED_SENDER || !to)
      return new Response(null, { status: 422 });
    try {
      const raw = await request.text();
      if (raw.length > 25 * 1024 * 1024) return new Response(null, { status: 413 });
      await env.SEND.send(new EmailMessage(from, to, raw));
      return new Response(null, { status: 204 });
    } catch (err) {
      return new Response(String(err?.message ?? "Submission failed"), { status: 422 });
    }
  },
};
