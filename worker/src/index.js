// Inbound hand-off for Synology Mail Server, Worker contract v1.
// email(): Cloudflare Email Routing delivers a message -> stored raw in KV until durable NAS acknowledgment under
//   msg:<13-digit arrival ms>:<uuid> with { from, to, size } metadata. Over 25 MiB is rejected.
//   A KV failure is rethrown so Email Routing retries instead of losing the message.
// fetch(): the NAS pulls over outbound HTTPS with a bearer token:
//   GET    /messages      -> {"ids": [oldest first], "complete": bool}  (one KV list per request)
//   GET    /messages/:id  -> message/rfc822 with Content-Length, X-SSM-Size and percent-encoded
//                            X-SSM-Envelope-To / X-SSM-Envelope-From (one getWithMetadata read)
//   DELETE /messages/:id  -> 204, also when the id is already gone (idempotent ack)

const MAX_BYTES = 25 * 1024 * 1024;
const TOO_LARGE = "552 5.3.4 Message too large";

export async function storeMessage(env, rawBuffer, from, to) {
  const id = `msg:${Date.now().toString().padStart(13, "0")}:${crypto.randomUUID()}`;
  await env.INBOX.put(id, rawBuffer, { metadata: { from, to, size: rawBuffer.byteLength } });
  return id;
}

function authorized(request, env) {
  const given = request.headers.get("authorization") || "";
  const want = `Bearer ${env.PULL_TOKEN || ""}`;
  if (!env.PULL_TOKEN || given.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= given.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

async function getMessage(env, id) {
  const { value, metadata } = await env.INBOX.getWithMetadata(id, "arrayBuffer");
  if (value === null) return new Response("not found", { status: 404 });
  const size = String(value.byteLength);
  const headers = { "content-type": "message/rfc822", "content-length": size, "x-ssm-size": size };
  if (metadata) {
    // encodeURIComponent output is printable ASCII, so UTF-8 addresses survive an HTTP header.
    headers["x-ssm-envelope-to"] = encodeURIComponent(metadata.to ?? "");
    headers["x-ssm-envelope-from"] = encodeURIComponent(metadata.from ?? "");
  }
  return new Response(value, { headers });
}

export async function handleFetch(request, env) {
  if (!authorized(request, env)) return new Response("unauthorized", { status: 401 });
  const url = new URL(request.url);
  if (url.pathname === "/messages" && request.method === "GET") {
    // Exactly one list() per request (KV list quota); the NAS lists again at once while complete is false.
    const l = await env.INBOX.list({ prefix: "msg:" });
    return Response.json({ ids: l.keys.map((k) => k.name), complete: l.list_complete === true });
  }
  const m = url.pathname.match(/^\/messages\/(.+)$/);
  if (m) {
    const id = decodeURIComponent(m[1]);
    if (request.method === "GET") return getMessage(env, id);
    if (request.method === "DELETE") {
      await env.INBOX.delete(id);
      return new Response(null, { status: 204 });
    }
  }
  return new Response("not found", { status: 404 });
}

export default {
  fetch: handleFetch,
  async email(message, env) {
    if (message.rawSize > MAX_BYTES) {
      message.setReject(TOO_LARGE);
      return;
    }
    const raw = await new Response(message.raw).arrayBuffer();
    if (raw.byteLength > MAX_BYTES) {
      message.setReject(TOO_LARGE);
      return;
    }
    await storeMessage(env, raw, message.from, message.to);
  },
};
