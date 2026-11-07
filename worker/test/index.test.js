import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { storeMessage, handleFetch } from "../src/index.js";

// Fake Workers KV, faithful to the parts of the real API the Worker uses:
// list() pages in lexicographic key order with list_complete/cursor and per-key metadata,
// getWithMetadata() returns { value, metadata }. Call counts let tests check KV quota use.
function fakeKV({ pageSize = 1000, failPut = false } = {}) {
  const m = new Map();
  const calls = { put: 0, get: 0, getWithMetadata: 0, list: 0, delete: 0 };
  return {
    calls,
    raw: m,
    put: async (k, v, o) => {
      calls.put++;
      if (failPut) throw new Error("KV put failed (fake)");
      m.set(k, { v, o });
    },
    get: async (k, t) => {
      calls.get++;
      return m.has(k) ? m.get(k).v : null;
    },
    getWithMetadata: async (k, t) => {
      calls.getWithMetadata++;
      if (!m.has(k)) return { value: null, metadata: null };
      return { value: m.get(k).v, metadata: m.get(k).o?.metadata ?? null };
    },
    delete: async (k) => {
      calls.delete++;
      m.delete(k);
    },
    list: async ({ prefix = "", limit = 1000, cursor } = {}) => {
      calls.list++;
      const all = [...m.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0;
      const n = Math.min(limit, pageSize);
      const page = all.slice(start, start + n);
      const done = start + n >= all.length;
      return {
        keys: page.map((name) => ({ name, metadata: m.get(name).o?.metadata })),
        list_complete: done,
        ...(done ? {} : { cursor: String(start + n) }),
      };
    },
  };
}
const env = (kv) => ({ INBOX: fakeKV(kv), PULL_TOKEN: "s3cret" });
const req = (path, init = {}, tok = "s3cret") =>
  new Request("https://x.test" + path, { ...init, headers: { authorization: `Bearer ${tok}`, ...(init.headers || {}) } });

test("stores raw message under msg: key with from/to metadata", async () => {
  const e = env();
  const id = await storeMessage(e, new TextEncoder().encode("Subject: hi\r\n\r\nbody").buffer, "a@b.c", "test@example.com");
  assert.match(id, /^msg:/);
  assert.ok(await e.INBOX.get(id));
});

test("rejects requests without the right bearer token", async () => {
  const r = await handleFetch(req("/messages", {}, "wrong"), env());
  assert.equal(r.status, 401);
});

test("lists, fetches and deletes a message", async () => {
  const e = env();
  const id = await storeMessage(e, new TextEncoder().encode("raw").buffer, "a@b.c", "test@example.com");
  const list = await (await handleFetch(req("/messages"), e)).json();
  assert.deepEqual(list.ids, [id]);
  const got = await handleFetch(req("/messages/" + encodeURIComponent(id)), e);
  assert.equal(got.status, 200);
  assert.equal(await got.text(), "raw");
  const del = await handleFetch(req("/messages/" + encodeURIComponent(id), { method: "DELETE" }), e);
  assert.equal(del.status, 204);
  assert.deepEqual((await (await handleFetch(req("/messages"), e)).json()).ids, []);
});

// ---------------------------------------------------------------------------
// Worker contract v1
// ---------------------------------------------------------------------------

const MiB = 1024 * 1024;
const enc = (s) => new TextEncoder().encode(s);

// A fake ForwardableEmailMessage as Cloudflare Email Routing hands it to email().
function fakeMessage(bytes, { from = "a@b.c", to = "test@example.com" } = {}) {
  const msg = { from, to, rawSize: bytes.byteLength, raw: new Response(bytes).body, headers: new Headers(), rejected: [] };
  msg.setReject = (reason) => msg.rejected.push(reason);
  return msg;
}

const getJSON = async (e, path = "/messages") => {
  const r = await handleFetch(req(path), e);
  assert.equal(r.status, 200);
  return r.json();
};

test("v1 list: ids oldest first (13-digit zero-padded ms sorts by time) and complete:true", async (t) => {
  const e = env();
  const at = (ms) => {
    t.mock.method(Date, "now", () => ms);
    return storeMessage(e, enc("x").buffer, "a@b.c", "test@example.com");
  };
  const late = await at(1793870040123);
  const early = await at(999);
  const mid = await at(1000);
  const body = await getJSON(e);
  assert.deepEqual(body.ids, [early, mid, late]);
  assert.equal(body.complete, true);
});

test("v1 list: one KV list per request; a partial page says complete:false, then the rest", async () => {
  const e = env({ pageSize: 2 });
  const ids = [];
  for (let i = 0; i < 3; i++) ids.push(await storeMessage(e, enc("m" + i).buffer, "a@b.c", "test@example.com"));
  ids.sort();
  const first = await getJSON(e);
  assert.equal(e.INBOX.calls.list, 1, "exactly one KV list() per GET /messages (KV list quota)");
  assert.deepEqual(first.ids, ids.slice(0, 2));
  assert.equal(first.complete, false);
  for (const id of first.ids) await handleFetch(req("/messages/" + encodeURIComponent(id), { method: "DELETE" }), e);
  const second = await getJSON(e);
  assert.equal(e.INBOX.calls.list, 2);
  assert.deepEqual(second.ids, ids.slice(2));
  assert.equal(second.complete, true);
});

test("v1 get: raw bytes, Content-Length, X-SSM-Size and percent-encoded envelope headers from one getWithMetadata", async () => {
  const e = env();
  const raw = enc("Subject: =?UTF-8?Q?=C5=A1?=\r\n\r\nbody šđč\r\n");
  const from = "a%b+tag@exämple.test";
  const to = "šef+news@example.com";
  const id = await storeMessage(e, raw.buffer, from, to);
  const r = await handleFetch(req("/messages/" + encodeURIComponent(id)), e);
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type") || "", /^message\/rfc822/);
  assert.equal(r.headers.get("content-length"), String(raw.byteLength));
  assert.equal(r.headers.get("x-ssm-size"), String(raw.byteLength));
  const hTo = r.headers.get("x-ssm-envelope-to");
  const hFrom = r.headers.get("x-ssm-envelope-from");
  assert.ok(hTo !== null && hFrom !== null, "both envelope headers present");
  assert.match(hTo, /^[\x21-\x7e]+$/, "envelope-to is printable ASCII");
  assert.match(hFrom, /^[\x21-\x7e]+$/, "envelope-from is printable ASCII");
  assert.equal(decodeURIComponent(hTo), to);
  assert.equal(decodeURIComponent(hFrom), from);
  assert.deepEqual(new Uint8Array(await r.arrayBuffer()), raw);
  assert.equal(e.INBOX.calls.getWithMetadata, 1, "one getWithMetadata read");
  assert.equal(e.INBOX.calls.get, 0, "no separate get() read");
});

test("v1 get: a message stored without metadata is still served with its size", async () => {
  const e = env();
  const raw = enc("Subject: old\r\n\r\nno metadata");
  const id = "msg:1793870040123:00000000-0000-4000-8000-000000000000";
  await e.INBOX.put(id, raw.buffer, {});
  const r = await handleFetch(req("/messages/" + encodeURIComponent(id)), e);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("content-length"), String(raw.byteLength));
  assert.equal(r.headers.get("x-ssm-size"), String(raw.byteLength));
  assert.deepEqual(new Uint8Array(await r.arrayBuffer()), raw);
});

test("v1 get: an id that is already gone gives 404", async () => {
  const r = await handleFetch(req("/messages/" + encodeURIComponent("msg:0000000000001:gone")), env());
  assert.equal(r.status, 404);
});

test("v1 delete: idempotent, a missing or already deleted id gives 204", async () => {
  const e = env();
  const id = await storeMessage(e, enc("x").buffer, "a@b.c", "test@example.com");
  const del = () => handleFetch(req("/messages/" + encodeURIComponent(id), { method: "DELETE" }), e);
  assert.equal((await del()).status, 204);
  assert.equal((await del()).status, 204);
  const never = await handleFetch(req("/messages/" + encodeURIComponent("msg:0000000000001:never"), { method: "DELETE" }), e);
  assert.equal(never.status, 204);
});

test("v1 auth: get and delete of one message also need the bearer token", async () => {
  const e = env();
  const id = await storeMessage(e, enc("x").buffer, "a@b.c", "test@example.com");
  const path = "/messages/" + encodeURIComponent(id);
  assert.equal((await handleFetch(req(path, {}, "wrong"), e)).status, 401);
  assert.equal((await handleFetch(req(path, { method: "DELETE" }, "wrong"), e)).status, 401);
  assert.equal(e.INBOX.calls.delete, 0);
  assert.ok(e.INBOX.raw.has(id));
});

test("v1 email(): key is msg:<13-digit arrival ms>:<uuid>, no expiry, from/to/size metadata", async (t) => {
  const e = env();
  t.mock.method(Date, "now", () => 1793870040123);
  const raw = enc("Subject: hi\r\n\r\nbody");
  const msg = fakeMessage(raw, { from: "a@b.c", to: "test@example.com" });
  await worker.email(msg, e, {});
  const keys = [...e.INBOX.raw.keys()];
  assert.equal(keys.length, 1);
  assert.match(keys[0], /^msg:1793870040123:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  const { o } = e.INBOX.raw.get(keys[0]);
  assert.equal(o.expirationTtl, undefined);
  assert.equal(o.expiration, undefined);
  assert.deepEqual(o.metadata, { from: "a@b.c", to: "test@example.com", size: raw.byteLength });
  assert.deepEqual(msg.rejected, []);
});

test("v1 email(): over 25 MiB is rejected with 552 5.3.4 and nothing is stored", async () => {
  const e = env();
  const msg = fakeMessage(new Uint8Array(25 * MiB + 1));
  await worker.email(msg, e, {});
  assert.deepEqual(msg.rejected, ["552 5.3.4 Message too large"]);
  assert.equal(e.INBOX.calls.put, 0);
  assert.equal(e.INBOX.raw.size, 0);
});

test("v1 email(): exactly 25 MiB is accepted and stored", async () => {
  const e = env();
  const msg = fakeMessage(new Uint8Array(25 * MiB));
  await worker.email(msg, e, {});
  assert.deepEqual(msg.rejected, []);
  assert.equal(e.INBOX.raw.size, 1);
  const [{ o }] = [...e.INBOX.raw.values()];
  assert.equal(o.metadata.size, 25 * MiB);
});

test("v1 email(): a KV put failure rethrows (Email Routing retries) and does not reject the message", async () => {
  const e = env({ failPut: true });
  const msg = fakeMessage(enc("Subject: hi\r\n\r\nbody"));
  await assert.rejects(worker.email(msg, e, {}), /KV put failed/);
  assert.deepEqual(msg.rejected, []);
});
