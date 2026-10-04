import { db, g } from "$lib/db";
import { quoteRoutingFee } from "$lib/lnquote";
import { l, shortError, warn } from "$lib/logging";
import { PaymentType } from "$lib/types";

// v3 forwarding bridge. A user who migrated their name to coinos v3 still has
// their legacy account, and payments keep arriving there: old BOLT12 offers,
// old bolt11 invoices, old bitcoin/liquid deposit addresses. Each confirmed
// receive of that kind is paid on, as it lands, to the name's v3 lightning
// address (the registrar mints the invoice on the ASP's node, and its
// forwarder delivers to the wallet's Ark mailbox even while the wallet is
// closed). Only new receives move — a balance already sitting in the legacy
// account stays put — and the forward costs the user the routing fee only
// (none at all over the direct channels to the ASP's node).
//
// "Migrated" needs proof, since this moves money people sent to the LEGACY
// account: the registrar holds the name either for the legacy account's own
// nostr key (the identity-takeover rule) or for the v3 wallet the legacy
// account's own session named in a migration grant (`granted`). A name that
// merely exists on v3 is never forwarded to.

const NAMES_URL = process.env.NAMES_URL || "https://names.coinos.io";
const DOMAIN = "coinos.io";
const TYPES = [PaymentType.lightning, PaymentType.bolt12, PaymentType.bitcoin, PaymentType.liquid];
const RETRY_KEY = "v3fwd:retry"; // hash pid -> {uid, amount, tries, next}
const RETRY_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3600_000, 12 * 3600_000];

const holderCache = new Map<string, { at: number; pk: string | null; granted: boolean }>();
async function v3Holder(username: string): Promise<{ pk: string | null; granted: boolean }> {
  const name = username.toLowerCase();
  const hit = holderCache.get(name);
  // this runs on every legacy receive: a holder is re-checked each minute,
  // a name nobody holds every ten (claims change on the order of days)
  if (hit && Date.now() - hit.at < (hit.pk ? 60_000 : 600_000)) return hit;
  const r = await fetch(`${NAMES_URL}/name/${encodeURIComponent(name)}?domain=${DOMAIN}`,
    { signal: AbortSignal.timeout(2000) });
  if (!r.ok) throw new Error(`registrar said ${r.status}`);
  const body: any = await r.json();
  const pk = body?.taken && typeof body.pubkey === "string" ? body.pubkey : null;
  const hit2 = { at: Date.now(), pk, granted: !!pk && body.granted === true };
  holderCache.set(name, hit2);
  return hit2;
}

// The name's v3 address, if this legacy account has moved there.
export async function v3Destination(user): Promise<string | null> {
  if (!user?.username || !user?.pubkey || user.username.length > 64) return null;
  const { pk, granted } = await v3Holder(user.username);
  return pk && (granted || pk === user.pubkey) ? user.username.toLowerCase() : null;
}

async function invoiceFor(name: string, sats: number): Promise<string> {
  const lnurl = `${NAMES_URL}/.well-known/lnurlp/${encodeURIComponent(name)}?domain=${DOMAIN}`;
  const pr: any = await (await fetch(lnurl, { signal: AbortSignal.timeout(5000) })).json();
  if (pr?.tag !== "payRequest" || !pr.callback) throw new Error("no payRequest from registrar");
  const msat = sats * 1000;
  if (msat < (pr.minSendable || 0)) throw Object.assign(new Error(`below the v3 minimum (${pr.minSendable / 1000} sats)`), { permanent: true });
  if (pr.maxSendable && msat > pr.maxSendable) throw Object.assign(new Error(`above the v3 maximum (${pr.maxSendable / 1000} sats)`), { permanent: true });
  const sep = pr.callback.includes("?") ? "&" : "?";
  const inv: any = await (await fetch(`${pr.callback}${sep}amount=${msat}`, { signal: AbortSignal.timeout(10_000) })).json();
  if (!inv?.pr) throw new Error(inv?.reason || "registrar returned no invoice");
  return inv.pr;
}

// Pay `amount` sats of the user's legacy balance on to their v3 address,
// routing fee included in it.
async function forward({ user, amount, pid, send }) {
  const name = await v3Destination(user);
  if (!name) return null;
  let pr = await invoiceFor(name, amount);
  let { fee } = await quoteRoutingFee({ pr, amount });
  if (fee > 0) {
    if (fee >= amount) throw Object.assign(new Error(`routing fee ${fee} exceeds ${amount}`), { permanent: true });
    pr = await invoiceFor(name, amount - fee);
    ({ fee } = await quoteRoutingFee({ pr, amount: amount - fee }));
  }
  const w = await send({ user, pr, fee, memo: `Forwarded to ${name}@${DOMAIN} (coinos v3)` });
  l("v3 forward", user.username, amount, "fee", fee, "payment", pid, "->", w?.id);
  return w;
}

// Called from completePayment for every receive. Fire-and-forget: never
// blocks or fails the credit. Returns true when the receive was the bridge's
// (so legacy autowithdraw stands down for it).
export async function maybeForwardToV3(p, user, send): Promise<boolean> {
  try {
    if (!p?.confirmed || !TYPES.includes(p.type) || !(p.amount > 0)) return false;
    if ((p.aid || p.uid) !== user?.id) return false; // sub-accounts stay put
    if (!(await v3Destination(user))) return false;
    // once per payment: completePayment runs twice for on-chain deposits
    const fresh = await db.set(`v3fwd:claimed:${p.id}`, "1", { NX: true, EX: 30 * 86400 });
    if (!fresh) return true;
    forward({ user, amount: p.amount, pid: p.id, send }).catch(async (e) => {
      warn("v3 forward failed", user.username, p.amount, shortError(e?.message));
      if (!e?.permanent) await queueRetry(p.id, user.id, p.amount, 0);
    });
    return true;
  } catch (e: any) {
    warn("v3 forward check failed", user?.username, shortError(e?.message));
    return false;
  }
}

async function queueRetry(pid: string, uid: string, amount: number, tries: number) {
  if (tries >= RETRY_MS.length) {
    warn("v3 forward gave up", uid, pid, amount, "— stays in the legacy balance");
    return;
  }
  await db.hSet(RETRY_KEY, pid, JSON.stringify({ uid, amount, tries, next: Date.now() + RETRY_MS[tries] }));
}

// One process at a time works the retry queue (a short redis lock).
export async function retryV3Forwards(send) {
  const lock = await db.set("v3fwd:lock", "1", { NX: true, EX: 120 });
  if (!lock) return;
  try {
    const all = await db.hGetAll(RETRY_KEY);
    for (const [pid, raw] of Object.entries(all)) {
      const e = JSON.parse(raw as string);
      if (Date.now() < e.next) continue;
      await db.hDel(RETRY_KEY, pid);
      const user = await g(`user:${e.uid}`);
      try {
        if (!(await forward({ user, amount: e.amount, pid, send }))) continue;
      } catch (err: any) {
        warn("v3 forward retry failed", user?.username, e.amount, shortError(err?.message));
        if (!err?.permanent) await queueRetry(pid, e.uid, e.amount, e.tries + 1);
      }
    }
  } finally {
    await db.del("v3fwd:lock");
  }
}
