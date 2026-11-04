import { archive, db, g } from "$lib/db";
import ln from "$lib/ln";

// Delete an account and everything hanging off it — the same sweep as
// scripts/delall.ts on the prod host. Beyond the plain keys this also:
//   - disables the account's bolt12 offers on the node, so a payer (e.g. an
//     OCEAN payout) fails instead of settling into the house wallet;
//   - removes the invoice pointer keys (invoice:<bolt11|bolt12|offer_id>) so a
//     late settlement resolves to "no invoice" and is skipped;
//   - deletes the same keys from the archive, which gf()/getUser fall back
//     to, so nothing resurrects from there.
// Without those, a deleted user's offer kept receiving and wedged the lightning
// listener for two hours on 2026-09-05 (pay_index 1068006).
//
// Offers are disabled before any key is deleted, so if the node can't be
// reached this throws with the account still intact.
export default async function deleteUser(user) {
  const { id, username, pubkey } = user;

  // Fail up front rather than halfway through the sweep.
  await archive.ping();

  const ga = async (k: string) => {
    const v = await archive.get(k);
    try {
      return JSON.parse(v);
    } catch {
      return v;
    }
  };
  const getInv = async (iid: string) =>
    (await g(`invoice:${iid}`)) ?? (await ga(`invoice:${iid}`));

  const aids = [
    id,
    ...(await db.lRange(`${id}:accounts`, 0, -1)).filter((a) => a !== id),
  ];
  const keys = new Set<string>();
  const add = (...ks: (string | false | undefined | null)[]) =>
    ks.forEach((k) => k && keys.add(k));

  // username->uid mapping is stored lowercased+despaced (see register.ts);
  // include both forms so a mixed-case username can't leave a dangling alias.
  add(
    `user:${id}`,
    `user:${username}`,
    `user:${username.toLowerCase().replace(/\s/g, "")}`,
  );
  add(
    ...[
      "payments",
      "payments:last",
      "apps",
      "lastlen",
      "accounts",
      "contacts",
      "invoices",
      "items",
      "pins",
      "subscriptions",
      "trust",
      "square",
      "codeVerifier",
    ].map((s) => `${id}:${s}`),
  );
  add(
    `account:${id}`,
    `balance:${id}`,
    `pending:${id}`,
    `credit:bitcoin:${id}`,
    `credit:lightning:${id}`,
    `credit:liquid:${id}`,
  );
  if (pubkey)
    add(
      `user:${pubkey}`,
      `${pubkey}:follows`,
      `${pubkey}:follows:n`,
      `${pubkey}:followers`,
      `${pubkey}:followers:n`,
      `${pubkey}:pubkeys`,
    );

  // Connected NWC apps. `${id}:apps` is a SET (sAdd in register.ts).
  for (const ap of await db.sMembers(`${id}:apps`))
    add(`app:${ap}`, `${ap}:payments`);

  // Invoices and payments for the main account and every sub-account.
  const invoiceIds = new Set<string>();
  const bolt12s = new Set<string>();
  for (const aid of aids) {
    if (aid !== id)
      add(
        `account:${aid}`,
        `${aid}:payments`,
        `${aid}:payments:last`,
        `${aid}:invoices`,
        `balance:${aid}`,
        `pending:${aid}`,
      );
    for (const pid of await db.lRange(`${aid}:payments`, 0, -1))
      add(`payment:${pid}`);
    for (const iid of await db.lRange(`${aid}:invoices`, 0, -1)) {
      invoiceIds.add(iid);
      add(`invoice:${iid}`);
      const inv = await getInv(iid);
      if (!inv) continue;
      add(inv.hash && `invoice:${inv.hash}`, inv.text && `invoice:${inv.text}`);
      if (inv.type === "bolt12" && inv.hash) bolt12s.add(inv.hash);
    }
  }

  // bolt12 offers: match by bolt12 string, or through the invoice:<offer_id>
  // pointer (which also catches offers whose :invoices entry is already gone).
  const { offers } = await ln.call("listoffers", {});
  let disabled = 0;
  for (const o of offers) {
    let mine = bolt12s.has(o.bolt12);
    if (!mine) {
      let iid = await g(`invoice:${o.offer_id}`);
      if (iid && typeof iid === "object") iid = iid.id;
      if (iid) {
        if (invoiceIds.has(iid)) mine = true;
        else {
          const inv = await getInv(iid);
          if (inv && aids.includes(inv.uid)) {
            mine = true;
            add(`invoice:${iid}`, inv.hash && `invoice:${inv.hash}`);
          }
        }
      }
    }
    if (!mine) continue;
    add(`invoice:${o.offer_id}`);
    if (o.active) {
      await ln.call("disableoffer", { offer_id: o.offer_id });
      disabled++;
    }
  }

  if (pubkey && user.nip5) await db.sRem("nip5", `${username}:${pubkey}`);

  let deleted = 0;
  for (const k of keys) {
    const inDb = await db.exists(k);
    const inArc = await archive.exists(k);
    if (!inDb && !inArc) continue;
    deleted++;
    if (inDb) await db.del(k);
    if (inArc) await archive.del(k);
  }

  return { deleted, disabled };
}
