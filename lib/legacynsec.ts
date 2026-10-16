import { warn } from "$lib/logging";
import { bech32m, hex } from "@scure/base";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { getPublicKey } from "nostr-tools";
import { privateKeyFromSeedWords } from "nostr-tools/nip06";
import { encrypt as nip49encrypt } from "nostr-tools/nip49";

// Accounts created before the switch to NIP-49 (Dec 2024) hold their nostr key
// as `cipher` + `salt`: BIP-39 entropy, AES-GCM encrypted under
// PBKDF2-SHA256(password, salt, 100k) with an all-zero 16-byte IV, bech32m
// encoded with the "en" prefix. The key is the NIP-06 derivation of the
// mnemonic. Returns the secret key, or undefined if the password doesn't open
// it (e.g. it was changed after the UI stopped re-encrypting the cipher).
const decryptLegacy = async ({ cipher, salt }, password: string) => {
  try {
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: hex.decode(salt), iterations: 100000, hash: "SHA-256" },
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"],
      ),
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );

    const entropy = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(16) },
      key,
      Uint8Array.from(bech32m.fromWords(bech32m.decode(cipher, 180).words)),
    );

    return privateKeyFromSeedWords(
      entropyToMnemonic(new Uint8Array(entropy), wordlist),
    );
  } catch (e) {}
};

// Given a verified password, convert a legacy cipher into a NIP-49 nsec on the
// user record so the normal reveal/sign paths work. Only adopts the key if it
// still matches the account's pubkey. Returns true if the user was changed.
export const upgradeLegacyNsec = async (user, password: string) => {
  if (user.nsec || !user.cipher || !user.salt || !password) return false;

  const sk = await decryptLegacy(user, password);
  if (!sk) {
    warn("legacy nsec: password doesn't open cipher", user.username);
    return false;
  }

  if (getPublicKey(sk) !== user.pubkey) {
    warn("legacy nsec: cipher key doesn't match pubkey", user.username);
    return false;
  }

  user.nsec = nip49encrypt(sk, password);
  return true;
};
