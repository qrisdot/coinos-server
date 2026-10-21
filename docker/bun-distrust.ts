// Bun compiles Mozilla's root store into its binary, and NODE_USE_SYSTEM_CA
// only adds to it. Until a Bun release drops a distrusted root, overwrite its
// DER in place with a same-length self-signed placeholder whose key was thrown
// away (zeroing it instead makes every TLS handshake fail).
//
// emSign ECC Root CA - G3: eMudhra intermediate key compromise, CVE-2026-111943.
import { readFileSync, writeFileSync } from "node:fs";
import { getCACertificates } from "node:tls";
import { X509Certificate } from "node:crypto";

const distrust = {
  "emSign ECC Root CA - G3":
    "MIICTjCCAdSgAwIBAgIUfFrc+EjEsB3lBo+k60ijjiGPT/IwCgYIKoZIzj0EAwIwXjEfMB0GA1UEAwwWeHh4eHh4eHh4eHh4eHh4eHh4eHh4eDE7MDkGA1UECgwyY29pbm9zIHJldm9rZWQgZW1TaWduIEVDQyBSb290IENBIC0gRzMgcGxhY2Vob2xkZXIwHhcNMjYxMDIxMTI1NjQzWhcNMzYxMDE4MTI1NjQzWjBeMR8wHQYDVQQDDBZ4eHh4eHh4eHh4eHh4eHh4eHh4eHh4MTswOQYDVQQKDDJjb2lub3MgcmV2b2tlZCBlbVNpZ24gRUNDIFJvb3QgQ0EgLSBHMyBwbGFjZWhvbGRlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABBBYruwA2K1haT213dKQAOYRE5Gdy1PMXpM7V57BH6VwUToz9hkWTCXqeOr7/NctfY1fpqbT+tcKl0/OnTVwZuO3ePtUkTvREL/fuVKd9LTU/eTMT1Pqf2GQfVTmkS8C76NTMFEwHQYDVR0OBBYEFARKTDRI5W1qeguIYelguHqh3gvBMB8GA1UdIwQYMBaAFARKTDRI5W1qeguIYelguHqh3gvBMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDaAAwZQIwIW/6zsZDBk7LGTetfJJzKqXbhsvMo+4ykb8JSHjLn5zoIsuyBPGvox71gdDPcttgAjEAu3xr0zjPLGQnlM4cwgv6mKTgiiXbt7HneYNN2hu/DvSuCj99c0KuGKEyfHGqotCL",
};

const bin = process.argv[2];
const buf = readFileSync(bin);
let patched = false;

for (const [cn, placeholder] of Object.entries(distrust)) {
  const pem = getCACertificates("bundled").find(
    (p) => new X509Certificate(p).subject.split("\n").includes(`CN=${cn}`),
  );
  if (!pem) {
    console.log(`${cn}: not in bun's root store, nothing to do`);
    continue;
  }
  const der = new X509Certificate(pem).raw;
  const repl = Buffer.from(placeholder, "base64");
  if (repl.length !== der.length)
    throw new Error(`${cn}: placeholder is ${repl.length} bytes, need ${der.length}`);
  const at = buf.indexOf(der);
  if (at < 0 || buf.indexOf(der, at + 1) >= 0)
    throw new Error(`${cn}: expected exactly one copy in ${bin}`);
  repl.copy(buf, at);
  patched = true;
  console.log(`${cn}: replaced at offset ${at}`);
}

if (patched) writeFileSync(bin, buf);
