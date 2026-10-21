// Bun (1.4+) compiles Mozilla's root store into its binary as DER, and NODE_USE_SYSTEM_CA
// only adds to it. Until a Bun release drops a distrusted root, overwrite its
// DER in place with a same-length self-signed placeholder whose key was thrown
// away (zeroing it instead makes every TLS handshake fail).
//
// Usage: bun bun-distrust.ts <path to a bun binary> (not the one running it)
import { readFileSync, writeFileSync } from "node:fs";

const distrust = [
  {
    // eMudhra intermediate key compromise, CVE-2026-111943.
    // sha256 86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
    name: "emSign ECC Root CA - G3",
    der: "MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xySfvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuBzhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWBCUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD+JbNR6iC8hZVdyR+EhCVBCyj",
    placeholder:
      "MIICTjCCAdSgAwIBAgIUfFrc+EjEsB3lBo+k60ijjiGPT/IwCgYIKoZIzj0EAwIwXjEfMB0GA1UEAwwWeHh4eHh4eHh4eHh4eHh4eHh4eHh4eDE7MDkGA1UECgwyY29pbm9zIHJldm9rZWQgZW1TaWduIEVDQyBSb290IENBIC0gRzMgcGxhY2Vob2xkZXIwHhcNMjYxMDIxMTI1NjQzWhcNMzYxMDE4MTI1NjQzWjBeMR8wHQYDVQQDDBZ4eHh4eHh4eHh4eHh4eHh4eHh4eHh4MTswOQYDVQQKDDJjb2lub3MgcmV2b2tlZCBlbVNpZ24gRUNDIFJvb3QgQ0EgLSBHMyBwbGFjZWhvbGRlcjB2MBAGByqGSM49AgEGBSuBBAAiA2IABBBYruwA2K1haT213dKQAOYRE5Gdy1PMXpM7V57BH6VwUToz9hkWTCXqeOr7/NctfY1fpqbT+tcKl0/OnTVwZuO3ePtUkTvREL/fuVKd9LTU/eTMT1Pqf2GQfVTmkS8C76NTMFEwHQYDVR0OBBYEFARKTDRI5W1qeguIYelguHqh3gvBMB8GA1UdIwQYMBaAFARKTDRI5W1qeguIYelguHqh3gvBMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDaAAwZQIwIW/6zsZDBk7LGTetfJJzKqXbhsvMo+4ykb8JSHjLn5zoIsuyBPGvox71gdDPcttgAjEAu3xr0zjPLGQnlM4cwgv6mKTgiiXbt7HneYNN2hu/DvSuCj99c0KuGKEyfHGqotCL",
  },
];

const bin = process.argv[2];
const buf = readFileSync(bin);
let patched = false;

for (const { name, der: d, placeholder } of distrust) {
  const der = Buffer.from(d, "base64");
  const repl = Buffer.from(placeholder, "base64");
  if (repl.length !== der.length)
    throw new Error(`${name}: placeholder is ${repl.length} bytes, need ${der.length}`);
  const at = buf.indexOf(der);
  if (at < 0) {
    console.log(`${name}: not in ${bin}, nothing to do`);
    continue;
  }
  if (buf.indexOf(der, at + 1) >= 0)
    throw new Error(`${name}: more than one copy in ${bin}`);
  repl.copy(buf, at);
  patched = true;
  console.log(`${name}: replaced at offset ${at}`);
}

if (patched) writeFileSync(bin, buf);
