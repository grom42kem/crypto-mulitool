import { BIP32Factory } from "bip32";
import * as ecc from "@bitcoinerlab/secp256k1";
import { Buffer } from "buffer";

// Match browser-ish globals provided by our esbuild inject shim
globalThis.Buffer = Buffer;

const bip32 = BIP32Factory(ecc);
const node = bip32.fromSeed(Buffer.alloc(32, 1)).derivePath("m/44'/0'/0'/0/0");

if (!node.privateKey) throw new Error("missing privateKey");
if (!node.publicKey || node.publicKey.length < 33) throw new Error("bad publicKey");

console.log("smoke ok", node.publicKey.length);
