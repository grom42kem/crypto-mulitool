import * as bip39 from "bip39";
import { BIP32Factory, type BIP32Interface } from "bip32";
import * as ecc from "@noble/secp256k1";
import * as bitcoin from "bitcoinjs-lib";
import { sha256 } from "@noble/hashes/sha2";
import { hexToBytes, bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { ethers } from "ethers";
import * as rippleKeypairs from "ripple-keypairs";

const bip32 = BIP32Factory(ecc);

type Coin = "BTC" | "ETH" | "LTC" | "DOGE" | "XRP";
type Mode = "mnemonic" | "brain";

type Row = {
  coin: Coin;
  index: number;
  path: string;
  address: string;
  pubkeyHex: string;
  privateOut?: string;
};

type ExportJson = {
  mode: Mode;
  createdAt: string;
  count: number;
  derivationPaths: Record<string, string>;
  mnemonic?: {
    mnemonic: string;
    passphrase?: string;
    valid: boolean;
  };
  brainWallet?: {
    input: string;
    normalize: "none" | "trim" | "trim-lower";
    sha256Hex: string;
  };
  rows: Row[];
};

const NETWORK_LTC: bitcoin.Network = {
  messagePrefix: "\x19Litecoin Signed Message:\n",
  bech32: "ltc",
  bip32: { public: 0x019da462, private: 0x019d9cfe }, // xpub/xprv-like for LTC
  pubKeyHash: 0x30,
  scriptHash: 0x32,
  wif: 0xb0
};

const NETWORK_DOGE: bitcoin.Network = {
  messagePrefix: "\x19Dogecoin Signed Message:\n",
  bech32: "doge",
  bip32: { public: 0x02facafd, private: 0x02fac398 }, // dgub/dgpv (Dogecoin)
  pubKeyHash: 0x1e,
  scriptHash: 0x16,
  wif: 0x9e
};

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Element not found: #${id}`);
  return el;
}

function getStr(id: string): string {
  return (($(id) as HTMLInputElement | HTMLTextAreaElement).value ?? "").toString();
}

function setStr(id: string, v: string) {
  (($(id) as HTMLInputElement | HTMLTextAreaElement).value as any) = v;
}

function setStatus(kind: "ok" | "err" | "info", msg: string) {
  const el = $("status");
  el.classList.remove("status-ok", "status-err");
  if (kind === "ok") el.classList.add("status-ok");
  if (kind === "err") el.classList.add("status-err");
  el.textContent = msg;
}

function normalizeMnemonic(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

function applyIndex(pathTemplate: string, index: number): string {
  if (pathTemplate.includes("{index}")) return pathTemplate.replaceAll("{index}", String(index));
  return pathTemplate;
}

function deriveNodeFromSeed(seed: Uint8Array, path: string): BIP32Interface {
  const root = bip32.fromSeed(Buffer.from(seed));
  return root.derivePath(path);
}

function btcLikeRowFromPriv(
  coin: "BTC" | "LTC" | "DOGE",
  index: number,
  path: string,
  privKey32: Uint8Array,
  showPriv: boolean
): Row[] {
  const network =
    coin === "BTC" ? bitcoin.networks.bitcoin : coin === "LTC" ? NETWORK_LTC : NETWORK_DOGE;

  const privBuf = Buffer.from(privKey32);

  const pairC = bitcoin.ECPair.fromPrivateKey(privBuf, { compressed: true, network });
  const pairU = bitcoin.ECPair.fromPrivateKey(privBuf, { compressed: false, network });

  const addrC = bitcoin.payments.p2pkh({ pubkey: pairC.publicKey, network }).address ?? "";
  const addrU = bitcoin.payments.p2pkh({ pubkey: pairU.publicKey, network }).address ?? "";

  const rows: Row[] = [];
  rows.push({
    coin,
    index,
    path,
    address: `${addrC} (compressed)`,
    pubkeyHex: Buffer.from(pairC.publicKey).toString("hex"),
    privateOut: showPriv ? `${pairC.toWIF()} (WIF compressed)` : undefined
  });
  rows.push({
    coin,
    index,
    path,
    address: `${addrU} (uncompressed)`,
    pubkeyHex: Buffer.from(pairU.publicKey).toString("hex"),
    privateOut: showPriv ? `${pairU.toWIF()} (WIF uncompressed)` : undefined
  });
  return rows;
}

function ethRowFromPriv(index: number, path: string, privKey32: Uint8Array, showPriv: boolean): Row {
  const w = new ethers.Wallet(bytesToHex(privKey32));
  return {
    coin: "ETH",
    index,
    path,
    address: w.address,
    pubkeyHex: w.publicKey.replace(/^0x/, ""),
    privateOut: showPriv ? w.privateKey : undefined
  };
}

function xrpRowFromPriv(index: number, path: string, privKey32: Uint8Array, showPriv: boolean): Row {
  const entropy = Buffer.from(privKey32.slice(0, 16));
  const seed = rippleKeypairs.generateSeed({ entropy });
  const kp = rippleKeypairs.deriveKeypair(seed);
  const address = rippleKeypairs.deriveAddress(kp.publicKey);
  return {
    coin: "XRP",
    index,
    path,
    address,
    pubkeyHex: kp.publicKey,
    privateOut: showPriv ? `seed=${seed}\nprivateKey=${kp.privateKey}` : undefined
  };
}

function parseCount(): number {
  const raw = getStr("count").trim();
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 1 || n > 50) throw new Error("Count must be within 1..50");
  return Math.floor(n);
}

function activeMode(): Mode {
  return $("paneMnemonic").classList.contains("pane-active") ? "mnemonic" : "brain";
}

function showPrivEnabled(): boolean {
  return getStr("showPriv") === "yes";
}

function getPaths(): Record<Coin, string> {
  return {
    BTC: getStr("path_btc").trim(),
    ETH: getStr("path_eth").trim(),
    LTC: getStr("path_ltc").trim(),
    DOGE: getStr("path_doge").trim(),
    XRP: getStr("path_xrp").trim()
  };
}

function ensurePathLooksOk(path: string) {
  if (!path.startsWith("m/")) throw new Error(`Derivation path must start with "m/": ${path}`);
  if (!/^[m0-9\/'\-{}index]+$/i.test(path.replaceAll("{index}", "index"))) {
    // мягкая проверка на мусор; реальную проверку сделает bip32.derivePath
  }
}

function render(rows: Row[], json: ExportJson) {
  const tbody = $("resultTbody");
  tbody.textContent = "";

  const privVisible = showPrivEnabled();
  const privColHeader = (document.querySelector("th.privcol") as HTMLTableCellElement | null);
  if (privColHeader) privColHeader.style.display = privVisible ? "" : "none";

  for (const r of rows) {
    const tr = document.createElement("tr");
    const cells: Array<{ v: string; mono?: boolean; hide?: boolean }> = [
      { v: r.coin },
      { v: String(r.index), mono: true },
      { v: r.path, mono: true },
      { v: r.address, mono: true },
      { v: r.pubkeyHex, mono: true },
      { v: r.privateOut ?? "", mono: true, hide: !privVisible }
    ];
    for (const c of cells) {
      const td = document.createElement("td");
      if (c.hide) td.style.display = "none";
      if (c.mono) {
        const code = document.createElement("code");
        code.textContent = c.v;
        td.appendChild(code);
      } else {
        td.textContent = c.v;
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }

  setStr("jsonOut", JSON.stringify(json, null, 2));
}

function brainNormalize(input: string, mode: "none" | "trim" | "trim-lower"): string {
  if (mode === "none") return input;
  if (mode === "trim") return input.trim();
  return input.trim().toLowerCase();
}

function deriveFromMnemonic(): { seed: Uint8Array; jsonMnemonic: ExportJson["mnemonic"] } {
  const m = normalizeMnemonic(getStr("mnemonic"));
  const passphrase = getStr("passphrase");
  const valid = bip39.validateMnemonic(m);
  if (!valid) throw new Error("Invalid mnemonic (check words and order).");
  const seed = bip39.mnemonicToSeedSync(m, passphrase);
  return {
    seed: new Uint8Array(seed),
    jsonMnemonic: { mnemonic: m, passphrase: passphrase ? passphrase : undefined, valid }
  };
}

function deriveFromBrain(): { masterPriv32: Uint8Array; jsonBrain: ExportJson["brainWallet"] } {
  const raw = getStr("brainText");
  const normMode = getStr("brainNormalize") as "none" | "trim" | "trim-lower";
  const normalized = brainNormalize(raw, normMode);
  const digest = sha256(utf8ToBytes(normalized));
  const shaHex = bytesToHex(digest);
  // Приведение к валидному приватному ключу: если 0 или >=n, домешиваем.
  let priv = digest;
  let counter = 0;
  while (!ecc.utils.isValidPrivateKey(priv)) {
    counter++;
    priv = sha256(new Uint8Array([...priv, counter & 0xff]));
    if (counter > 50) throw new Error("Failed to derive a valid private key from the input string.");
  }
  return {
    masterPriv32: priv,
    jsonBrain: { input: normalized, normalize: normMode, sha256Hex: shaHex }
  };
}

function compute(): { rows: Row[]; json: ExportJson } {
  const mode = activeMode();
  const count = parseCount();
  const showPriv = showPrivEnabled();
  const paths = getPaths();
  for (const p of Object.values(paths)) ensurePathLooksOk(p);

  const rows: Row[] = [];
  let jsonMnemonic: ExportJson["mnemonic"] | undefined;
  let jsonBrain: ExportJson["brainWallet"] | undefined;

  if (mode === "mnemonic") {
    const { seed, jsonMnemonic: jm } = deriveFromMnemonic();
    jsonMnemonic = jm;

    for (let i = 0; i < count; i++) {
      const btcPath = applyIndex(paths.BTC, i);
      const ethPath = applyIndex(paths.ETH, i);
      const ltcPath = applyIndex(paths.LTC, i);
      const dogePath = applyIndex(paths.DOGE, i);
      const xrpPath = applyIndex(paths.XRP, i);

      const btcNode = deriveNodeFromSeed(seed, btcPath);
      const ethNode = deriveNodeFromSeed(seed, ethPath);
      const ltcNode = deriveNodeFromSeed(seed, ltcPath);
      const dogeNode = deriveNodeFromSeed(seed, dogePath);
      const xrpNode = deriveNodeFromSeed(seed, xrpPath);

      if (!btcNode.privateKey || !ethNode.privateKey || !ltcNode.privateKey || !dogeNode.privateKey || !xrpNode.privateKey)
        throw new Error("Failed to derive a private key (the path may point to a neutered node).");

      rows.push(...btcLikeRowFromPriv("BTC", i, btcPath, new Uint8Array(btcNode.privateKey), showPriv));
      rows.push(ethRowFromPriv(i, ethPath, new Uint8Array(ethNode.privateKey), showPriv));
      rows.push(...btcLikeRowFromPriv("LTC", i, ltcPath, new Uint8Array(ltcNode.privateKey), showPriv));
      rows.push(...btcLikeRowFromPriv("DOGE", i, dogePath, new Uint8Array(dogeNode.privateKey), showPriv));
      rows.push(xrpRowFromPriv(i, xrpPath, new Uint8Array(xrpNode.privateKey), showPriv));
    }
  } else {
    const { masterPriv32, jsonBrain: jb } = deriveFromBrain();
    jsonBrain = jb;

    // Для brain wallet делаем "псевдо-HD": index → SHA256(masterPriv||index||coin)
    const coinSalt: Record<Coin, string> = {
      BTC: "BTC",
      ETH: "ETH",
      LTC: "LTC",
      DOGE: "DOGE",
      XRP: "XRP"
    };

    for (let i = 0; i < count; i++) {
      for (const coin of Object.keys(paths) as Coin[]) {
        const path = applyIndex(paths[coin], i);
        const material = new Uint8Array([
          ...masterPriv32,
          ...utf8ToBytes("|"),
          ...utf8ToBytes(coinSalt[coin]),
          ...utf8ToBytes("|"),
          ...utf8ToBytes(String(i)),
          ...utf8ToBytes("|"),
          ...utf8ToBytes(path)
        ]);
        let priv = sha256(material);
        let tries = 0;
        while (!ecc.utils.isValidPrivateKey(priv)) {
          tries++;
          priv = sha256(new Uint8Array([...priv, tries & 0xff]));
          if (tries > 50) throw new Error("Brain Wallet: failed to derive a valid private key.");
        }

        if (coin === "BTC") rows.push(...btcLikeRowFromPriv("BTC", i, path, priv, showPriv));
        if (coin === "ETH") rows.push(ethRowFromPriv(i, path, priv, showPriv));
        if (coin === "LTC") rows.push(...btcLikeRowFromPriv("LTC", i, path, priv, showPriv));
        if (coin === "DOGE") rows.push(...btcLikeRowFromPriv("DOGE", i, path, priv, showPriv));
        if (coin === "XRP") rows.push(xrpRowFromPriv(i, path, priv, showPriv));
      }
    }
  }

  const json: ExportJson = {
    mode,
    createdAt: new Date().toISOString(),
    count,
    derivationPaths: { ...paths },
    mnemonic: jsonMnemonic,
    brainWallet: jsonBrain,
    rows
  };

  return { rows, json };
}

async function copyText(s: string) {
  await navigator.clipboard.writeText(s);
}

function rowsToTsv(rows: Row[], includePriv: boolean): string {
  const header = ["coin", "index", "path", "address", "pubkey", ...(includePriv ? ["private"] : [])];
  const lines = [header.join("\t")];
  for (const r of rows) {
    const cols = [r.coin, String(r.index), r.path, r.address, r.pubkeyHex, ...(includePriv ? [r.privateOut ?? ""] : [])];
    lines.push(cols.join("\t"));
  }
  return lines.join("\n");
}

function setupTabs() {
  const tabMnemonic = $("tabMnemonic");
  const tabBrain = $("tabBrain");
  const paneMnemonic = $("paneMnemonic");
  const paneBrain = $("paneBrain");

  const activate = (mode: Mode) => {
    if (mode === "mnemonic") {
      tabMnemonic.classList.add("tab-active");
      tabBrain.classList.remove("tab-active");
      paneMnemonic.classList.add("pane-active");
      paneBrain.classList.remove("pane-active");
    } else {
      tabBrain.classList.add("tab-active");
      tabMnemonic.classList.remove("tab-active");
      paneBrain.classList.add("pane-active");
      paneMnemonic.classList.remove("pane-active");
    }
  };

  tabMnemonic.addEventListener("click", () => activate("mnemonic"));
  tabBrain.addEventListener("click", () => activate("brain"));
}

function setupAutoUpdate() {
  const inputs = [
    "mnemonic",
    "passphrase",
    "brainText",
    "brainNormalize",
    "count",
    "showPriv",
    "autoUpdate",
    "path_btc",
    "path_eth",
    "path_ltc",
    "path_doge",
    "path_xrp"
  ];

  const handler = () => {
    if (getStr("autoUpdate") !== "on") return;
    tryGenerate(false);
  };

  for (const id of inputs) {
    $(id).addEventListener("input", handler);
    $(id).addEventListener("change", handler);
  }
}

let lastRows: Row[] = [];
let lastJson: ExportJson | null = null;

function tryGenerate(userInitiated: boolean) {
  try {
    const { rows, json } = compute();
    lastRows = rows;
    lastJson = json;
    render(rows, json);
    setStatus("ok", userInitiated ? "Generated" : "Ready");
  } catch (e: any) {
    lastRows = [];
    lastJson = null;
    $("resultTbody").textContent = "";
    setStr("jsonOut", "");
    setStatus("err", e?.message ? String(e.message) : "Error");
  }
}

function setupButtons() {
  $("btnGenerate").addEventListener("click", () => tryGenerate(true));
  $("btnClear").addEventListener("click", () => {
    setStr("mnemonic", "");
    setStr("passphrase", "");
    setStr("brainText", "");
    setStr("jsonOut", "");
    $("resultTbody").textContent = "";
    setStatus("info", "Cleared");
  });

  $("btnCopyJson").addEventListener("click", async () => {
    if (!lastJson) return setStatus("err", "Nothing to copy (JSON is empty).");
    await copyText(JSON.stringify(lastJson, null, 2));
    setStatus("ok", "JSON copied to clipboard");
  });

  $("btnCopyTable").addEventListener("click", async () => {
    if (!lastRows.length) return setStatus("err", "Nothing to copy (table is empty).");
    await copyText(rowsToTsv(lastRows, showPrivEnabled()));
    setStatus("ok", "Table (TSV) copied to clipboard");
  });
}

function main() {
  setupTabs();
  setupButtons();
  setupAutoUpdate();
  setStatus("info", "Enter input and click “Generate”");
}

main();

