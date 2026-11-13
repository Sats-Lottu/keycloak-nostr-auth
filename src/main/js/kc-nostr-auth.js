import { BunkerSigner } from "nostr-tools/nip46";
import { SimplePool } from "nostr-tools/pool";
import { finalizeEvent, generateSecretKey } from "nostr-tools/pure";
import { authorizationTarget } from "./signer-authorization.mjs";

const form = document.querySelector("#kc-nostr-auth");
const browserButton = document.querySelector("#kc-nostr-auth-browser");
const remoteButton = document.querySelector("#kc-nostr-auth-remote");
const remoteInput = document.querySelector("#kc-nostr-auth-bunker");
const status = document.querySelector("#kc-nostr-auth-status");
const authLink = document.querySelector("#kc-nostr-auth-authorize");
const authOrigin = document.querySelector("#kc-nostr-auth-authorize-origin");
const authBlocked = document.querySelector("#kc-nostr-auth-authorize-blocked");
browserButton.disabled = false;
remoteButton.disabled = false;

function allowedRelay(url) {
    const relay = new URL(url);
    const loopback = location.protocol === "http:" && location.hostname === "localhost" &&
        relay.protocol === "ws:" && relay.hostname === "localhost";
    return (relay.protocol === "wss:" || loopback) && !relay.username && !relay.password && !relay.hash;
}

function parseBunker(value) {
    const url = new URL(value.trim());
    if (url.protocol !== "bunker:" || !/^[0-9a-f]{64}$/.test(url.hostname) ||
        url.username || url.password || url.port || url.pathname || url.hash) {
        throw new Error("Invalid bunker URI");
    }

    const relays = url.searchParams.getAll("relay");
    if (relays.length < 1 || relays.length > 5 || !relays.every(allowedRelay)) {
        throw new Error("Invalid NIP-46 relays");
    }
    return {pubkey: url.hostname, relays: [...new Set(relays)], secret: url.searchParams.get("secret") ?? ""};
}

function clearAuthorization() {
    authLink.hidden = true;
    authLink.removeAttribute("href");
    authOrigin.textContent = "";
    authBlocked.hidden = true;
}

function showAuthorization(url) {
    clearAuthorization();
    const target = authorizationTarget(url, form.dataset.authorizationOrigins ?? "");
    if (!target) {
        authBlocked.hidden = false;
        return;
    }
    authOrigin.textContent = target.origin;
    authLink.href = target.href;
    authLink.hidden = false;
}

class RemoteSignerRelayPool extends SimplePool {
    constructor(key) {
        const signAuth = async event => finalizeEvent(event, key);
        super({allowConnectingToRelay: allowedRelay, automaticallyAuth: () => signAuth});
        this.signAuth = signAuth;
    }

    subscribe(relays, filter, options) {
        return super.subscribe(relays, filter, {...options, onauth: this.signAuth});
    }

    publish(relays, event, options) {
        return super.publish(relays, event, {...options, onauth: this.signAuth});
    }
}

async function remoteSign(event) {
    const bunker = parseBunker(remoteInput.value);
    const key = generateSecretKey();
    const pool = new RemoteSignerRelayPool(key);
    const signer = BunkerSigner.fromBunker(key, bunker, {pool, onauth: showAuthorization, authTimeout: 90_000});
    try {
        const connected = await signer.sendRequest("connect", [
            bunker.pubkey, bunker.secret, "sign_event:27235", JSON.stringify({name: "Nostr Auth", url: location.origin}),
        ]);
        if (connected !== "ack") throw new Error("Remote signer did not acknowledge connection");
        await signer.switchRelays();
        const publicKey = await signer.getPublicKey();
        const signed = await signer.signEvent({...event, created_at: Math.floor(Date.now() / 1000)});
        if (signed.pubkey !== publicKey) throw new Error("Unexpected Nostr signing key");
        return signed;
    } finally {
        await signer.close();
        pool.destroy();
        key.fill(0);
        clearAuthorization();
    }
}

async function verifyWith(signEvent) {
    browserButton.disabled = true;
    remoteButton.disabled = true;
    clearAuthorization();
    status.textContent = form.dataset.signing;
    try {
        const url = form.dataset.verify;
        const nonce = form.elements.nonce.value;
        const encoder = new TextEncoder();
        const digest = await crypto.subtle.digest("SHA-256", encoder.encode(nonce));
        const hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
        const event = await signEvent({
            created_at: Math.floor(Date.now() / 1000),
            kind: 27235,
            content: "",
            tags: [["u", url], ["method", "POST"], ["payload", hash]],
        });
        const encoded = btoa(String.fromCharCode(...encoder.encode(JSON.stringify(event))));
        const response = await fetch(url, {
            method: "POST",
            headers: {Authorization: "Nostr " + encoded, "Content-Type": "text/plain"},
            body: nonce,
            cache: "no-store",
            redirect: "error",
        });
        if (response.status === 429) {
            status.textContent = form.dataset.rateLimited;
        } else {
            if (response.status !== 204) throw new Error("Nostr authorization failed");
            remoteInput.value = "";
            form.submit();
            return;
        }
    } catch {
        status.textContent = form.dataset.failed;
    }
    browserButton.disabled = false;
    remoteButton.disabled = false;
}

form.addEventListener("submit", event => event.preventDefault());

browserButton.addEventListener("click", () => {
    if (!window.nostr?.signEvent || !window.crypto?.subtle) {
        status.textContent = form.dataset.missing;
        return;
    }
    void verifyWith(event => window.nostr.signEvent(event));
});

remoteButton.addEventListener("click", () => {
    if (!remoteInput.value.trim()) {
        remoteInput.focus();
        return;
    }
    void verifyWith(remoteSign);
});
