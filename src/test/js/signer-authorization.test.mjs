import assert from "node:assert/strict";
import { test } from "node:test";

import { authorizationTarget } from "../../main/js/signer-authorization.mjs";

test("keeps the authorization URL and displays its canonical HTTPS origin", () => {
    const target = authorizationTarget("https://bücher.example:8443/approve?token=test", "");
    assert.equal(target.origin, "https://xn--bcher-kva.example:8443");
    assert.equal(target.href, "https://xn--bcher-kva.example:8443/approve?token=test");
});

test("rejects invalid, non-HTTPS and credential-bearing addresses", () => {
    for (const address of ["not a URL", "http://signer.example", "https://user@signer.example", "javascript:void(0)"]) {
        assert.equal(authorizationTarget(address, ""), null);
    }
});

test("requires an exact origin when the administrator configures an allowlist", () => {
    const origins = "https://other.example:8443, https://SIGNER.example:443/";
    assert.equal(authorizationTarget("https://signer.example/approve", origins)?.origin, "https://signer.example");
    assert.equal(authorizationTarget("https://signer.example:8443/approve", origins), null);
    assert.equal(authorizationTarget("https://signer.example.invalid/approve", origins), null);
    assert.equal(authorizationTarget("https://signer.example/approve", "https://signer.example/approve"), null);
    assert.equal(authorizationTarget("https://signer.example/approve", "invalid"), null);
});
