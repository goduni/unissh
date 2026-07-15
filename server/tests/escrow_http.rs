//! Escrow sign-in e2e (Phase 2, Task 4): the keyless keyset-recovery round trip,
//! driven with the REAL core crypto. A fresh client holding only the password + the
//! Secret Key re-derives K_auth, fetches the encrypted keyset by handle, and opens
//! it — no session, no device. Also proves the enumeration-resistance guarantees:
//! `GET /v1/escrow/params` is always 200 (a real account's params, or a deterministic
//! per-handle decoy of the same shape), and `POST /v1/escrow/fetch` is 403 on any
//! failure (unknown handle / not-enrolled / wrong credential are indistinguishable).

mod common;

use common::{claim_owner, login_v2, make_identity, spawn};
use serde_json::{Value, json};
use unissh_crypto::{KdfParams, derive_key};
use unissh_keychain::{EncryptedKeyset, create_account, derive_escrow_auth_key, unlock_account};
use unissh_server::ids::{b64, unb64};

#[tokio::test]
async fn escrow_keyless_recovery_round_trip() {
    let app = spawn().await;

    // 1. Claim the instance as the owner (handle "owner") and log in for the PUT.
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let device_id = c["device_id"].as_str().unwrap().to_string();
    let access = login_v2(&app, &id, &account_id, &device_id).await;

    // The escrow keyset is a REAL, openable keyset minted by the core, driven
    // INDEPENDENTLY of the claim identity: `create_account` generates its OWN
    // keypair + Secret Key; that blob is uploaded (opaquely) under the owner account.
    // Recovery needs only (password, SecretKey) — exactly what an Emergency Kit holds.
    let password: &[u8] = b"correct horse battery staple";
    let params = KdfParams::recommended();
    let (secret_key, keyset, _unlocked) = create_account(Some(password), params.clone()).unwrap();
    let keyset_bytes = keyset.to_bytes().unwrap();

    // 2. Owner enrolls escrow: derive the Argon key + K_auth from (password, SecretKey)
    //    and PUT the keyset with its escrow credentials (the server stores sha256(K_auth)).
    let argon_key = derive_key(password, &params).unwrap();
    let k_auth = derive_escrow_auth_key(Some(&argon_key), &secret_key);
    let put = app
        .client
        .put(format!("{}/v1/keyset", app.base))
        .header("Authorization", format!("Bearer {access}"))
        .json(&json!({
            "keyset_blob": b64(&keyset_bytes),
            "escrow": {
                "k_auth": b64(k_auth.expose_bytes()),
                "argon_salt": b64(&params.salt),
                "argon_mem_kib": params.mem_kib as i64,
                "argon_iterations": params.iterations as i64,
                "argon_parallelism": params.parallelism as i64,
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "escrow-enrolling keyset PUT should 200");

    // 3. GET /v1/escrow/params?handle=owner → the SAME salt + params it was enrolled with.
    let resp = app
        .client
        .get(format!("{}/v1/escrow/params?handle=owner", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "params for a real handle is 200");
    let p: Value = resp.json().await.unwrap();
    assert_eq!(
        p["argon_salt"],
        b64(&params.salt),
        "the real salt is echoed back"
    );
    assert_eq!(p["argon_mem_kib"], params.mem_kib as i64);
    assert_eq!(p["argon_iterations"], params.iterations as i64);
    assert_eq!(p["argon_parallelism"], params.parallelism as i64);

    // 4. A FRESH client (no session, no device): rebuild the params from the GET,
    //    re-derive K_auth from (password, SecretKey), and fetch the keyset by handle.
    let params2 = KdfParams {
        mem_kib: p["argon_mem_kib"].as_i64().unwrap() as u32,
        iterations: p["argon_iterations"].as_i64().unwrap() as u32,
        parallelism: p["argon_parallelism"].as_i64().unwrap() as u32,
        salt: unb64(p["argon_salt"].as_str().unwrap()).unwrap(),
    };
    let argon_key2 = derive_key(password, &params2).unwrap();
    let k_auth2 = derive_escrow_auth_key(Some(&argon_key2), &secret_key);
    let fetch = app
        .client
        .post(format!("{}/v1/escrow/fetch", app.base))
        .json(&json!({ "handle": "owner", "k_auth": b64(k_auth2.expose_bytes()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(fetch.status(), 200, "the correct K_auth fetches the keyset");
    let fetched: Value = fetch.json().await.unwrap();
    assert_eq!(
        fetched["keyset_blob"].as_str().unwrap(),
        b64(&keyset_bytes),
        "fetch returns exactly the uploaded blob"
    );
    assert_eq!(fetched["generation"], 1);
    assert_eq!(
        fetched["account_id"].as_str().unwrap(),
        account_id,
        "the blob is attributed to the owner account"
    );

    // 5. Decrypt: the fetched blob opens with (password, SecretKey). Keyless recovery.
    let recovered_bytes = unb64(fetched["keyset_blob"].as_str().unwrap()).unwrap();
    let recovered = EncryptedKeyset::from_bytes(&recovered_bytes).unwrap();
    unlock_account(&recovered, Some(password), &secret_key)
        .expect("the recovered keyset opens with the password + Secret Key");

    // 6. NEGATIVE: a wrong K_auth for a real, enrolled handle → 403 (constant-time).
    let bad = app
        .client
        .post(format!("{}/v1/escrow/fetch", app.base))
        .json(&json!({ "handle": "owner", "k_auth": b64(&[0u8; 32]) }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 403, "a wrong K_auth is denied");
}

#[tokio::test]
async fn escrow_params_and_fetch_resist_enumeration() {
    let app = spawn().await;

    // 7. An unknown handle still returns a well-formed params response (200) with a
    //    DETERMINISTIC decoy salt of the same shape as a real one — no enumeration.
    let resp1 = app
        .client
        .get(format!("{}/v1/escrow/params?handle=ghost", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200, "an unknown handle still returns 200");
    let p1: Value = resp1.json().await.unwrap();

    let resp2 = app
        .client
        .get(format!("{}/v1/escrow/params?handle=ghost", app.base))
        .send()
        .await
        .unwrap();
    let p2: Value = resp2.json().await.unwrap();

    // Stable per handle across calls, recommended params, 16-byte salt (same shape).
    // Asserted against `KdfParams::recommended()` (NOT bare literals) so a future
    // `recommended()` bump can't silently split a real enrollment from a decoy.
    assert_eq!(
        p1["argon_salt"], p2["argon_salt"],
        "the decoy salt is stable per handle across calls"
    );
    let rec = KdfParams::recommended();
    assert_eq!(p1["argon_mem_kib"], rec.mem_kib as i64);
    assert_eq!(p1["argon_iterations"], rec.iterations as i64);
    assert_eq!(p1["argon_parallelism"], rec.parallelism as i64);
    let salt = unb64(p1["argon_salt"].as_str().unwrap()).unwrap();
    assert_eq!(
        salt.len(),
        16,
        "the decoy salt is 16 bytes, matching a real salt"
    );

    // The decoy is keyed from a SERVER-PRIVATE secret, NOT from the PUBLIC
    // instance_id. Prove it is unforgeable from public data: recompute what the
    // decoy WOULD be if it were keyed off instance_id (the old, leaky scheme) and
    // assert the real decoy differs. instance_id is served openly by /v1/instance.
    let inst: Value = app
        .client
        .get(format!("{}/v1/instance", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let instance_id = unb64(inst["instance_id"].as_str().unwrap()).unwrap();
    let forgeable = {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::{Digest, Sha256};
        let mut key_material = instance_id.clone();
        key_material.extend_from_slice(b"escrow-params-decoy");
        let key: [u8; 32] = Sha256::digest(&key_material).into();
        let mut mac = <Hmac<Sha256>>::new_from_slice(&key).unwrap();
        mac.update(b"ghost");
        b64(&mac.finalize().into_bytes()[..16])
    };
    assert_ne!(
        p1["argon_salt"].as_str().unwrap(),
        forgeable,
        "the decoy must NOT be forgeable from the public instance_id"
    );

    // A different handle → a different decoy (bound to the handle, not a constant).
    let resp3 = app
        .client
        .get(format!("{}/v1/escrow/params?handle=phantom", app.base))
        .send()
        .await
        .unwrap();
    let p3: Value = resp3.json().await.unwrap();
    assert_ne!(
        p1["argon_salt"], p3["argon_salt"],
        "the decoy salt varies per handle"
    );

    // Fetch on an unknown handle → 403, identical to a wrong-credential rejection.
    let fetch = app
        .client
        .post(format!("{}/v1/escrow/fetch", app.base))
        .json(&json!({ "handle": "ghost", "k_auth": b64(&[0u8; 32]) }))
        .send()
        .await
        .unwrap();
    assert_eq!(fetch.status(), 403, "fetch on an unknown handle is denied");
}

#[tokio::test]
async fn escrow_unenrolled_account_is_indistinguishable() {
    let app = spawn().await;

    // Claim the owner (handle "owner") and upload a REAL keyset — but WITHOUT the
    // `escrow` field, so escrow sign-in is never armed for this generation. This is
    // the sharp case: a genuine, keyset-holding account that simply didn't opt into
    // escrow must be INDISTINGUISHABLE from a handle that doesn't exist at all.
    let id = make_identity();
    let c = claim_owner(&app, &id.payload_b64, &id.sig_b64).await;
    let account_id = c["account_id"].as_str().unwrap().to_string();
    let device_id = c["device_id"].as_str().unwrap().to_string();
    let access = login_v2(&app, &id, &account_id, &device_id).await;

    let password: &[u8] = b"pw";
    let params = KdfParams::recommended();
    let (_secret_key, keyset, _unlocked) = create_account(Some(password), params).unwrap();
    let keyset_bytes = keyset.to_bytes().unwrap();
    let put = app
        .client
        .put(format!("{}/v1/keyset", app.base))
        .header("Authorization", format!("Bearer {access}"))
        .json(&json!({ "keyset_blob": b64(&keyset_bytes) })) // NO "escrow" key → unenrolled
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "a keyset PUT without escrow still 200s");

    // GET params?handle=owner → 200 with a DECOY (recommended params + a 16-byte salt),
    // NOT a real salt (none exists), NOT an error. Stable per handle across calls.
    let resp1 = app
        .client
        .get(format!("{}/v1/escrow/params?handle=owner", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp1.status(),
        200,
        "params for an unenrolled account is still 200"
    );
    let owner1: Value = resp1.json().await.unwrap();
    let owner2: Value = app
        .client
        .get(format!("{}/v1/escrow/params?handle=owner", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rec = KdfParams::recommended();
    assert_eq!(owner1["argon_mem_kib"], rec.mem_kib as i64);
    assert_eq!(owner1["argon_iterations"], rec.iterations as i64);
    assert_eq!(owner1["argon_parallelism"], rec.parallelism as i64);
    assert_eq!(
        unb64(owner1["argon_salt"].as_str().unwrap()).unwrap().len(),
        16,
        "the unenrolled decoy salt is 16 bytes, matching a real salt"
    );
    assert_eq!(
        owner1["argon_salt"], owner2["argon_salt"],
        "the unenrolled decoy salt is stable per handle across calls"
    );

    // Indistinguishable from a handle that does not exist: same-shape decoy, and the
    // salt is per-handle (differs from an unknown handle's decoy — no existence signal).
    let unknown: Value = app
        .client
        .get(format!("{}/v1/escrow/params?handle=nobody", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unknown["argon_mem_kib"], owner1["argon_mem_kib"]);
    assert_eq!(unknown["argon_iterations"], owner1["argon_iterations"]);
    assert_eq!(unknown["argon_parallelism"], owner1["argon_parallelism"]);
    assert_ne!(
        unknown["argon_salt"], owner1["argon_salt"],
        "decoys are per-handle: an unenrolled account and an unknown handle differ"
    );

    // POST fetch?handle=owner with ANY k_auth → 403 (not 500, not a distinguishable
    // error): escrow was never armed, so it is denied exactly like a wrong credential.
    let fetch = app
        .client
        .post(format!("{}/v1/escrow/fetch", app.base))
        .json(&json!({ "handle": "owner", "k_auth": b64(&[0u8; 32]) }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        fetch.status(),
        403,
        "fetch on an unenrolled account is denied, indistinguishable from a wrong credential"
    );
}
