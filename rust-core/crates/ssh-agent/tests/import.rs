//! Tests of importing private keys from classic PEM formats
//! (PKCS#1 / PKCS#8 / SEC1) into canonical OpenSSH via
//! [`normalize_private_key_to_openssh`]. The vectors were generated with
//! ssh-keygen/openssl (one-off test keys) — we check that the public key after
//! conversion matches the reference and that the normalized private key is
//! accepted by the agent.

use ed25519_dalek::pkcs8::DecodePrivateKey;
use unissh_ssh_agent::ssh_key::{self, PrivateKey};
use unissh_ssh_agent::{
    normalize_private_key_to_openssh, normalize_private_key_with_passphrase, AgentError,
    InMemoryAgent,
};

// --- The same RSA-2048 in PKCS#1 (BEGIN RSA PRIVATE KEY) and PKCS#8 ---
const RSA_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Nz6qk+yFoEL3gBixnDidk4jLEIvDk25O5yTpEMmmIHa/o8x
MVd1pYkXbh2IZwy/SrTyUqWDvAif5Monzuti7kT/0/VMldm4X/JNhfr6K+p5Y+oJ
61cHMNzW+PVe/SFCdqYeFZaa4v0feSKfc3pdTawrVyopGQ9Onj/W2QS5OGdwFblq
zqzaJKZWA9qvFy90qmTpliSxxr7mY5C/RMwqiXt9+4DtPeJBRK9BNZ8AkMGbwgP8
/WW6yqYDd1L62AxLA+uNymQWf6t9nWaSf03mREe1zVXS/HFIVeSPBDej80gULfJt
3ftjQNTem6PxSqAOdHWBS2PCtrRVClMSnLcvPwIDAQABAoIBAACnSj+Uc33n3dZO
K1ZHm5DUJS90pSyp/x0hfYUlkosmqEmbamshAeAtGAK4eVCvUc+c+qcEsAeW3Wn3
dUlhHaI4QpH7rXIkGm+rjoBxGQ8XQlWW7ojSob2zA/KxvsrQVmXBNTRpnE/47T88
EGbjnbE2VJgxgdyNu/4X5yKQZ2jnYaONCPPozU9/P94oXj+huOl8LQQ3P+dukcMu
13X/Bdbo7FjmHL0Fci7Ii33PZm350lcfeIuOIYltglZNSTUPrJy9FIrQ8H8BY6yM
GKrI6UMbMWSopJdwEi99pCoPGr7O7frz9Ly7Cpl1axj9WfsA/G6MZMjnFLAyvYKv
43AdHPECgYEA9+pbS3o9LwMok/cqPHzrYnK1Vn0BHH10HqeXpuwJE4lsps2Fo2LH
Xz1Wi9+/JY1jObnadWMkkAvx1ZUsp4FkcLOr/HDZOYF+uaEw+gKRVpOlWCLICjlm
GjeP5X72aoHUJ8PNBvjqAVp8ylKBFE9ukLzZsVb4FBPS+bMu63pJ8YsCgYEA16yb
cUO9N2uzlQMAUckIDyoUnHptRdcHapXDneZd/SnKzcU/hD/S/RcVqQB1YANpZyeM
/bNzSfkWcxVkaWC7Z2maHn/DXm3ZhFT15I5ELAbdq37e+vUbdvWGcBuCzmtwFdIl
yeqx6BzHoUWaVuPAZ5Z5VJQoTH1OhHuQFJUxx50CgYEAlLu/JdsiVdAZShwg9MUl
Gp0i+c5pGkSRo8p8CyLUlyn9S11F7a3XWuYbxDLqJIdcnkdILuDaEKl53t9uONhB
//NrHTo+uGdeNdPk5DkiJMTTj7reNHQXM2deJxsyjtdxBqJLoQE4srMs5tz0n9C/
zoneOKyqjLEQA8piPdfSAN0CgYASvq3D6l9HsdSp3tjoQtCwgLfJ4dodd9LtMJcP
4jXJCxjVSY97rxBnbtozFhcdgS5oCMf4ROCATWXmGrXfcsjW9BaxD+mrC2EcX0X/
112VdgNOJHi81xDMBgrpM3rq9euH+fvO0NcllVrEaYhAhQrz9eAVucrG2x035oVf
RJhPAQKBgQCcjnPyuFuq3zIIAVSA1ryvtFW5n95eij/AABeBhKjcsKKC9TyPy145
5mXOxoXcTAT4qbLxLc34BVjC49DoquOVble2OBVWWNng+x+AKyJXVaih7o+mTt6Y
otqRUgfM3Hf3sdwr66X6ltp1sQlzggaVlhH3pBsCWTPQ6nBzWEgiPA==
-----END RSA PRIVATE KEY-----";

const RSA_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQ3PqqT7IWgQve
AGLGcOJ2TiMsQi8OTbk7nJOkQyaYgdr+jzExV3WliRduHYhnDL9KtPJSpYO8CJ/k
yifO62LuRP/T9UyV2bhf8k2F+vor6nlj6gnrVwcw3Nb49V79IUJ2ph4Vlpri/R95
Ip9zel1NrCtXKikZD06eP9bZBLk4Z3AVuWrOrNokplYD2q8XL3SqZOmWJLHGvuZj
kL9EzCqJe337gO094kFEr0E1nwCQwZvCA/z9ZbrKpgN3UvrYDEsD643KZBZ/q32d
ZpJ/TeZER7XNVdL8cUhV5I8EN6PzSBQt8m3d+2NA1N6bo/FKoA50dYFLY8K2tFUK
UxKcty8/AgMBAAECggEAAKdKP5Rzfefd1k4rVkebkNQlL3SlLKn/HSF9hSWSiyao
SZtqayEB4C0YArh5UK9Rz5z6pwSwB5bdafd1SWEdojhCkfutciQab6uOgHEZDxdC
VZbuiNKhvbMD8rG+ytBWZcE1NGmcT/jtPzwQZuOdsTZUmDGB3I27/hfnIpBnaOdh
o40I8+jNT38/3iheP6G46XwtBDc/526Rwy7Xdf8F1ujsWOYcvQVyLsiLfc9mbfnS
Vx94i44hiW2CVk1JNQ+snL0UitDwfwFjrIwYqsjpQxsxZKikl3ASL32kKg8avs7t
+vP0vLsKmXVrGP1Z+wD8boxkyOcUsDK9gq/jcB0c8QKBgQD36ltLej0vAyiT9yo8
fOticrVWfQEcfXQep5em7AkTiWymzYWjYsdfPVaL378ljWM5udp1YySQC/HVlSyn
gWRws6v8cNk5gX65oTD6ApFWk6VYIsgKOWYaN4/lfvZqgdQnw80G+OoBWnzKUoEU
T26QvNmxVvgUE9L5sy7reknxiwKBgQDXrJtxQ703a7OVAwBRyQgPKhScem1F1wdq
lcOd5l39KcrNxT+EP9L9FxWpAHVgA2lnJ4z9s3NJ+RZzFWRpYLtnaZoef8NebdmE
VPXkjkQsBt2rft769Rt29YZwG4LOa3AV0iXJ6rHoHMehRZpW48BnlnlUlChMfU6E
e5AUlTHHnQKBgQCUu78l2yJV0BlKHCD0xSUanSL5zmkaRJGjynwLItSXKf1LXUXt
rdda5hvEMuokh1yeR0gu4NoQqXne32442EH/82sdOj64Z1410+TkOSIkxNOPut40
dBczZ14nGzKO13EGokuhATiysyzm3PSf0L/Oid44rKqMsRADymI919IA3QKBgBK+
rcPqX0ex1Kne2OhC0LCAt8nh2h130u0wlw/iNckLGNVJj3uvEGdu2jMWFx2BLmgI
x/hE4IBNZeYatd9yyNb0FrEP6asLYRxfRf/XXZV2A04keLzXEMwGCukzeur164f5
+87Q1yWVWsRpiECFCvP14BW5ysbbHTfmhV9EmE8BAoGBAJyOc/K4W6rfMggBVIDW
vK+0Vbmf3l6KP8AAF4GEqNywooL1PI/LXjnmZc7GhdxMBPipsvEtzfgFWMLj0Oiq
45VuV7Y4FVZY2eD7H4ArIldVqKHuj6ZO3pii2pFSB8zcd/ex3CvrpfqW2nWxCXOC
BpWWEfekGwJZM9DqcHNYSCI8
-----END PRIVATE KEY-----";

const RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQ3PqqT7IWgQveAGLGcOJ2TiMsQi8OTbk7nJOkQyaYgdr+jzExV3WliRduHYhnDL9KtPJSpYO8CJ/kyifO62LuRP/T9UyV2bhf8k2F+vor6nlj6gnrVwcw3Nb49V79IUJ2ph4Vlpri/R95Ip9zel1NrCtXKikZD06eP9bZBLk4Z3AVuWrOrNokplYD2q8XL3SqZOmWJLHGvuZjkL9EzCqJe337gO094kFEr0E1nwCQwZvCA/z9ZbrKpgN3UvrYDEsD643KZBZ/q32dZpJ/TeZER7XNVdL8cUhV5I8EN6PzSBQt8m3d+2NA1N6bo/FKoA50dYFLY8K2tFUKUxKcty8/";

// --- The same ECDSA nistp256 in SEC1 (BEGIN EC PRIVATE KEY) and PKCS#8 ---
const EC_SEC1: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMEy4osLlE4d1sUqXj271OcrWpkCyglTQ9QSUpP9/m7WoAoGCCqGSM49
AwEHoUQDQgAEdz+R9yFpJfYqjCT9+/GZajyUKvzWSOiRdOjnL00bOsaXwBbjH9C/
oYMQmwLE1N1FwPJkuXp+BG3AuOULr+v9SA==
-----END EC PRIVATE KEY-----";

const EC_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwTLiiwuUTh3WxSpe
PbvU5ytamQLKCVND1BJSk/3+btahRANCAAR3P5H3IWkl9iqMJP378ZlqPJQq/NZI
6JF06OcvTRs6xpfAFuMf0L+hgxCbAsTU3UXA8mS5en4EbcC45Quv6/1I
-----END PRIVATE KEY-----";

const EC_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHc/kfchaSX2Kowk/fvxmWo8lCr81kjokXTo5y9NGzrGl8AW4x/Qv6GDEJsCxNTdRcDyZLl6fgRtwLjlC6/r/Ug=";

// --- Ed25519 in PKCS#8 (ssh-keygen does not read it, but we do) ---
const ED_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEII7RqXdCM82vWxqE0Z8zNchaT7DaF/at25Id8DZJ7xFa
-----END PRIVATE KEY-----";

// --- Encrypted PKCS#8 (PBES2, passphrase "secret"). This is the same key as
//     RSA_PKCS1 → after decryption the public key == RSA_PUB. ---
const ENC_PKCS8: &str = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIH3tgEWfsFCICAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCJBkMOuP+J5ngwpiBBV0A3BIIE
0D8B8lwkfQwFHV2m6nttuTkyg4XK60NA01H91+dRVCg5N4JGlPBioY4WJvgaTnaA
5a/VgZXQtZ+8vp5UZ0jU2OBNv+6XTkMnRPMDI5uDec89DEuSFpOGDI5iD0ZwE1M0
E67xGiHhCrbACoI+EieVyAjJOCW7IzsTZjDCkxZ2eAeBUpT2HcQh2CjM6uGdH27r
eLPUNjgxE0tgrPK3Hqmk82LTLApkGTsadV+sQnR09d8Ga4gHUfBErdGJEA3FKaZ7
DYMeVhd13I4Ou5AiYujtOSHHUo+eu8IwImYPxGWIax1yk/yHTZ0lIkOcOSOsIUJM
dOUYBejJsOiSWDO8ksAzZay/VeN1Zy4lcM3dudW5dLiUYOwnoS1AalSVSdiRLTcW
9BL1mJlOifTwqg/b4vhtLuHeyaAU7iYib5R14PZKoFB2An/HgmpUbEfZZcLYgVoa
7hhbOoi0MyVxqUnficEZjP3FkfMM/0AdX3jaEA8qFpgE7fH3Jfxm+mVXA4upX8ag
8ns6ZATyQEY7ezVjAz3GMlSy4iGRL92UZ5mKQgi4/cWg+mOT0fvyyQgQMP+03ncb
iOkZj6ABzW/mPsv7uRVMjNwlDtPZU92j+BMVvhwq/ETzvDuV4u2sbosshpB5+DoM
ggkzw/CpCZeXUG8AbRuSJUxBFE6Gpdw4nVYX9HHrJ8bm2NPiX8ykRgIq809PsVI9
IlHjyizsmFrS9beyQTyn2YhloPMPoqWyP6EGu5iYNuM8KrZTipwANyLBvapbCMd/
9y+H+96d6ThdnksBG59EkWCyV8Blf1oSGfzpbkqMMNlVIZVCstNV3tNFHJTi0Gs6
O17MtsJ/FwYhoKRBLIPCDeNs12kFxgRtl6rnM1yLDLjy5ZN+/G6R0XKsP8hU2C28
d9UR9e1EZu9icE7gYZiuUxrzVYVICj2groZS8682BBuJoz7N/w/LjutfdD104Y0s
4bIozpfBLZL0YMzJXw51r3OT++wnK7zmiCyqtNut4suvavj9sUoVBB5ZdK5GlTrm
AiphP6b7ukZJ8TaW6CMY1DFMev2v1qw3Wp4pl8VXkwXAuFM0aP6LNQoKxNSIzsXM
nadOiznQFiHG30EDlSXfD1sqy3GUd49lj2OcuIoU+wgcEWKxoTx3LahjCC1mp8A3
1aRlb4cGC0TfrFnUDbZoe77PHyjsxNyxZ+OOu70WSM5SEwAJohVNaRoFaCWJOWNg
vLGFmgE62MJ8ZB9khZXciSIT9zX3Xpdx/eUpSOIIW+qpTkbV0lfprg4bIqcT82Gf
gvzjXOqtMc5LG0dBao9a7PM4HrCJQl7DAwKKvTByYAp0yuLnNS25BYgkEDYrnsxm
BFMm+kBpjVdfCcAr6JvpL64Em3mpNXomekqSqnukDfqpfavCZomNXLI9EpFhJwO9
ueyN3FMnp4INWx3WaoO+D9gCkDfCYUDTwwMM2V/rlY0+ohzxVdCQEVHhh2ZsR4VY
ZXX5EILd9H2l2EKYk41bdPqLPa+/rBdHVAhbWBCdM7eL0vFhA5D8j0bcCFOfGuc9
aeHzPGStG2/rdvDzcKu+8Ju2SbgZNyGIfTEGa6a47lfbcl6Xdejy9bnTkW8OZnTZ
AJ0GHlmW3eZFIR4GNCpB1WmE8AkLHJmLEjU/FjB6o+2d
-----END ENCRYPTED PRIVATE KEY-----";

// --- Encrypted OpenSSH private key (ed25519, passphrase "secret") ---
const OSSH_ENC_ED: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBhWyUDQ0
LH5fgFmZybFVGsAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDDxyy7jcqQSO7Rp
Z3up+OaKtad5xPLA0fSAt93YICPGAAAAkIahBcpaJCrNyYUPbaaKso44xI2ZYmiSrb92MC
Nlvin/PJJN/GTW2LlzHA099vtHXGRP246MJnvDJKcbBZXuc4Lfkm1nvyYGC6b4C0q324Ck
NhGHKcKs9BW8DCq9KkAc4T8gPe5Gz/NP/jWwaAJWPUt5tJ2qWXWHy8OskCc9/wsspARTE0
bQ+jhbv16Otv7qiw==
-----END OPENSSH PRIVATE KEY-----";

const OSSH_ENC_ED_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDxyy7jcqQSO7RpZ3up+OaKtad5xPLA0fSAt93YICPG";

/// The public key of the normalized private key — material only (`algo base64`),
/// without the comment (OpenSSH keys keep their comment on decryption, ones
/// converted from PKCS do not; it does not matter for the comparison).
fn pub_of(normalized: &str) -> String {
    let key = PrivateKey::from_openssh(normalized).expect("normalized must be valid OpenSSH");
    assert!(!key.is_encrypted());
    let openssh = key.public_key().to_openssh().expect("public to_openssh");
    openssh
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn rsa_pkcs1_imports_and_matches_pub() {
    let out = normalize_private_key_to_openssh(RSA_PKCS1).expect("PKCS#1 RSA must import");
    assert!(out.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert_eq!(pub_of(&out), RSA_PUB);
}

#[test]
fn rsa_pkcs8_imports_and_matches_pub() {
    let out = normalize_private_key_to_openssh(RSA_PKCS8).expect("PKCS#8 RSA must import");
    assert_eq!(pub_of(&out), RSA_PUB);
}

#[test]
fn ec_sec1_imports_and_matches_pub() {
    let out = normalize_private_key_to_openssh(EC_SEC1).expect("SEC1 EC must import");
    assert_eq!(pub_of(&out), EC_PUB);
}

#[test]
fn ec_pkcs8_imports_and_matches_pub() {
    let out = normalize_private_key_to_openssh(EC_PKCS8).expect("PKCS#8 EC must import");
    assert_eq!(pub_of(&out), EC_PUB);
}

#[test]
fn ed25519_pkcs8_imports_and_matches_pub() {
    // We derive the reference directly from the same PKCS#8 via ed25519-dalek.
    let want = ed25519_dalek::SigningKey::from_pkcs8_pem(ED_PKCS8)
        .unwrap()
        .verifying_key()
        .to_bytes();

    let out = normalize_private_key_to_openssh(ED_PKCS8).expect("PKCS#8 Ed25519 must import");
    let key = PrivateKey::from_openssh(&*out).unwrap();
    let got = match key.public_key().key_data() {
        ssh_key::public::KeyData::Ed25519(p) => p.0,
        _ => panic!("expected ed25519"),
    };
    assert_eq!(got, want);
}

#[test]
fn normalized_key_is_usable_by_agent() {
    // The imported PKCS#1 key must work in the agent (load + sign).
    let out = normalize_private_key_to_openssh(RSA_PKCS1).unwrap();
    let mut agent = InMemoryAgent::new();
    agent
        .add_from_openssh(b"k".to_vec(), out.as_bytes())
        .unwrap();
    let sig = agent.sign(b"k", b"challenge").expect("must sign");
    assert!(sig.algorithm.starts_with("rsa-sha2"));
}

#[test]
fn already_openssh_is_normalized_idempotently() {
    let once = normalize_private_key_to_openssh(EC_SEC1).unwrap();
    let twice = normalize_private_key_to_openssh(&once).unwrap();
    assert_eq!(pub_of(&once), pub_of(&twice));
    assert_eq!(pub_of(&twice), EC_PUB);
}

#[test]
fn encrypted_pkcs8_without_passphrase_is_encrypted() {
    // Without a passphrase — a signal for the UI to prompt for one.
    let err = normalize_private_key_to_openssh(ENC_PKCS8).unwrap_err();
    assert!(matches!(err, AgentError::Encrypted), "got {err:?}");
}

#[test]
fn encrypted_pkcs8_decrypts_with_passphrase() {
    // With the correct passphrase it decrypts; this is the same key as RSA_PKCS1.
    let out = normalize_private_key_with_passphrase(ENC_PKCS8, Some("secret"))
        .expect("must decrypt PKCS#8");
    assert_eq!(pub_of(&out), RSA_PUB);
}

#[test]
fn encrypted_pkcs8_wrong_passphrase() {
    let err = normalize_private_key_with_passphrase(ENC_PKCS8, Some("nope")).unwrap_err();
    assert!(matches!(err, AgentError::WrongPassphrase), "got {err:?}");
}

#[test]
fn openssh_encrypted_without_passphrase_is_encrypted() {
    let err = normalize_private_key_to_openssh(OSSH_ENC_ED).unwrap_err();
    assert!(matches!(err, AgentError::Encrypted), "got {err:?}");
}

#[test]
fn openssh_encrypted_decrypts_with_passphrase() {
    let out = normalize_private_key_with_passphrase(OSSH_ENC_ED, Some("secret"))
        .expect("must decrypt OpenSSH key");
    assert_eq!(pub_of(&out), OSSH_ENC_ED_PUB);
}

#[test]
fn openssh_encrypted_wrong_passphrase() {
    let err = normalize_private_key_with_passphrase(OSSH_ENC_ED, Some("nope")).unwrap_err();
    assert!(matches!(err, AgentError::WrongPassphrase), "got {err:?}");
}

#[test]
fn legacy_encrypted_pkcs1_reports_legacy() {
    // OpenSSL legacy: the Proc-Type/DEK-Info headers inside BEGIN RSA PRIVATE KEY.
    // Not supported — a dedicated error with a hint (a passphrase will not help).
    let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
               Proc-Type: 4,ENCRYPTED\n\
               DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n\
               aGVsbG8gd29ybGQ=\n\
               -----END RSA PRIVATE KEY-----";
    assert!(matches!(
        normalize_private_key_to_openssh(pem).unwrap_err(),
        AgentError::LegacyEncrypted
    ));
}

#[test]
fn dsa_reports_unsupported() {
    let pem = "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----";
    assert!(matches!(
        normalize_private_key_to_openssh(pem).unwrap_err(),
        AgentError::Unsupported
    ));
}

#[test]
fn garbage_reports_parse() {
    assert!(matches!(
        normalize_private_key_to_openssh("not a key at all").unwrap_err(),
        AgentError::Parse
    ));
    // Correct label, but garbage PKCS#1 body.
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nZ m9v\n-----END RSA PRIVATE KEY-----";
    assert!(matches!(
        normalize_private_key_to_openssh(pem).unwrap_err(),
        AgentError::Parse
    ));
}
