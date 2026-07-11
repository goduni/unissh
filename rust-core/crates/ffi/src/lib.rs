//! # unissh-ffi
//!
//! FFI-граница ядра UniSSH (ТЗ 4). Фасад [`Core`] связывает `keychain`,
//! `storage`, `vault`, `ssh-agent`, `ssh-transport` в стабильный контракт для UI
//! (UniFFI → Swift/Kotlin/…).
//!
//! ## Граница секретов (контракт; зафиксирован тестом `secret_returning_surface`)
//! Приватный **keyset устройства** (ключи подписи/шифрования инстанса) НИКОГДА не
//! пересекает FFI-границу. Обычные вызовы отдают только публичные ключи и
//! результаты сессий. Секретный материал уходит наружу ТОЛЬКО по явному,
//! инициированному пользователем действию — и таких методов ровно несколько
//! (исчерпывающий список — в тесте):
//! - [`Core::get_password`] / [`Core::get_note`] — reveal пользовательского
//!   секрета (поведение менеджера паролей); для item другого типа — отказ;
//! - [`Core::export_ssh_key`] — экспорт приватного SSH-ключа. Это ОСОЗНАННАЯ
//!   возможность: пользователь владеет своими ключами и вправе их вынести — мы
//!   не запираем их в закрытую экосистему. Вызов всегда явный, по действию юзера;
//! - [`Core::export_vault`] — passphrase-зашифрованный бэкап волта.
//!
//! Любой НОВЫЙ метод, возвращающий секретный материал, обязан быть добавлен и
//! сюда, и в перечисляющий тест — это tripwire против случайной утечки.
//!
//! ## Модель
//! Локальный инстанс = файл зашифрованной БД (`storage`) + сайдкар с зашифрованным
//! keyset. Ключ SQLCipher выводится из секретов распакованного keyset (нужна
//! разблокировка). SSH-сессии запускаются через встроенный агент (ключ в агенте,
//! не в UI).

#![allow(clippy::arc_with_non_send_sync)]

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use unissh_crypto::{aead_decrypt, aead_encrypt, derive_key, AssociatedData};
use unissh_keychain::{
    build_registration, build_registration_request, change_password, create_account,
    generate_account_id, load_account_id, sign_server_challenge, store_account_id, unlock_account,
    unlock_account_migrating, EncryptedKeyset, KdfParams, OnboardInitiator, OnboardResponder,
    SecretKey, ServerAuthChallenge,
};
use unissh_ssh_agent::{generate_ed25519_openssh, InMemoryAgent};
use unissh_ssh_transport::{
    canonical_host_key, trust_host_key, Auth, ConnectOptions, ExecHandle, ForwardGuard, OutputSink,
    SftpSession, ShellHandle, SshClient, SshConfig,
};
use unissh_storage::{CachePolicy, MemberRole, Storage, SyncTarget};
use unissh_sync::{
    reset_pull_cursor, sync_pull, sync_push, SyncContext, SyncObject, SyncTransport,
};
use unissh_vault::{
    member_fingerprint, open_account_payload, pin_and_verify_member, pin_and_verify_vault_anchor,
    seal_account_payload, sign_account_state, verify_chain_to_epoch, Member, Vault,
};

uniffi::setup_scaffolding!();

/// Тип item для SSH-ключа (открытые метаданные).
const ITEM_TYPE_SSH_KEY: u32 = 1;
/// Тип item для SSH user-сертификата.
const ITEM_TYPE_SSH_CERT: u32 = 2;
/// Тип item для профиля соединения (сохранённый «хост»).
const ITEM_TYPE_CONNECTION: u32 = 3;
/// Тип item для пароля сервера (контент — UTF-8 байты пароля).
const ITEM_TYPE_PASSWORD: u32 = 4;
/// Тип item для группы хостов (контент — JSON [`StoredGroup`]).
const ITEM_TYPE_GROUP: u32 = 5;
/// Тип item для зашифрованной заметки (контент — произвольный UTF-8).
const ITEM_TYPE_NOTE: u32 = 6;
/// Тип item для личной идентичности (контент — JSON [`StoredIdentity`]:
/// username + ссылки на ключ/пароль-item в том же волте).
const ITEM_TYPE_IDENTITY: u32 = 7;
/// Тип item для привязки идентичности к shared-хосту (контент — JSON
/// [`StoredBinding`]). Живёт в ЛИЧНОМ волте; ключуется по (team_vault_id,
/// profile_uid). Синкается только между устройствами аккаунта.
const ITEM_TYPE_BINDING: u32 = 8;
/// Предел глубины раскрытия вложенных групп (защита от раздувания/зацикливания
/// сверх visited-set).
const GROUP_MAX_DEPTH: u32 = 32;

/// Id item-сертификата для данного ключа.
fn cert_item_id(key_item_id: &str) -> String {
    format!("{key_item_id}.cert")
}

/// Ошибки FFI-границы.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Ядро не разблокировано.
    #[error("core is locked")]
    Locked,
    /// Неверный пароль или Secret Key.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Объект не найден.
    #[error("not found")]
    NotFound,
    /// Инстанс по этому пути уже существует (защита от перезаписи keyset/БД).
    #[error("instance already exists")]
    AlreadyExists,
    /// Host key не совпал с закреплённым — возможный MITM (показать пользователю
    /// `fingerprint` предъявленного ключа и предложить `trust_host`).
    #[error("host key mismatch for {host}:{port}; presented {fingerprint}")]
    HostKeyMismatch {
        /// Хост.
        host: String,
        /// Порт.
        port: u16,
        /// SHA256-отпечаток ФАКТИЧЕСКИ предъявленного сервером ключа.
        fingerprint: String,
    },
    /// Ошибка SSH.
    #[error("ssh error: {msg}")]
    Ssh {
        /// Сообщение.
        msg: String,
    },
    /// Прочая ошибка.
    #[error("{msg}")]
    Other {
        /// Сообщение.
        msg: String,
    },
}

impl FfiError {
    fn other(e: impl std::fmt::Display) -> Self {
        FfiError::Other { msg: e.to_string() }
    }
    fn ssh(e: impl std::fmt::Display) -> Self {
        FfiError::Ssh { msg: e.to_string() }
    }
}

/// Краткая информация о волте.
#[derive(uniffi::Record)]
pub struct VaultInfo {
    /// Идентификатор волта.
    pub vault_id: String,
    /// Имя волта.
    pub name: String,
    /// Цель синхронизации: локальный волт или облачный. Для значка Local/Cloud в
    /// UI и гейтинга облачных операций (членство/синк/онбординг разрешены только
    /// для Cloud). Берётся из `VaultRecord.sync_target`.
    pub sync_target: FfiSyncTarget,
    /// **1:1-привязка cloud-волта к серверу:** `tenant_id` сервера (та же base64-
    /// строка, что в `ServerConfig.tenant_id`), с которым синкается этот облачный
    /// волт. `None` — не привязан (локальный волт ИЛИ ещё-не-привязанный legacy
    /// cloud-волт). UI показывает, к какому серверу привязан волт.
    pub sync_tenant: Option<String>,
}

/// Цель синхронизации волта для UI (зеркало `unissh_storage::SyncTarget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSyncTarget {
    /// Локальный волт: на сервер не уходит.
    Local,
    /// Облачный волт: синкается с сервером.
    Cloud,
}

impl FfiSyncTarget {
    fn from_core(t: SyncTarget) -> FfiSyncTarget {
        match t {
            SyncTarget::Local => FfiSyncTarget::Local,
            SyncTarget::Cloud => FfiSyncTarget::Cloud,
            // SyncTarget — non_exhaustive: неизвестная будущая цель → консервативно
            // Local (никаких облачных операций/гейтинга для неизвестной цели).
            _ => FfiSyncTarget::Local,
        }
    }
}

/// Регистрационный запрос к серверу (server-tz §5.3): канонический payload
/// (`RegistrationPayload::canonical`) + само-подпись (домен
/// `unissh-registration-v1`). Клиент шлёт их как два base64-поля
/// (`registration_payload` + `registration_signature`) в `/v1/bootstrap` или
/// `/v1/register`. Оба — публичные данные (account-id + публичные ключи + подпись).
#[derive(Debug, Clone, uniffi::Record)]
pub struct RegistrationRequest {
    /// Канонический payload: `u16 len(account_id) || account_id || x25519(32) || ed25519(32)`.
    pub payload: Vec<u8>,
    /// Подпись payload Ed25519-ключом keyset (67-байтный блоб).
    pub signature: Vec<u8>,
}

/// Краткая информация об item.
#[derive(uniffi::Record)]
pub struct ItemInfo {
    /// Идентификатор item.
    pub item_id: String,
    /// Тип item.
    pub item_type: u32,
    /// Версия.
    pub version: u64,
    /// Когда создан (unix-сек; 0, если неизвестно).
    pub created_at: i64,
    /// Когда последний раз изменён (unix-сек).
    pub updated_at: i64,
    /// Есть ли привязанный SSH-сертификат (для item-ключа).
    pub has_certificate: bool,
}

/// Публичный ключ item + его отпечаток (для показа/копирования в UI).
#[derive(uniffi::Record)]
pub struct PublicKeyInfo {
    /// Публичный ключ в формате OpenSSH (`ssh-ed25519 AAAA...`).
    pub openssh: String,
    /// SHA256-отпечаток (`SHA256:...`).
    pub fingerprint: String,
}

/// Запись каталога SFTP.
#[derive(uniffi::Record)]
pub struct SftpEntry {
    /// Имя файла (без пути).
    pub filename: String,
    /// Каталог ли это.
    pub is_dir: bool,
    /// Размер в байтах.
    pub size: u64,
    /// Unix-биты режима (полный st_mode), 0 если неизвестно.
    pub mode: u32,
    /// Время изменения, секунды от эпохи; 0 если неизвестно.
    pub mtime: u64,
}

/// Результат SFTP stat.
#[derive(uniffi::Record)]
pub struct SftpFileStat {
    /// Размер в байтах.
    pub size: u64,
    /// Каталог ли это.
    pub is_dir: bool,
    /// Unix-биты режима (полный st_mode), 0 если неизвестно.
    pub mode: u32,
    /// Время изменения, секунды от эпохи; 0 если неизвестно.
    pub mtime: u64,
}

/// Сохранённый профиль соединения («хост»). `profile_id` — это id item в волте.
#[derive(uniffi::Record, Clone)]
pub struct ConnectionProfile {
    /// Идентификатор профиля (item_id в волте).
    pub profile_id: String,
    /// Неизменяемый uid профиля (внутри шифр-тела; не меняется при правке
    /// host/label). Стабильный ключ для binding'ов личной идентичности (B3).
    /// На создании пустой — ядро минтит при [`Core::save_connection`].
    pub uid: String,
    /// Человекочитаемая метка.
    pub label: String,
    /// Хост.
    pub host: String,
    /// Порт.
    pub port: u16,
    /// Пользователь.
    pub user: String,
    /// Способ аутентификации (ссылки на items волта; секретов внутри нет).
    pub auth: ProfileAuth,
    /// Username-шаблон: `%u` → username идентичности; для шлюзов, кодирующих цель в
    /// username-шаблоне `{identity.user}:{target}` (B4.2, обычно с `Personal`).
    pub username_template: Option<String>,
    /// ProxyJump-цепочка.
    pub jumps: Vec<JumpHost>,
    /// Метки для организации/выборки целей (например `prod`, `web`, `eu`). Это
    /// фильтр выборки, а не права доступа (RBAC — серверная Веха 2).
    pub tags: Vec<String>,
}

/// Личная идентичность: SSH-креды под одним именем (username + опц. ссылки на
/// ключ и/или пароль-item в ТОМ ЖЕ волте). Живёт первично в личном волте и
/// линкуется с shared-хостом через binding (Phase B3), поэтому личные креды не
/// попадают в общий волт. `identity_id` — это item_id в волте. Секрет внутрь не
/// встраивается — только ссылки (как `ProfileAuth`).
#[derive(uniffi::Record, Clone)]
pub struct Identity {
    /// Идентификатор (item_id в волте).
    pub identity_id: String,
    /// Человекочитаемая метка.
    pub label: String,
    /// Имя пользователя для входа.
    pub user: String,
    /// Ссылка на ключ-item (тип «SSH-ключ») в этом волте, если задан.
    pub key_item_id: Option<String>,
    /// Ссылка на пароль-item (тип «пароль») в этом волте, если задан.
    pub password_item_id: Option<String>,
}

/// Сериализуемое тело идентичности (JSON в контенте item). `identity_id` не
/// сериализуется — это id item. Плоские опциональные поля (как у `StoredProfile`)
/// для forward-совместимости.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    label: String,
    user: String,
    #[serde(default)]
    key_item_id: Option<String>,
    #[serde(default)]
    password_item_id: Option<String>,
    /// Forward-совместимость (см. [`StoredProfile::extra`]).
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl StoredIdentity {
    fn into_identity(self, identity_id: String) -> Identity {
        Identity {
            identity_id,
            label: self.label,
            user: self.user,
            key_item_id: self.key_item_id,
            password_item_id: self.password_item_id,
        }
    }
}

/// Привязка личной идентичности к shared-хосту. Живёт в ЛИЧНОМ волте (синкается
/// только между устройствами аккаунта), поэтому личные креды и сам факт линковки
/// не видны команде. Ключуется по (`team_vault_id`, `profile_uid`): волт
/// shared-профиля + его неизменяемый uid (B2.1, устойчив к правке/рециклу id).
#[derive(uniffi::Record, Clone)]
pub struct IdentityBinding {
    /// Волт shared-профиля (куда привязываемся).
    pub team_vault_id: String,
    /// Неизменяемый uid shared-профиля.
    pub profile_uid: String,
    /// Id идентичности (item в личном волте), которой логинимся.
    pub identity_item_id: String,
    /// Закреплённый пункт назначения (`host:port`; с учётом username-шаблона и
    /// username-шаблона) на момент привязки. Анти-редирект-якорь: при коннекте
    /// сверяется с текущим отрендеренным назначением (см. [`resolve_binding`]).
    pub destination_pin: String,
}

/// Сериализуемое тело привязки (JSON в контенте item личного волта). Поля key
/// (`team_vault_id`, `profile_uid`) дублируются в теле для листинга; сам item_id
/// детерминирован от них ([`binding_item_id`]).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredBinding {
    team_vault_id: String,
    profile_uid: String,
    identity_item_id: String,
    destination_pin: String,
    /// Forward-совместимость (см. [`StoredProfile::extra`]).
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl StoredBinding {
    fn into_binding(self) -> IdentityBinding {
        IdentityBinding {
            team_vault_id: self.team_vault_id,
            profile_uid: self.profile_uid,
            identity_item_id: self.identity_item_id,
            destination_pin: self.destination_pin,
        }
    }
}

/// Итог резолва привязки при коннекте (с анти-редирект-проверкой). Отдаётся
/// клиенту: `Unbound` → fallback; `Matched` → логиниться личной идентичностью;
/// `Redirected` → показать re-bind, личный кред НЕ слать. Строгую in-core-защиту
/// (коннект сам отказывает при редиректе) доведёт Personal-auth (B4); это —
/// запрос-примитив для UX-слоя.
#[derive(uniffi::Enum, Debug, PartialEq, Eq, Clone)]
pub enum BindingResolution {
    /// Привязки нет — использовать fallback (prompt / коннект без личных кредов).
    Unbound,
    /// Привязка есть и текущий пункт назначения совпал с закреплённым — можно
    /// логиниться личной идентичностью `identity_item_id`.
    Matched { identity_item_id: String },
    /// Привязка есть, но текущее назначение ОТЛИЧАЕТСЯ от закреплённого: хост
    /// мог быть переклеен (in-place правка host или username-шаблона) →
    /// ОТКАЗ отправлять личный кред, нужна явная перепривязка.
    Redirected { pinned: String, current: String },
}

/// Чистая анти-редирект-логика: сверяет текущий отрендеренный пункт назначения с
/// закреплённым в привязке. Никогда не «обучается» новому назначению молча —
/// расхождение всегда даёт [`BindingResolution::Redirected`] (нужен явный
/// re-bind). Вынесена отдельно для юнит-тестируемости без живого коннекта.
fn resolve_binding(
    binding: Option<&IdentityBinding>,
    current_destination: &str,
) -> BindingResolution {
    match binding {
        None => BindingResolution::Unbound,
        Some(b) if b.destination_pin == current_destination => BindingResolution::Matched {
            identity_item_id: b.identity_item_id.clone(),
        },
        Some(b) => BindingResolution::Redirected {
            pinned: b.destination_pin.clone(),
            current: current_destination.to_string(),
        },
    }
}

/// Детерминированный item_id привязки в личном волте от (team_vault_id,
/// profile_uid): одна привязка на пару, прямой O(1)-lookup при коннекте.
fn binding_item_id(team_vault_id: &str, profile_uid: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"unissh-binding-v1");
    h.update((team_vault_id.len() as u64).to_be_bytes());
    h.update(team_vault_id.as_bytes());
    h.update(profile_uid.as_bytes());
    format!("binding:{}", hex::encode(&h.finalize()[..16]))
}

/// Разрешённая личная аутентификация для коннекта к shared-хосту: конкретный
/// vault-квалифицированный [`AuthMethod`] (ключ/пароль из ЛИЧНОГО волта) плюс
/// username из идентичности. Возвращается [`Core::resolve_personal_auth`] уже
/// ПОСЛЕ анти-редирект-проверки — т.е. личный кред резолвится только для
/// закреплённого назначения.
#[derive(uniffi::Record, Clone)]
pub struct PersonalAuth {
    /// Имя пользователя (identity.user → fallback профиля → account-default).
    pub user: String,
    /// Конкретный способ аутентификации (ссылка на ключ/пароль в личном волте).
    pub auth: AuthMethod,
}

/// username-цепочка для Personal: identity.user → fallback профиля →
/// account-default → пусто. Первый непустой (trim) выигрывает.
fn pick_username(
    identity_user: &str,
    profile_fallback: &str,
    account_default: Option<&str>,
) -> String {
    for c in [identity_user, profile_fallback] {
        if !c.trim().is_empty() {
            return c.to_string();
        }
    }
    account_default
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_default()
}

/// Каноническая строка ЦЕПОЧКИ ПРЫЖКОВ для анти-редиректа. Пустая цепочка → "".
/// Каждый хоп: `host:port:user` (inline) или `ref=vault/uid` (host-chain B2.2).
/// Любая правка/вставка/переупорядочение прыжка меняет строку → меняет пин.
fn canonical_jumps(jumps: &[JumpHost]) -> String {
    jumps
        .iter()
        .map(|j| match &j.hop_ref {
            Some(r) => format!("ref={}/{}", r.vault_id, r.profile_uid),
            None => format!("{}:{}:{}", j.host, j.port, j.user),
        })
        .collect::<Vec<_>>()
        .join(">")
}

/// Каноническое строковое назначение для закрепления/сверки (анти-редирект).
/// ВКЛЮЧАЕТ username-шаблон (`host:port#template`), чтобы его правка
/// меняла назначение и триггерила Redirected. ВКЛЮЧАЕТ и цепочку ProxyJump
/// (`|via=...`), когда она непуста — иначе админ команды вставил бы MITM-прыжок в
/// общий Personal-профиль (host:port не меняется → пин совпадал бы) и увёл бы
/// личный кред участника через свою машину. Хосты без прыжков дают прежнюю строку
/// (обратная совместимость со старыми пинами); появление прыжка → Redirected →
/// отказ (fail-safe), а не утечка. Клиент рендерит им И пин при bind'е, И
/// `current_destination` при коннекте — форматы гарантированно совпадают.
fn personal_destination(
    host: &str,
    port: u16,
    username_template: Option<&str>,
    jumps: &[JumpHost],
) -> String {
    let base = match username_template {
        Some(t) if !t.trim().is_empty() => format!("{host}:{port}#{}", t.trim()),
        _ => format!("{host}:{port}"),
    };
    if jumps.is_empty() {
        base
    } else {
        format!("{base}|via={}", canonical_jumps(jumps))
    }
}

/// Шаблон финального username коннекта (гейтвей-агностично): подстановка `%u`
/// на username идентичности. Пусто → просто `base_user`. Покрывает warpgate-подобные
/// сценарии (`%u:prod-db` → `alice:prod-db`) и любой шлюз, кодирующий цель в имени
/// (`%u@target`, `target+%u` и т.п.), не завязываясь на конкретный продукт. Клиент
/// применяет тот же шаблон, что попадает в destination-пин (форматы совпадают).
fn apply_username_template(base_user: &str, username_template: Option<&str>) -> String {
    match username_template {
        Some(t) if !t.trim().is_empty() => t.trim().replace("%u", base_user),
        _ => base_user.to_string(),
    }
}

/// Способ аутентификации, сохранённый в профиле. Содержит только **ссылки** на
/// items волта — сам секрет в JSON профиля не встраивается никогда.
#[derive(uniffi::Enum, Clone)]
pub enum ProfileAuth {
    /// Ключом из волта (item типа «SSH-ключ»).
    Key {
        /// Id ключа-item.
        key_item_id: String,
    },
    /// Паролем из волта (item типа «пароль»).
    VaultPassword {
        /// Id пароля-item.
        password_item_id: String,
    },
    /// Пароль спрашивается у пользователя при каждом подключении.
    PromptPassword,
    /// Личной идентичностью: у shared-профиля НЕТ хранимых кредов; каждый член
    /// линкует свою идентичность через binding в личном волте (B3). При коннекте
    /// креды и username берутся из личного волта ([`Core::resolve_personal_auth`]),
    /// личные секреты в общий волт не попадают. Дефолт при переносе хоста в
    /// cloud-волт (B5).
    Personal,
}

/// Внутреннее (сериализуемое) тело профиля. `profile_id` не сериализуется — это
/// id item. JSON хранится как зашифрованный контент item (слой vault).
///
/// Совместимость: плоские опциональные поля вместо enum — старые профили (без
/// `password_item_id`) читаются как есть; `password_item_id` приоритетнее
/// `key_item_id`, оба `None` → парольная аутентификация с вводом при коннекте.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredProfile {
    /// Неизменяемый uid профиля (внутри шифр-тела). Минтится при создании,
    /// НЕ переписывается при правке (host/label меняются, uid — нет). Стабильный
    /// ключ для binding'ов (Phase B3), устойчивый к рециклу item_id после
    /// tombstone. Легаси-профили без него получают детерминированный fallback
    /// при чтении ([`legacy_profile_uid`]), закрепляемый при первом пере-сохранении.
    #[serde(default)]
    uid: Option<String>,
    label: String,
    host: String,
    port: u16,
    user: String,
    #[serde(default)]
    key_item_id: Option<String>,
    #[serde(default)]
    password_item_id: Option<String>,
    /// Personal-профиль: кредов в этом (общем) волте нет, логинимся личной
    /// идентичностью через binding (B4). Приоритетнее key/password-ссылок.
    #[serde(default)]
    personal: bool,
    /// Username-шаблон: если задан, целевой
    /// сервер кодируется в username (`{identity.user}:{target}`, B4.2). Обычно
    /// вместе с `personal`. Правка target покрыта анти-редиректом (входит в
    /// закрепляемое назначение).
    #[serde(default)]
    username_template: Option<String>,
    jumps: Vec<StoredJump>,
    #[serde(default)]
    tags: Vec<String>,
    /// Forward-совместимость: неизвестные поля (добавленные будущей версией)
    /// сохраняются при round-trip, а не отбрасываются. Иначе клиент СТАРЕЕ поля
    /// прочитал бы профиль без нового поля (напр. `personal`), а при пере-
    /// сохранении вырезал бы его → LWW-даунгрейд для всех. Пусто → сериализуется
    /// в ничто (существующие подписанные items байт-в-байт не меняются).
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Сериализуемое тело host-chain-ссылки (B2.2).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredHopRef {
    vault_id: String,
    profile_uid: String,
}

/// Сериализуемый jump-хост. Легаси-формат хранил `key_item_id` строкой
/// (возможно пустой — «ключ не назначен»); новые записи задают ровно одно из
/// полей. Inline-пароль здесь невозможен по построению.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredJump {
    host: String,
    port: u16,
    user: String,
    #[serde(default)]
    key_item_id: Option<String>,
    #[serde(default)]
    password_item_id: Option<String>,
    /// Host-chain-ссылка (B2.2): хоп ссылается на другой профиль по uid.
    #[serde(default)]
    hop_ref: Option<StoredHopRef>,
    /// Forward-совместимость на уровне serde round-trip. Замечание: при правке
    /// профиля хопы пересобираются из FFI `JumpHost` ([`jump_to_stored`]), так
    /// что merge-on-save (как у [`StoredProfile::extra`]) для хопов НЕ выполняется
    /// — jump-уровневые будущие поля переживают только чистый sync (raw bytes),
    /// не FFI-правку. Приемлемо: хопы редко получают новые синкаемые поля.
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Способ аутентификации на хосте (целевом или jump) при подключении.
///
/// Ссылки на items волта **vault-квалифицированы**: каждый метод несёт `vault_id`
/// того волта, где лежит ключ/пароль. Это позволяет цели и каждому jump-хопу
/// брать креды из РАЗНЫХ волтов (общий бастион в командном волте + личная
/// идентичность в личном волте) — см. [`resolve_auth`], который резолвит каждый
/// метод против его собственного волта, а не одного общего.
#[derive(uniffi::Enum, Clone)]
pub enum AuthMethod {
    /// Ключом из волта (через встроенный агент).
    Agent {
        /// Волт, где лежит ключ-item.
        vault_id: String,
        /// Id ключа-item в волте.
        key_item_id: String,
    },
    /// Паролем, введённым пользователем сейчас (в волте не хранится).
    Password {
        /// Пароль. ⚠️ Остаточный риск границы FFI: UniFFI-`Enum` не умеет держать
        /// поле в `Zeroizing`, поэтому эта `String` (и копия внутри russh) не
        /// зануляется автоматически. На нашей стороне пароль переносится в
        /// `Zeroizing` при сборке `ConnectOptions` ([`resolve_auth`]).
        password: String,
    },
    /// Паролем из волта (item типа «пароль»). Ядро расшифровывает его само в
    /// момент коннекта; plaintext через FFI не проходит.
    VaultPassword {
        /// Волт, где лежит пароль-item.
        vault_id: String,
        /// Id пароля-item в волте.
        password_item_id: String,
    },
}

/// Закреплённый host key (для экрана управления known_hosts).
#[derive(uniffi::Record)]
pub struct KnownHostInfo {
    /// Хост.
    pub host: String,
    /// Порт.
    pub port: u16,
    /// Публичный host key (OpenSSH).
    pub key: String,
    /// Время закрепления (unix-сек).
    pub added_at: i64,
}

/// Итог импорта хостов из внешнего формата (PuTTY и т.п.).
#[derive(uniffi::Record)]
pub struct HostImportReport {
    /// id созданных профилей.
    pub created_ids: Vec<String>,
    /// Сколько записей пропущено (не SSH, нет хоста, коллизия id).
    pub skipped: u32,
}

/// Итог импорта `~/.ssh/known_hosts`.
#[derive(uniffi::Record)]
pub struct KnownHostsImport {
    /// Сколько (host, port) закреплено.
    pub imported: u32,
    /// Сколько строк пропущено как hashed (`|1|…` — необратимы, не привязать).
    pub skipped_hashed: u32,
    /// Сколько строк пропущено как некорректные (нет ключа/не парсится).
    pub skipped_invalid: u32,
}

/// Описание jump-хоста для ProxyJump.
#[derive(uniffi::Record, Clone)]
pub struct JumpHost {
    /// Хост.
    pub host: String,
    /// Порт.
    pub port: u16,
    /// Пользователь.
    pub user: String,
    /// Аутентификация на jump-хосте (items — в том же волте, что и у целевого
    /// хоста). В профиль сохраняются только ссылки (ключ/пароль из волта);
    /// inline-`Password` допустим лишь при непосредственном подключении.
    pub auth: AuthMethod,
    /// Host-chain (B2.2): если задан, хоп — ССЫЛКА на другой сохранённый профиль
    /// (по неизменяемому uid, возможно в ДРУГОМ волте); его host/port/user/auth
    /// резолвятся при коннекте, а inline-поля выше ИГНОРИРУЮТСЯ. Позволяет
    /// переиспользовать бастион-профиль в цепочках без дублирования.
    pub hop_ref: Option<HopRef>,
}

/// Ссылка host-chain на сохранённый профиль-бастион (B2.2). Резолвится в
/// host/port/user/auth того профиля при коннекте (см. [`resolve_profile_by_uid`]).
#[derive(uniffi::Record, Clone)]
pub struct HopRef {
    /// Волт, где лежит профиль-бастион.
    pub vault_id: String,
    /// Неизменяемый uid профиля-бастиона (B2.1).
    pub profile_uid: String,
}

/// Результат выполнения SSH-команды.
#[derive(Debug, uniffi::Record)]
pub struct SshExecResult {
    /// stdout (как текст; невалидный UTF-8 заменяется).
    pub stdout: String,
    /// stderr.
    pub stderr: String,
    /// Код возврата (или -1, если не получен).
    pub exit_status: i32,
}

/// Цель для multi-exec: один хост + ключ/джампы.
#[derive(uniffi::Record)]
pub struct MultiExecTarget {
    /// Хост.
    pub host: String,
    /// Порт.
    pub port: u16,
    /// Пользователь.
    pub user: String,
    /// Способ аутентификации (несёт `vault_id` ключа/пароля; jump-хопы — свои).
    pub auth: AuthMethod,
    /// ProxyJump-цепочка (может быть пустой).
    pub jumps: Vec<JumpHost>,
}

/// Категория нарушения структурной целостности БД (FFI-зеркало `ConsistencyKind`).
#[derive(Debug, uniffi::Enum, PartialEq, Eq)]
pub enum DbConsistencyKind {
    /// Item без записи волта.
    OrphanItem,
    /// Версия < 1.
    BadVersion,
    /// Длина `author_pubkey` != 32.
    BadAuthorLen,
    /// Слишком короткая подпись.
    BadSignatureLen,
    /// Tombstone с непустым контентом.
    TombstoneNotEmpty,
    /// История версий для удалённого/отсутствующего item.
    StaleHistory,
}

/// Нарушение целостности БД (без секретов; идентификаторы — hex).
#[derive(Debug, uniffi::Record)]
pub struct DbConsistencyIssue {
    /// Категория.
    pub kind: DbConsistencyKind,
    /// vault_id (hex).
    pub vault_id_hex: String,
    /// item_id (hex); пусто для проблем уровня волта.
    pub item_id_hex: String,
    /// Машиночитаемая деталь.
    pub detail: String,
}

/// Отчёт структурной проверки БД инстанса (без секретов).
#[derive(Debug, uniffi::Record)]
pub struct DbConsistencyReport {
    /// Целостность и инварианты соблюдены.
    pub ok: bool,
    /// `PRAGMA integrity_check` прошёл.
    pub integrity_ok: bool,
    /// Найденные нарушения.
    pub issues: Vec<DbConsistencyIssue>,
}

/// Результат раскладки файла на один хост ([`Core::sftp_put_multi`]).
#[derive(uniffi::Record)]
pub struct SftpPutResult {
    /// Хост.
    pub host: String,
    /// Ошибка, если запись не удалась (иначе `None`).
    pub error: Option<String>,
}

/// Статус одного хоста broadcast-сессии (по индексу в `targets`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct BroadcastHostStatus {
    /// Хост.
    pub host: String,
    /// Индекс в исходном списке целей (совпадает с `host_index` в observer).
    pub index: u32,
    /// Установлена ли PTY-сессия.
    pub connected: bool,
    /// Ошибка коннекта/открытия shell, если была.
    pub error: Option<String>,
}

/// Причина провала проверки целостности (FFI-зеркало `IntegrityFailure`).
#[derive(Debug, uniffi::Enum)]
pub enum IntegrityFailureKind {
    /// Подпись не сходится (порча блоба или повреждённый sig).
    SignatureInvalid,
    /// `author_pubkey` не совпал с владельцем волта (подмена автора).
    AuthorMismatch,
    /// Структурно некорректные автор/подпись.
    Malformed,
}

/// Проблемная запись в отчёте целостности (без секретов).
#[derive(Debug, uniffi::Record)]
pub struct IntegrityIssueInfo {
    /// `item_id` (UTF-8 lossy); пустая строка — проблема самой vault-записи.
    pub item_id: String,
    /// Версия записи.
    pub version: u64,
    /// Tombstone ли это.
    pub tombstone: bool,
    /// Причина.
    pub failure: IntegrityFailureKind,
}

/// Отчёт аудита целостности волта (read-only, без plaintext/секретов).
#[derive(Debug, uniffi::Record)]
pub struct VaultIntegrityReport {
    /// Все записи (включая tombstones) прошли проверку.
    pub ok: bool,
    /// Сколько записей проверено.
    pub checked: u64,
    /// Проблемные записи.
    pub issues: Vec<IntegrityIssueInfo>,
}

/// Группа хостов: именованный набор ссылок на профили и/или вложенные группы в
/// том же волте. Обслуживает организацию (дерево папок через `parent_id`) и
/// операции (резолв членов → multi-exec). Это не RBAC — группа не несёт прав.
#[derive(uniffi::Record, Clone)]
pub struct ServerGroup {
    /// Идентификатор группы (item_id в волте).
    pub group_id: String,
    /// Человекочитаемая метка.
    pub label: String,
    /// Члены: id профилей-соединений или id вложенных групп (того же волта).
    pub member_ids: Vec<String>,
    /// Родительская группа для дерева папок в UI (`None` = корень).
    pub parent_id: Option<String>,
}

/// Сериализуемое тело группы. Только ссылки, никаких кред. `color` — открытое
/// UI-поле; новые поля добавляются с `#[serde(default)]` (forward-compat).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredGroup {
    label: String,
    #[serde(default)]
    member_ids: Vec<String>,
    #[serde(default)]
    parent_id: Option<String>,
    #[serde(default)]
    color: Option<String>,
}

/// Статус разрешения члена группы (для dry-run и диагностики).
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResolveStatus {
    /// Член — существующий профиль, цель построена.
    Ok,
    /// Ссылка не указывает ни на профиль, ни на группу (удалён/опечатка).
    Dangling,
    /// Член — пароль из волта неизвестен заранее (`PromptPassword`); потребует
    /// ввода при коннекте, в пакетный прогон не годится без интерактива.
    PromptPassword,
    /// Член-группа уже посещена (цикл) либо превышен лимит глубины — пропущен.
    CycleSkipped,
    /// Член — Personal-хост: логин личной идентичностью требует per-host
    /// резолва привязки + анти-редирект-проверки, что в fan-out пока не
    /// поддержано (B6). НЕ подключаем с пустым паролем — исключаем из пакета.
    Personal,
}

/// Развёрнутая цель группы в dry-run: что зарезолвилось и с каким статусом, без
/// коннекта/загрузки ключей/расшифровки паролей.
#[derive(uniffi::Record)]
pub struct GroupTargetPlan {
    /// Id профиля-члена (или проблемной ссылки).
    pub member_id: String,
    /// Хост (пусто, если не зарезолвилось).
    pub host: String,
    /// Порт.
    pub port: u16,
    /// Пользователь.
    pub user: String,
    /// Статус разрешения.
    pub status: ResolveStatus,
}

/// Результат multi-exec по одному хосту.
#[derive(uniffi::Record)]
pub struct MultiExecResult {
    /// Хост.
    pub host: String,
    /// stdout.
    pub stdout: String,
    /// stderr.
    pub stderr: String,
    /// Код возврата (или -1).
    pub exit_status: i32,
    /// Ошибка коннекта/выполнения, если была (тогда остальные поля пусты).
    pub error: Option<String>,
    /// Длительность фазы выполнения команды (мс). Для ошибок коннекта — 0.
    pub duration_ms: u64,
    /// Команда не уложилась в per-host таймаут (`timeout_secs`). Тогда `error`
    /// тоже выставлен, а `exit_status == -1`.
    pub timed_out: bool,
}

// === Веха-2: FFI-типы (cloud/membership/identity/cache/audit/sync) ===

/// Роль члена волта (FFI-зеркало `storage::MemberRole`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMemberRole {
    /// Только чтение.
    Viewer,
    /// Чтение и запись items.
    Editor,
    /// Управление членством (выдача/отзыв, ротация).
    Admin,
}

impl FfiMemberRole {
    fn to_core(self) -> MemberRole {
        match self {
            FfiMemberRole::Viewer => MemberRole::Viewer,
            FfiMemberRole::Editor => MemberRole::Editor,
            FfiMemberRole::Admin => MemberRole::Admin,
        }
    }
    fn from_core(r: MemberRole) -> FfiMemberRole {
        match r {
            MemberRole::Viewer => FfiMemberRole::Viewer,
            MemberRole::Editor => FfiMemberRole::Editor,
            MemberRole::Admin => FfiMemberRole::Admin,
            // non_exhaustive: будущая роль → консервативно Viewer (минимум прав).
            _ => FfiMemberRole::Viewer,
        }
    }
}

/// Политика кэширования волта (FFI-зеркало `storage::CachePolicy`, server-tz §6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiCachePolicy {
    /// Разрешён оффлайн-доступ (слабее отзыв).
    OfflineAllowed,
    /// Только онлайн (сильный отзыв, нет оффлайна).
    OnlineOnly,
}

impl FfiCachePolicy {
    fn to_core(self) -> CachePolicy {
        match self {
            FfiCachePolicy::OfflineAllowed => CachePolicy::OfflineAllowed,
            FfiCachePolicy::OnlineOnly => CachePolicy::OnlineOnly,
        }
    }
    fn from_core(c: CachePolicy) -> FfiCachePolicy {
        match c {
            CachePolicy::OfflineAllowed => FfiCachePolicy::OfflineAllowed,
            CachePolicy::OnlineOnly => FfiCachePolicy::OnlineOnly,
            _ => FfiCachePolicy::OfflineAllowed,
        }
    }
}

/// Член волта для UI: публичные ключи (hex) + роль + fingerprint. Секретов нет.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberInfo {
    /// Ed25519-pubkey члена (member-id) в hex.
    pub ed25519_pub_hex: String,
    /// Роль.
    pub role: FfiMemberRole,
    /// OOB-fingerprint (hex(SHA-256(ed25519_pub)), 64 символа) для подтверждения.
    pub fingerprint: String,
}

/// Оставшийся член при ротации VK: публичные ключи (hex) + роль.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RemainingMember {
    /// Ed25519-pubkey (member-id), hex.
    pub ed25519_pub_hex: String,
    /// X25519-pubkey (получатель обёртки VK'), hex.
    pub x25519_pub_hex: String,
    /// Роль.
    pub role: FfiMemberRole,
}

/// Один элемент дельты синка, который foreign-транспорт отдаёт ядру.
/// `object` — непрозрачные байты сериализованного sync-объекта.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncDeltaItem {
    /// server_seq, назначенный сервером (НЕ доверенный — движок верифицирует).
    pub server_seq: u64,
    /// Сериализованный объект (непрозрачные зашифрованные/подписанные байты).
    pub object: Vec<u8>,
}

/// Отчёт синка для UI (FFI-зеркало `sync::SyncReport`; без секретов).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncReport {
    /// Сколько объектов применено (merged).
    pub applied: u64,
    /// Сколько пропущено как stale/откат версии.
    pub skipped_stale: u64,
    /// Сколько конфликтов равной версии (локальное не тронуто).
    pub conflicts: u32,
    /// Сколько недоверенных объектов отклонено (verify/floor/cursor fail).
    pub rejected: u32,
    /// Сколько объектов отдано на push.
    pub pushed: u64,
}

/// Запись аудита для UI (FFI-зеркало `storage::AuditEntry`; блобы непрозрачны).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAuditEntry {
    /// Монотонный seq (присвоен storage; открытая метадата, не доверенная для
    /// tamper-evidence в v1).
    pub seq: u64,
    /// Подписанное событие (непрозрачный блоб слоя выше).
    pub entry_blob: Vec<u8>,
    /// Подпись автора (Ed25519-блоб).
    pub signature: Vec<u8>,
    /// Публичный ключ автора (hex).
    pub author_pubkey_hex: String,
    /// Когда записано (unix-сек).
    pub recorded_at: i64,
}

struct CoreState {
    storage: Storage,
    keyset: unissh_keychain::UnlockedKeyset,
    agent: InMemoryAgent,
    /// Кэш расшифрованных имён волтов (vault_id → name), чтобы `list_vaults` не
    /// делал HPKE-разворот VK для каждого волта при каждом вызове.
    vault_names: HashMap<Vec<u8>, String>,
}

/// Корневой объект ядра для UI. Управляет одним локальным инстансом.
#[derive(uniffi::Object)]
pub struct Core {
    db_path: PathBuf,
    keyset_path: PathBuf,
    // Arc — чтобы разделить распакованное состояние с ReconnectingSession
    // (переподключение требует доступа к keyset/storage/agent).
    state: Arc<Mutex<Option<CoreState>>>,
    rt: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl Core {
    /// Создаёт фасад поверх путей БД и сайдкара keyset (ещё не разблокирован).
    #[uniffi::constructor]
    pub fn new(db_path: String, keyset_path: String) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Core {
            db_path: PathBuf::from(db_path),
            keyset_path: PathBuf::from(keyset_path),
            state: Arc::new(Mutex::new(None)),
            rt: Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime"),
            ),
        })
    }

    /// Заводит новый аккаунт (первое устройство). Возвращает Secret Key (hex) для
    /// Emergency Kit — показать пользователю **один раз**. `password = None` →
    /// беспарольный режим (SSO/trusted devices).
    pub fn create_account(&self, password: Option<String>) -> Result<String, FfiError> {
        // Защита от перезаписи существующего инстанса (иначе — необратимая потеря БД).
        if self.keyset_path.exists() || self.db_path.exists() {
            return Err(FfiError::AlreadyExists);
        }
        let has_password = password.is_some();
        let password = password.map(Zeroizing::new);
        let (secret_key, enc, unlocked) = create_account(
            password.as_deref().map(|s| s.as_bytes()),
            KdfParams::recommended(),
        )
        .map_err(FfiError::other)?;
        let enc_bytes = enc.to_bytes().map_err(FfiError::other)?;

        // Порядок важен (защита от «кирпича»): сначала открываем БД, и только при
        // успехе пишем keyset-сайдкар — атомарно (O_EXCL). При любом сбое после
        // создания БД откатываем файлы, чтобы повторная попытка была чистой.
        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(|e| {
            let _ = std::fs::remove_file(&self.db_path);
            FfiError::other(e)
        })?;

        match open_keyset_file(&self.keyset_path, true) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(&enc_bytes) {
                    drop(storage);
                    let _ = std::fs::remove_file(&self.keyset_path);
                    let _ = std::fs::remove_file(&self.db_path);
                    return Err(FfiError::other(e));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Гонка: keyset появился между проверкой и записью. БД мы только что
                // создали сами — убираем её, чужой инстанс не трогаем.
                drop(storage);
                let _ = std::fs::remove_file(&self.db_path);
                return Err(FfiError::AlreadyExists);
            }
            Err(e) => {
                drop(storage);
                let _ = std::fs::remove_file(&self.db_path);
                return Err(FfiError::other(e));
            }
        }

        *self.locked_state() = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        log::info!("instance created (password-protected: {has_password})");
        // Emergency Kit: промежуточную копию hex зануляем; возвращаемая через FFI
        // строка вне нашего контроля (ограничение границы FFI).
        let kit = Zeroizing::new(hex::encode(secret_key.expose_bytes()));
        Ok(kit.as_str().to_string())
    }

    /// Разблокирует инстанс паролем (если нужен) и Secret Key (hex из Emergency Kit).
    pub fn unlock(&self, password: Option<String>, secret_key_hex: String) -> Result<(), FfiError> {
        let password = password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let enc_bytes = std::fs::read(&self.keyset_path).map_err(|_| FfiError::NotFound)?;
        let enc = EncryptedKeyset::from_bytes(&enc_bytes).map_err(FfiError::other)?;
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        // migrate-on-open: keyset, записанный старой схемой (до round 2), открывается
        // пробой и возвращается переобёрнутым под текущую схему (`migrated`). Это
        // чинит «неверный секретный ключ/мастер-пароль» у тех, кто создал аккаунт на
        // прошлых сборках. Персист переобёртки — ниже, ПОСЛЕ open storage и проверки пола.
        let (unlocked, migrated) =
            unlock_account_migrating(&enc, password.as_deref().map(|s| s.as_bytes()), &secret_key)
                .map_err(|e| match e {
                    unissh_keychain::KeychainError::InvalidCredentials
                    | unissh_keychain::KeychainError::PasswordRequired => {
                        FfiError::InvalidCredentials
                    }
                    other => FfiError::other(other),
                })?;

        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(FfiError::other)?;

        // anti-rollback (server-tz §13.13b): локальный сайдкар тоже под защитой пола.
        // Атакующий с доступом к диску может подменить keyset-файл СТАРЫМ
        // (понижённой generation) блобом — после смены пароля это downgrade. Та же
        // логика, что в unlock_from_server_blob: ОТВЕРГАЕМ generation ниже пола ДО
        // установки состояния (пол живёт в storage-meta, доступен только после
        // unlock+open). Пол читаем/поднимаем тем же keychain-хелпером.
        let floor = unissh_keychain::keyset_gen_floor(&storage)
            .map_err(map_keychain_err)?
            .unwrap_or(0);
        let attempted = enc.generation as u64;
        if attempted < floor {
            // Security event: an on-disk keyset older than the recorded floor — a
            // possible downgrade attack. Generations are counters, not secrets.
            log::warn!(
                "keyset generation rollback rejected (attempted={attempted}, floor={floor})"
            );
            return Err(map_keychain_err(
                unissh_keychain::KeychainError::GenerationRollback { attempted, floor },
            ));
        }
        // Порядок защищён от кирпича: сперва атомарно персистим переобёрнутый keyset,
        // и ТОЛЬКО потом поднимаем пол до его (новой, +1) generation. При сбое записи
        // пол не поднимается — старый блоб (generation=attempted) ещё откроется на
        // следующем запуске и миграция повторится. После успеха старый блоб уходит
        // под пол — downgrade на старую/слабую схему больше не пройдёт.
        let accepted_gen = if let Some(new_enc) = migrated {
            // Бэкап старого сайдкара перед перезаписью (логирует путь) — обратимость.
            backup_keyset_sidecar(&self.keyset_path);
            let new_bytes = new_enc.to_bytes().map_err(FfiError::other)?;
            write_keyset_atomic(&self.keyset_path, &new_bytes)?;
            log::info!(
                "keyset migrated to current scheme (generation {} -> {})",
                attempted,
                new_enc.generation
            );
            new_enc.generation as u64
        } else {
            attempted
        };
        // Принято: поднять пол до принятой generation (TOFU; понизить нельзя — идемпотентно).
        unissh_keychain::raise_keyset_gen_floor(&storage, accepted_gen)
            .map_err(map_keychain_err)?;

        *self.locked_state() = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        log::info!("instance unlocked");
        Ok(())
    }

    /// Разблокирован ли инстанс.
    pub fn is_unlocked(&self) -> bool {
        self.locked_state().is_some()
    }

    /// Нужен ли мастер-пароль для разблокировки инстанса на диске. Читает только
    /// заголовок keyset-сайдкара (KDF-параметры есть ⇔ режим Password) — без
    /// открытия БД и без доступа к секретам. `None`, если keyset ещё нет или его
    /// не удалось прочитать/разобрать. Позволяет UI честно показать, что
    /// авто-разблокировка «открыт при старте» применима только к беспарольным
    /// инстансам (пароль нигде не хранится).
    pub fn instance_requires_password(&self) -> Option<bool> {
        let bytes = std::fs::read(&self.keyset_path).ok()?;
        let enc = EncryptedKeyset::from_bytes(&bytes).ok()?;
        Some(enc.kdf_params.is_some())
    }

    /// Блокирует инстанс (секреты в памяти зануляются при Drop).
    pub fn lock(&self) {
        log::info!("instance locked");
        *self.locked_state() = None;
    }

    /// Создаёт локальный волт.
    pub fn create_vault(&self, vault_id: String, name: String) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let id = vault_id.into_bytes();
        Vault::create(&state.storage, &state.keyset, id.clone(), name.as_bytes())
            .map_err(FfiError::other)?;
        state.vault_names.insert(id, name);
        Ok(())
    }

    /// Создаёт **cloud-волт** (server-tz §4.2): `vault_id` = случайный UUIDv4
    /// (`vault::new_vault_id`), `SyncTarget::Cloud`, **привязанный к серверу**
    /// `tenant_b64` (1:1-binding). `tenant_b64` — base64-`tenant_id` активного
    /// сервера (как в `ServerConfig.tenant_id`); хранится как непрозрачная метка
    /// маршрутизации, по которой `sync_now` решает, на какой сервер пушить волт.
    /// Пустой `tenant_b64` отвергается (клиент обязан передать активный сервер).
    /// Возвращает `vault_id` как hex-строку (UUIDv4 — не-UTF8 байты; cloud-методы
    /// принимают hex).
    pub fn create_cloud_vault(&self, name: String, tenant_b64: String) -> Result<String, FfiError> {
        if tenant_b64.is_empty() {
            return Err(FfiError::Other {
                msg: "cloud vault requires an active server (empty tenant)".into(),
            });
        }
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vid = unissh_vault::new_vault_id();
        Vault::create_with_target(
            &state.storage,
            &state.keyset,
            vid.clone(),
            name.as_bytes(),
            SyncTarget::Cloud,
        )
        .map_err(map_vault_err)?;
        // Привязываем ТОЛЬКО свежесозданный волт по его vault_id (1:1), чтобы не
        // задеть чужие непривязанные legacy cloud-волты (они должны привязаться к
        // своему серверу, а не к этому).
        state
            .storage
            .set_vault_tenant(&vid, tenant_b64.as_bytes())
            .map_err(FfiError::other)?;
        let vid_hex = hex::encode(&vid);
        state.vault_names.insert(vid, name);
        Ok(vid_hex)
    }

    /// **Одноразовая привязка legacy cloud-волтов к серверу** (1:1-binding миграция):
    /// проставляет `tenant_b64` каждому облачному волту с пустым `sync_tenant`
    /// (созданному до multi-server). Клиент вызывает это РОВНО когда привязан
    /// единственный сервер — иначе можно привязать не к тому. Идемпотентно
    /// (уже-привязанные волты не трогаются). Возвращает число привязанных волтов.
    pub fn bind_unbound_cloud_vaults(&self, tenant_b64: String) -> Result<u32, FfiError> {
        if tenant_b64.is_empty() {
            return Err(FfiError::Other {
                msg: "cannot bind cloud vaults to an empty tenant".into(),
            });
        }
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let n = state
            .storage
            .bind_unbound_cloud_vaults(tenant_b64.as_bytes())
            .map_err(FfiError::other)?;
        Ok(n as u32)
    }

    /// Снять привязку у всех cloud-волтов, привязанных к `tenant_b64` (напр. при
    /// удалении сервера) — они становятся unbound и могут быть привязаны заново
    /// (через re-link или ручную привязку). Возвращает число затронутых волтов.
    pub fn clear_cloud_vault_binding(&self, tenant_b64: String) -> Result<u32, FfiError> {
        if tenant_b64.is_empty() {
            return Ok(0);
        }
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let n = state
            .storage
            .clear_binding_for_tenant(tenant_b64.as_bytes())
            .map_err(FfiError::other)?;
        Ok(n as u32)
    }

    /// Привязать ОДИН cloud-волт (по hex `vault_id`) к серверу `tenant_b64` (1:1).
    /// Для ручной привязки unbound-волта к выбранному серверу из UI.
    pub fn bind_cloud_vault(&self, vault_id: String, tenant_b64: String) -> Result<(), FfiError> {
        if tenant_b64.is_empty() {
            return Err(FfiError::Other {
                msg: "cannot bind a cloud vault to an empty tenant".into(),
            });
        }
        let vid = hex::decode(vault_id.trim()).map_err(|_| FfiError::other("invalid vault id"))?;
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        state
            .storage
            .set_vault_tenant(&vid, tenant_b64.as_bytes())
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Добавляет/повышает члена cloud-волта (server-tz §5): расширяет набор
    /// последней эпохи на `(member_ed25519_pub, role)` и выпускает обёртку VK под
    /// `member_x25519_pub`. Владелец остаётся `Admin`. Ключи — hex (публичный
    /// материал, не секрет). `vault_id` — hex (cloud UUIDv4).
    pub fn add_member(
        &self,
        vault_id: String,
        member_ed25519_pub: String,
        member_x25519_pub: String,
        role: FfiMemberRole,
    ) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        let member_ed = decode_pubkey32("member_ed25519_pub", &member_ed25519_pub)?;
        let member_x = decode_pubkey32("member_x25519_pub", &member_x25519_pub)?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
        let owner_x = state.keyset.encryption.public.to_bytes().to_vec();

        // Владелец ВСЕГДА Admin своего волта. «Добавление» владельца как члена ниже
        // по upsert-пути пере-вставило бы его с переданной ролью (напр. Viewer); как
        // только `verify_record_authority` требует `can_write`, волт становится
        // нечитаем для собственного владельца (необратимый брик). Отвергаем явно.
        if member_ed == owner_ed {
            return Err(FfiError::other(
                "cannot add the vault owner as a member — the owner is always Admin",
            ));
        }

        let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;

        // целевой набор = текущий (если есть manifest) ∪ {owner Admin, новый член}.
        let mut members: Vec<Member> = match state
            .storage
            .latest_membership_epoch(&vid)
            .map_err(FfiError::other)?
        {
            Some(latest) => verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
                .map_err(map_vault_err)?
                .members()
                .to_vec(),
            None => Vec::new(),
        };
        // гарантируем owner=Admin в наборе
        if !members.iter().any(|m| m.ed25519_pub == owner_ed) {
            members.push(Member {
                ed25519_pub: owner_ed.clone(),
                role: MemberRole::Admin,
            });
        }
        // upsert нового члена (его роль)
        members.retain(|m| m.ed25519_pub != member_ed);
        members.push(Member {
            ed25519_pub: member_ed.clone(),
            role: role.to_core(),
        });

        let x25519_by_ed = vec![(owner_ed.clone(), owner_x), (member_ed.clone(), member_x)];
        vault
            .establish_or_extend_membership(&state.keyset, &members, &x25519_by_ed)
            .map_err(map_vault_err)?;
        Ok(())
    }

    /// Список членов cloud-волта на последней эпохе (публичные ключи + роль +
    /// fingerprint). Пусто, если членства ещё нет.
    pub fn list_members(&self, vault_id: String) -> Result<Vec<MemberInfo>, FfiError> {
        let vid = decode_vid(&vault_id)?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
        let latest = match state
            .storage
            .latest_membership_epoch(&vid)
            .map_err(FfiError::other)?
        {
            Some(l) => l,
            None => return Ok(Vec::new()),
        };
        let verified = verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
            .map_err(map_vault_err)?;
        Ok(verified
            .members()
            .iter()
            .map(|m| MemberInfo {
                ed25519_pub_hex: hex::encode(&m.ed25519_pub),
                role: FfiMemberRole::from_core(m.role),
                fingerprint: member_fingerprint(&m.ed25519_pub),
            })
            .collect())
    }

    /// OOB-fingerprint Ed25519-pubkey члена (hex(SHA-256), 64 символа) — для
    /// показа/сверки в UI (как Bitwarden Confirm / 1Password fingerprint).
    pub fn member_fingerprint(&self, ed25519_pub: String) -> Result<String, FfiError> {
        let ed = decode_pubkey32("ed25519_pub", &ed25519_pub)?;
        Ok(member_fingerprint(&ed))
    }

    /// Подтверждает (пиннит TOFU) pubkey члена под `account_id` (server-tz §5.2):
    /// первый раз — пиннится; повторно тем же ключом — ок; другим → ошибка
    /// (`PinMismatch`, защита от подмены pubkey сервером). Требует unlock (storage).
    pub fn confirm_member_pin(
        &self,
        account_id: String,
        ed25519_pub: String,
    ) -> Result<(), FfiError> {
        let ed = decode_pubkey32("ed25519_pub", &ed25519_pub)?;
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        pin_and_verify_member(&state.storage, account_id.as_bytes(), &ed).map_err(map_vault_err)
    }

    /// Подтверждает (пиннит TOFU) genesis-owner (creator-pubkey) волта, созданного
    /// тиммейтом — share-accept (A0): без этого пина запись чужого волта не проходит
    /// authority-верификацию на синке (якорь = локальный keyset). Первый раз —
    /// пиннится; повторно тем же ключом — ок; другим → `PinMismatch` (защита от
    /// тихого ре-биндинга vault→owner сервером). `ed25519_pub` — creator-pubkey,
    /// полученный OOB и сверенный по отпечатку (`member_fingerprint`). Требует unlock.
    pub fn pin_vault_genesis_owner(
        &self,
        vault_id: String,
        ed25519_pub: String,
    ) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        let ed = decode_pubkey32("ed25519_pub", &ed25519_pub)?;
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        // Якорь пиннится ТОЛЬКО для чужих (teammate) волтов. Свой keyset как
        // «genesis-owner тиммейта» — почти наверняка ошибка/мис-анкоринг: собственные
        // волты и так авторизуются локальным keyset (фолбэк). Отвергаем явно.
        if ed == state.keyset.signing.verifying.to_bytes() {
            return Err(FfiError::Other {
                msg: "cannot pin your own keyset as a vault trust anchor".into(),
            });
        }
        pin_and_verify_vault_anchor(&state.storage, &vid, &ed).map_err(map_vault_err)
    }

    /// Назначает ЛИЧНЫЙ волт аккаунта (A3.2): указатель хранится в per-account
    /// состоянии (self-sealed payload, синкается на устройства аккаунта). `vault_id`
    /// — hex cloud-волта ИЛИ произвольный UTF-8-id локального (оффлайн) волта:
    /// личный волт может быть и полностью локальным (самый приватный вариант —
    /// идентичности не покидают устройство). Требует unlock. Инкрементит версию.
    ///
    /// Guard (B5.3): личный волт должен быть single-member — в него пишутся
    /// идентичности и привязки, а расшаренный (multi-member) волт синкает их всей
    /// команде (утечка личных кредов + факта/цели привязки). >1 члена → отказ;
    /// у локального волта membership-цепочки нет (0 членов) → проходит.
    pub fn set_personal_vault(&self, vault_id: String) -> Result<(), FfiError> {
        let vid = {
            let mut guard = self.locked_state();
            let state = guard.as_mut().ok_or(FfiError::Locked)?;
            // resolve_vid принимает и локальный (UTF-8), и cloud (hex) id; decode_vid
            // был hex-only и отвергал локальные волты.
            let vid = resolve_vid(&state.storage, &vault_id);
            let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
            let members = match state
                .storage
                .latest_membership_epoch(&vid)
                .map_err(FfiError::other)?
            {
                Some(latest) => verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
                    .map_err(map_vault_err)?
                    .members()
                    .len(),
                None => 0, // локальный / ещё-не-расшаренный волт — членов нет
            };
            if members > 1 {
                return Err(FfiError::other(
                    "cannot use a shared (multi-member) vault as your personal vault",
                ));
            }
            vid
        }; // guard освобождён до update_account_state (он лочит state сам)
        self.update_account_state(move |p| p.personal_vault_id = vid)
    }

    /// Account-default username (A3.2): используется в резолве логина, когда у хоста
    /// нет своего. Пустая строка очищает. Требует unlock.
    pub fn set_account_default_username(&self, username: String) -> Result<(), FfiError> {
        self.update_account_state(move |p| p.default_username = username)
    }

    /// Личный волт аккаунта, если назначен. Id отдаётся в ТОМ ЖЕ представлении, что
    /// и `list_vaults` (иначе UI не сматчит: local-волт там UTF-8-строкой, cloud —
    /// hex). Локальный существующий волт → сырая UTF-8-строка; cloud или неизвестный
    /// (напр. удалён) → hex (как раньше).
    pub fn get_personal_vault(&self) -> Result<Option<String>, FfiError> {
        let raw = match self.read_account_state()? {
            Some(p) if !p.personal_vault_id.is_empty() => p.personal_vault_id,
            _ => return Ok(None),
        };
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let display = match state.storage.get_vault(&raw).map_err(FfiError::other)? {
            Some(rec) if !matches!(rec.sync_target, SyncTarget::Cloud) => {
                String::from_utf8_lossy(&raw).to_string()
            }
            _ => hex::encode(&raw),
        };
        Ok(Some(display))
    }

    /// Account-default username, если задан.
    pub fn get_account_default_username(&self) -> Result<Option<String>, FfiError> {
        Ok(self.read_account_state()?.and_then(|p| {
            if p.default_username.is_empty() {
                None
            } else {
                Some(p.default_username)
            }
        }))
    }

    /// **Eager-ротация Vault Key** cloud-волта (server-tz §6.2): новый VK',
    /// manifest на `epoch+1` над оставшимися, гранты под VK', re-wrap живых
    /// item-ключей, подъём пола эпохи (атомарно). Владелец (этот keyset) всегда
    /// остаётся `Admin` в наборе. `remaining_member_pubkeys` — дополнительные
    /// оставшиеся члены как `(ed25519_hex, x25519_hex, role)`; отсутствующие в
    /// списке (кроме владельца) считаются отозванными. Возвращает новую эпоху.
    pub fn rotate_vk(
        &self,
        vault_id: String,
        remaining_member_pubkeys: Vec<RemainingMember>,
    ) -> Result<u64, FfiError> {
        let vid = decode_vid(&vault_id)?;
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
        let owner_x = state.keyset.encryption.public.to_bytes().to_vec();

        // строим набор оставшихся: владелец Admin + переданные.
        let mut members: Vec<Member> = vec![Member {
            ed25519_pub: owner_ed.clone(),
            role: MemberRole::Admin,
        }];
        let mut grants: Vec<(Vec<u8>, Vec<u8>, MemberRole)> =
            vec![(owner_x, owner_ed.clone(), MemberRole::Admin)];
        for rm in &remaining_member_pubkeys {
            let ed = decode_pubkey32("ed25519", &rm.ed25519_pub_hex)?;
            let x = decode_pubkey32("x25519", &rm.x25519_pub_hex)?;
            if ed == owner_ed {
                continue; // владелец уже добавлен
            }
            members.push(Member {
                ed25519_pub: ed.clone(),
                role: rm.role.to_core(),
            });
            grants.push((x, ed, rm.role.to_core()));
        }

        let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
        vault
            .rotate_vk(&state.keyset, &members, &grants)
            .map_err(map_vault_err)
    }

    /// **Кооперативный hard-delete** cloud-волта (server-tz §6.4): физически
    /// стирает запись/items/историю/манифесты/гранты/пол эпохи и зануляет VK.
    /// Best-effort/гигиена, НЕ remote-wipe (модифицированный клиент данные оставит).
    pub fn purge_vault(&self, vault_id: String) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
        vault.purge_vault().map_err(map_vault_err)?;
        state.vault_names.remove(&vid);
        Ok(())
    }

    /// Member-aware аудит целостности cloud-волта (server-tz §6.2): D1-цепочка +
    /// пол эпохи. Отчёт без секретов. (Для local-волтов — `verify_vault_integrity`.)
    pub fn verify_chain(&self, vault_id: String) -> Result<VaultIntegrityReport, FfiError> {
        let vid = decode_vid(&vault_id)?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
        let report = vault.verify_chain().map_err(map_vault_err)?;
        Ok(integrity_report_to_ffi(report))
    }

    /// Локальный account-id (server-tz §2.1): генерится один раз и персистится в
    /// storage-meta; последующие вызовы возвращают тот же id. Открытый
    /// идентификатор (НЕ секрет), hex (16 байт). Требует unlock (storage).
    pub fn account_id(&self) -> Result<String, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let id = ensure_account_id(&state.storage)?;
        Ok(hex::encode(id))
    }

    /// Self-attested registration-блоб (server-tz §2.1): связывает account-id с
    /// публичными ключами keyset и подписывает Ed25519-ключом keyset. Непрозрачный
    /// подписанный блоб (НЕ секрет) — публикуется серверу. Требует unlock.
    pub fn build_registration(&self) -> Result<Vec<u8>, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let id = ensure_account_id(&state.storage)?;
        build_registration(&state.keyset, &id).map_err(map_keychain_err)
    }

    /// Как [`Core::build_registration`], но возвращает И канонический payload, И
    /// подпись — сервер требует оба поля (`registration_payload` +
    /// `registration_signature`). payload строится в ядре, чтобы UI не пересобирал
    /// каноническую форму (риск рассинхрона байт → отказ верификации на сервере).
    pub fn build_registration_request(&self) -> Result<RegistrationRequest, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let id = ensure_account_id(&state.storage)?;
        let (payload, signature) =
            build_registration_request(&state.keyset, &id).map_err(map_keychain_err)?;
        Ok(RegistrationRequest { payload, signature })
    }

    /// Подписывает серверный challenge Ed25519-ключом keyset (server-tz §2.2,
    /// домен `unissh-server-auth-v1`). Возвращает блоб подписи (НЕ секрет);
    /// приватный ключ наружу не идёт. Проверку nonce/срока делает сервер.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_server_challenge(
        &self,
        host: String,
        account_id: String,
        device_id: String,
        key_id: String,
        nonce: Vec<u8>,
        expiry: u64,
    ) -> Result<Vec<u8>, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let challenge = ServerAuthChallenge {
            host: host.into_bytes(),
            account_id: account_id.into_bytes(),
            device_id: device_id.into_bytes(),
            key_id: key_id.into_bytes(),
            nonce,
            expiry,
        };
        sign_server_challenge(&state.keyset, &challenge).map_err(map_keychain_err)
    }

    /// Как [`Core::sign_server_challenge`], но принимает идентификаторы как **сырые
    /// байты** (host/account_id/device_id/key_id), а не UTF-8-строки. Нужно для
    /// серверного auth-флоу: сервер выдаёт `account_id`/`device_id` случайными 16
    /// байтами (НЕ UTF-8), а подпись/проверку challenge ведёт над сырыми байтами
    /// (`ids::unb64` → `ServerAuthChallenge::canonical`). Строковый вариант
    /// подписал бы UTF-8-байты строки → mismatch. Возвращает блоб подписи (НЕ
    /// секрет); проверку nonce/срока делает сервер.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_server_challenge_raw(
        &self,
        host: Vec<u8>,
        account_id: Vec<u8>,
        device_id: Vec<u8>,
        key_id: Vec<u8>,
        nonce: Vec<u8>,
        expiry: u64,
    ) -> Result<Vec<u8>, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let challenge = ServerAuthChallenge {
            host,
            account_id,
            device_id,
            key_id,
            nonce,
            expiry,
        };
        sign_server_challenge(&state.keyset, &challenge).map_err(map_keychain_err)
    }

    /// Читает cache-policy волта (server-tz §6.6). `vault_id` — hex (cloud).
    pub fn get_cache_policy(&self, vault_id: String) -> Result<FfiCachePolicy, FfiError> {
        let vid = decode_vid(&vault_id)?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let rec = state
            .storage
            .get_vault(&vid)
            .map_err(FfiError::other)?
            .ok_or(FfiError::NotFound)?;
        Ok(FfiCachePolicy::from_core(rec.cache_policy))
    }

    /// Меняет cache-policy волта (version+1, переподпись записи). `vault_id` — hex.
    pub fn set_cache_policy(
        &self,
        vault_id: String,
        policy: FfiCachePolicy,
    ) -> Result<(), FfiError> {
        let vid = decode_vid(&vault_id)?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let mut vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(map_vault_err)?;
        vault
            .set_cache_policy(policy.to_core())
            .map_err(map_vault_err)
    }

    /// Дописывает подписанную аудит-запись (server-tz §8): storage хранит
    /// `(entry_blob, signature, author_pubkey)` как есть, присваивает монотонный
    /// seq. Подпись/верификацию делает слой выше — FFI переносит непрозрачные
    /// блобы. `vault_id`/`author_pubkey` — hex. (vault_id в storage-audit v1 не
    /// хранится — инстанс-уровневый лог; принимается для будущего vault-scoping.)
    pub fn audit_append(
        &self,
        vault_id: String,
        entry_blob: Vec<u8>,
        signature: Vec<u8>,
        author_pubkey: String,
    ) -> Result<u64, FfiError> {
        let _vid = decode_vid(&vault_id)?; // валидация формата (на будущее)
        let author = hex::decode(author_pubkey.trim())
            .map_err(|_| FfiError::other("invalid hex author_pubkey"))?;
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        state
            .storage
            .append_audit(&entry_blob, &signature, &author)
            .map_err(FfiError::other)
    }

    /// Записи аудита с `seq > since_seq` (server-tz §8, admin-view). Блобы
    /// непрозрачны; seq — открытая метадата (НЕ доверенная для tamper-evidence v1).
    pub fn audit_query(&self, since_seq: u64) -> Result<Vec<FfiAuditEntry>, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        Ok(state
            .storage
            .list_audit(since_seq)
            .map_err(FfiError::other)?
            .into_iter()
            .map(|e| FfiAuditEntry {
                seq: e.seq,
                entry_blob: e.entry_blob,
                signature: e.signature,
                author_pubkey_hex: hex::encode(&e.author_pubkey),
                recorded_at: e.recorded_at,
            })
            .collect())
    }

    /// **Онбординг Path A** (server-tz §9): новое устройство принимает зашифрованный
    /// keyset-блоб «с сервера», распаковывает его паролем + Secret Key, персистит
    /// блоб в локальный сайдкар (уже-зашифрован — не секрет) и открывает БД
    /// инстанса. Не требует предварительного локального keyset.
    ///
    /// Anti-rollback: db-ключ выводится из распакованного keyset → сначала
    /// `unlock_account` (AEAD-аутентификация кредов и деривация ключа), затем
    /// открытие БД, затем подъём generation-пола до принятой записи (TOFU при
    /// первом онбординге; понизить пол нельзя). v1 honest gap: confidentiality
    /// есть, freshness относительно сервера — на слое выше.
    pub fn unlock_from_server_blob(
        &self,
        keyset_blob: Vec<u8>,
        password: Option<String>,
        secret_key_hex: String,
    ) -> Result<(), FfiError> {
        // Один guard на весь метод (сериализация + финальная установка состояния):
        // Mutex не reentrant, повторный self.locked_state() здесь → дедлок.
        let mut guard = self.locked_state();
        let password = password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let enc = EncryptedKeyset::from_bytes(&keyset_blob).map_err(FfiError::other)?;
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        // migrate-on-open: легаси-блоб (до round 2) от старого устройства открывается
        // пробой и сразу переоборачивается под текущую схему — в локальный сайдкар
        // ляжет уже v3 (`migrated`), офлайн-unlock дальше пойдёт без пробы.
        let (unlocked, migrated) =
            unlock_account_migrating(&enc, password.as_deref().map(|s| s.as_bytes()), &secret_key)
                .map_err(map_keychain_err)?;

        // db-ключ выводится из распакованного keyset, поэтому пол (в storage-meta)
        // доступен только ПОСЛЕ unlock+open. Распаковка raw-крипто (AEAD-проверка
        // кредов) не вводит keyset в систему и не создаёт побочных эффектов; приём
        // блоба = персист сайдкара + установка состояния НИЖЕ, и оба отсекаются
        // anti-rollback ДО них.
        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(FfiError::other)?;

        // anti-rollback (server-tz §13.13b): ОТВЕРГАЕМ устаревшую generation ДО
        // приёма блоба. Прежняя версия только поднимала пол (raise) — устаревший
        // keyset-блоб ниже пола проходил вопреки докстрингу. Та же логика, что в
        // unlock_account_checked (которую нельзя вызвать раньше: storage ещё закрыт).
        let floor = unissh_keychain::keyset_gen_floor(&storage)
            .map_err(map_keychain_err)?
            .unwrap_or(0);
        let attempted = enc.generation as u64;
        if attempted < floor {
            // Security event: an on-disk keyset older than the recorded floor — a
            // possible downgrade attack. Generations are counters, not secrets.
            log::warn!(
                "keyset generation rollback rejected (attempted={attempted}, floor={floor})"
            );
            return Err(map_keychain_err(
                unissh_keychain::KeychainError::GenerationRollback { attempted, floor },
            ));
        }

        // Персистим keyset-блоб в локальный сайдкар (атомарно), чтобы офлайн-unlock
        // работал далее. Уже-зашифрованный блоб — не секрет. Если блоб был легаси,
        // на диск ложится переобёрнутая (v3, generation+1) запись. Персист ДО подъёма
        // пола — защита от кирпича (см. `unlock`). Пол поднимаем до фактической
        // (персистнутой) generation.
        let record_to_persist = migrated.as_ref().unwrap_or(&enc);
        let accepted_gen = record_to_persist.generation as u64;
        // Бэкап существующего сайдкара только если перезапись — это миграция легаси-блоба
        // (логирует путь). Обычный приём server-блоба не трогаем.
        if migrated.is_some() {
            backup_keyset_sidecar(&self.keyset_path);
        }
        let enc_bytes = record_to_persist.to_bytes().map_err(FfiError::other)?;
        write_keyset_atomic(&self.keyset_path, &enc_bytes)?;
        if migrated.is_some() {
            log::info!(
                "keyset migrated to current scheme on server-blob unlock (generation {} -> {})",
                attempted,
                accepted_gen
            );
        }
        // Принято: поднять пол до принятой generation (TOFU; понизить нельзя).
        unissh_keychain::raise_keyset_gen_floor(&storage, accepted_gen)
            .map_err(map_keychain_err)?;

        *guard = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        log::info!("instance unlocked from server keyset");
        Ok(())
    }

    /// **Онбординг Path B (initiator):** завершает PAKE по `msg2` responder'а,
    /// проверяет подтверждение и E2E-шифрует секреты keyset + **общий аккаунтный
    /// Secret Key** (`secret_key_hex`) под канальным ключом. Возвращает `msg3`
    /// (sealed keyset — релей-блоб; sealed, не plaintext-секрет). Требует
    /// разблокированного keyset. Хэндл одноразовый (повторный вызов → Other).
    ///
    /// `secret_key_hex` — Secret Key ЭТОГО устройства (его читает Tauri-слой из
    /// кейчейна; Core ключ в памяти не держит), чтобы все устройства аккаунта
    /// делили один ключ (модель 1Password).
    pub fn onboard_confirm_and_seal(
        &self,
        handle: Arc<OnboardInitiatorHandle>,
        msg2: Vec<u8>,
        secret_key_hex: String,
    ) -> Result<Vec<u8>, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;
        let init = handle
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| FfiError::other("onboard initiator step already consumed"))?;
        init.confirm_and_seal(&msg2, &state.keyset, &secret_key)
            .map_err(map_keychain_err)
    }

    /// **Онбординг Path B (responder):** принимает `msg3`, проверяет подтверждение,
    /// расшифровывает payload (секреты keyset + **общий аккаунтный Secret Key**) и
    /// ставит собственную device-запись под этим общим ключом и локальным
    /// `password`, персистит keyset-сайдкар и открывает БД инстанса. Возвращает
    /// общий Secret Key (hex), чтобы Tauri-слой сохранил его в кейчейн устройства
    /// для будущих разблокировок. Не требует предварительного состояния. Одноразовый.
    pub fn onboard_finish_install(
        &self,
        handle: Arc<OnboardResponderHandle>,
        msg3: Vec<u8>,
        password: Option<String>,
    ) -> Result<String, FfiError> {
        // Один guard на весь метод (Mutex не reentrant — см. unlock_from_server_blob).
        let mut guard = self.locked_state();
        if self.keyset_path.exists() || self.db_path.exists() {
            return Err(FfiError::AlreadyExists);
        }
        let password = password.map(Zeroizing::new);
        let resp = handle
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| FfiError::other("onboard responder step already consumed"))?;
        let (secret_key, enc, unlocked) = resp
            .finish_install(
                &msg3,
                password.as_deref().map(|s| s.as_bytes()),
                KdfParams::recommended(),
            )
            .map_err(map_keychain_err)?;

        let db_key = derive_db_key(&unlocked);
        let storage = Storage::open(&self.db_path, &db_key[..]).map_err(|e| {
            let _ = std::fs::remove_file(&self.db_path);
            FfiError::other(e)
        })?;
        let enc_bytes = enc.to_bytes().map_err(FfiError::other)?;
        // sealed keyset-сайдкар (O_EXCL): при сбое — откат БД/сайдкара.
        match open_keyset_file(&self.keyset_path, true) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(&enc_bytes) {
                    drop(storage);
                    let _ = std::fs::remove_file(&self.keyset_path);
                    let _ = std::fs::remove_file(&self.db_path);
                    return Err(FfiError::other(e));
                }
            }
            Err(e) => {
                drop(storage);
                let _ = std::fs::remove_file(&self.db_path);
                return Err(FfiError::other(e));
            }
        }
        // anti-rollback пол: TOFU на generation принятого keyset.
        unissh_keychain::raise_keyset_gen_floor(&storage, enc.generation as u64)
            .map_err(map_keychain_err)?;

        *guard = Some(CoreState {
            storage,
            keyset: unlocked,
            agent: InMemoryAgent::new(),
            vault_names: HashMap::new(),
        });
        // ОБЩИЙ аккаунтный Secret Key (одинаков на всех устройствах, модель A):
        // возвращаем hex, чтобы Tauri-слой сохранил его в кейчейн ЭТОГО устройства
        // для будущих разблокировок. Пользователю НЕ показываем — нового Emergency
        // Kit нет, у него уже есть аккаунтный. Промежуточный hex зануляем; строка
        // через границу FFI — вне нашего контроля (ограничение FFI).
        let kit = Zeroizing::new(hex::encode(secret_key.expose_bytes()));
        Ok(kit.as_str().to_string())
    }

    /// **Запускает синк** против foreign-транспорта (server-tz §3.3): сначала push
    /// локальных объектов, затем pull+verify-before-apply дельты. Транспорт
    /// недоверенный — каждый объект верифицируется (подпись/эпоха-пол/авторитет)
    /// до применения. Возвращает сведённый отчёт (без секретов). Требует unlock.
    ///
    /// `tenant_b64` — base64-`tenant_id` синкаемого сервера (как в
    /// `ServerConfig.tenant_id`). **1:1-привязка:** push отдаёт ТОЛЬКО cloud-волты,
    /// привязанные к этому tenant (см. `sync_push`); локальные и привязанные к
    /// другим серверам волты не уходят. Пустой `tenant_b64` → ничего не пушится.
    pub fn sync_now(
        &self,
        transport: Arc<dyn FfiSyncTransport>,
        tenant_b64: String,
    ) -> Result<FfiSyncReport, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let genesis_owner = state.keyset.signing.verifying.to_bytes().to_vec();
        let ctx = SyncContext {
            genesis_owner,
            tenant: tenant_b64.as_bytes().to_vec(),
        };
        let mut adapter = ForeignTransportAdapter {
            inner: transport,
            push_err: Mutex::new(None),
        };

        // push: если коллбэк бросил — пробросить его ошибку (не маскировать Format).
        let push = sync_push(&mut adapter, &state.storage, tenant_b64.as_bytes()).map_err(|e| {
            if let Some(fe) = adapter
                .push_err
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                fe
            } else {
                map_sync_err(e)
            }
        })?;
        // pull
        let pull = sync_pull(&mut adapter, &state.storage, &ctx).map_err(map_sync_err)?;

        Ok(FfiSyncReport {
            applied: pull.applied,
            skipped_stale: pull.skipped_stale,
            conflicts: pull.conflicts.len() as u32,
            rejected: pull.rejected.len() as u32,
            pushed: push.pushed,
        })
    }

    /// Сбрасывает pull-курсор тенанта → следующий `sync_now` перечитывает ВСЮ
    /// историю сервера (полный re-pull), а не инкремент от последнего seq. Нужно,
    /// когда объекты уже были обработаны при ПРЕЖНЕМ authority-контексте и отвергнуты
    /// (reject двигает курсор), а keyset потом сменился на владельца (re-attach):
    /// без сброса владелец не перечитает волт, который теперь может расшифровать.
    /// `tenant_b64` — та же строка, что передаётся в `sync_now` (ключ курсора
    /// строится из её байт). Требует unlock.
    pub fn reset_pull_cursor(&self, tenant_b64: String) -> Result<(), FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        reset_pull_cursor(&state.storage, tenant_b64.as_bytes()).map_err(map_sync_err)
    }

    /// Восстанавливает облачные волты, удалённые ЛОКАЛЬНО (tombstone), но всё ещё
    /// живые на сервере. Локальный tombstone новее (версия выросла при удалении) →
    /// LWW не даёт pull'у его перезаписать серверной копией, а `list_vaults` его
    /// прячет: волт «застрял удалённым» на этом устройстве. Физически стираем его
    /// локальную запись (`purge_vault_data`) и сбрасываем pull-курсор тенанта →
    /// следующий `sync_now` перетянет живую серверную копию заново. Волты, удалённые
    /// И на сервере, после re-pull снова станут tombstone (не воскреснут — это верно).
    /// Трогаем только tombstone-волты, привязанные к ЭТОМУ тенанту или непривязанные
    /// (после снятия линка); чужие не трогаем. Возвращает число очищенных записей.
    /// Требует unlock.
    pub fn restore_deleted_cloud_vaults(&self, tenant_b64: String) -> Result<u32, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let tenant = tenant_b64.as_bytes();
        let mut restored = 0u32;
        for v in state
            .storage
            .list_tombstoned_cloud_vaults()
            .map_err(FfiError::other)?
        {
            if !v.sync_tenant.is_empty() && v.sync_tenant != tenant {
                continue; // привязан к ДРУГОМУ серверу — не наш, не трогаем
            }
            state
                .storage
                .purge_vault_data(&v.vault_id)
                .map_err(FfiError::other)?;
            state.vault_names.remove(&v.vault_id);
            restored += 1;
        }
        if restored > 0 {
            reset_pull_cursor(&state.storage, tenant).map_err(map_sync_err)?;
        }
        Ok(restored)
    }

    /// Переименовывает волт.
    pub fn rename_vault(&self, vault_id: String, new_name: String) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        // Resolve once: the name cache is keyed by the RAW vault id (the storage
        // key), so for a cloud vault we must insert under the decoded UUID bytes,
        // not the hex string — otherwise list_vaults reads a stale name.
        let vid = resolve_vid(&state.storage, &vault_id);
        let mut vault =
            Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
        vault
            .set_name(new_name.as_bytes())
            .map_err(FfiError::other)?;
        state.vault_names.insert(vid, new_name);
        Ok(())
    }

    /// Удаляет волт (tombstone). Из списка он исчезает.
    pub fn delete_vault(&self, vault_id: String) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vid = resolve_vid(&state.storage, &vault_id);
        let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
        vault.delete().map_err(FfiError::other)?;
        state.vault_names.remove(vid.as_slice());
        Ok(())
    }

    /// Удаляет item (tombstone) и, если он был SSH-ключом в агенте, выгружает его.
    pub fn delete_item(&self, vault_id: String, item_id: String) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .delete_item(item_id.as_bytes())
            .map_err(FfiError::other)?;
        // A4a namespace: агент хранит ключ под agent_key_id(vault_id,item_id), а не
        // под голым item_id — выгружать надо тем же ключом, иначе remove — no-op и
        // отозванный/ротированный приватник остаётся живым в агенте до конца сессии.
        state.agent.remove(&agent_key_id(&vault_id, &item_id));
        Ok(())
    }

    /// Сохраняет/обновляет пароль сервера как item волта (тип «пароль»).
    /// Контент — UTF-8 байты пароля; шифрование/подпись/версия — слой vault.
    /// (Вход пароля от UI допустим — он там и рождается; обратно — только через
    /// явный [`Core::get_password`].)
    pub fn save_password(
        &self,
        vault_id: String,
        item_id: String,
        password: String,
    ) -> Result<(), FfiError> {
        // Пароль немедленно в Zeroizing — зануляется при выходе.
        let password = Zeroizing::new(password);
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        ensure_item_type(
            &state.storage,
            &vault_id,
            item_id.as_bytes(),
            ITEM_TYPE_PASSWORD,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .put_item_keep_history(item_id.as_bytes(), ITEM_TYPE_PASSWORD, password.as_bytes())
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Возвращает пароль сервера (reveal: показать/скопировать в UI по явному
    /// действию пользователя). Работает **только** для item типа «пароль» —
    /// приватный ключ или иной item через этот вызов получить нельзя, инвариант
    /// «plaintext-ключи не пересекают FFI» сохраняется.
    ///
    /// ⚠️ Возвращаемая `String` уходит за FFI-границу и на той стороне не
    /// зануляется — UI отвечает за минимальное время жизни (показ/клипборд).
    pub fn get_password(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let password = read_password_item(state, &vault_id, &item_id)?;
        Ok(password.as_str().to_string())
    }

    /// Сохраняет/обновляет зашифрованную заметку как item волта (тип «заметка»).
    /// Контент — произвольный UTF-8 (recovery-коды, доступы к IPMI и т.п.).
    /// Шифрование/подпись/версия — слой vault; вход от UI допустим, обратно —
    /// только через явный [`Core::get_note`].
    pub fn save_note(
        &self,
        vault_id: String,
        item_id: String,
        text: String,
    ) -> Result<(), FfiError> {
        let text = Zeroizing::new(text);
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        ensure_item_type(
            &state.storage,
            &vault_id,
            item_id.as_bytes(),
            ITEM_TYPE_NOTE,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .put_item_keep_history(item_id.as_bytes(), ITEM_TYPE_NOTE, text.as_bytes())
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Возвращает текст заметки (reveal для UI). Работает **только** для item типа
    /// «заметка» — ключ/пароль/иной item через этот вызов получить нельзя.
    ///
    /// ⚠️ Возвращаемая `String` уходит за FFI-границу и там не зануляется — UI
    /// отвечает за её время жизни.
    pub fn get_note(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let text = read_utf8_item(state, &vault_id, &item_id, ITEM_TYPE_NOTE, "a note")?;
        Ok(text.as_str().to_string())
    }

    /// Версии item, доступные для reveal: текущая + архивные (история секрета).
    /// Возвращает только номера версий — секретов не раскрывает.
    pub fn list_item_versions(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<Vec<u64>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .list_item_versions(item_id.as_bytes())
            .map_err(FfiError::other)
    }

    /// Reveal конкретной версии пароля из истории (type-gated к «паролю»).
    pub fn get_password_version(
        &self,
        vault_id: String,
        item_id: String,
        version: u64,
    ) -> Result<String, FfiError> {
        self.read_item_version(
            &vault_id,
            &item_id,
            version,
            ITEM_TYPE_PASSWORD,
            "a password",
        )
    }

    /// Reveal конкретной версии заметки из истории (type-gated к «заметке»).
    pub fn get_note_version(
        &self,
        vault_id: String,
        item_id: String,
        version: u64,
    ) -> Result<String, FfiError> {
        self.read_item_version(&vault_id, &item_id, version, ITEM_TYPE_NOTE, "a note")
    }

    /// Список закреплённых host key (для экрана known_hosts).
    pub fn list_known_hosts(&self) -> Result<Vec<KnownHostInfo>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        Ok(state
            .storage
            .list_known_hosts()
            .map_err(FfiError::other)?
            .into_iter()
            .map(|h| KnownHostInfo {
                host: h.host,
                port: h.port,
                key: String::from_utf8_lossy(&h.host_key).to_string(),
                added_at: h.added_at,
            })
            .collect())
    }

    /// «Забыть» закреплённый host key. Возвращает, была ли запись.
    pub fn forget_host(&self, host: String, port: u16) -> Result<bool, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        state
            .storage
            .remove_known_host(&host, port)
            .map_err(FfiError::other)
    }

    /// Осознанно доверять НОВОМУ host key после [`FfiError::HostKeyMismatch`]:
    /// подключается напрямую (только хендшейк), сверяет предъявленный ключ с
    /// подтверждённым пользователем `expected_fingerprint` (из ошибки mismatch) и
    /// только при совпадении перезакрепляет его. Возвращает SHA256-отпечаток.
    /// Требует разблокировки.
    ///
    /// Если за время между предупреждением и согласием ключ снова подменили,
    /// вернётся `HostKeyMismatch` с фактическим отпечатком (закрепления не будет).
    /// Только прямые хосты (без ProxyJump): для джамп-целей — `forget_host` +
    /// обычное переподключение (повторный TOFU).
    pub fn trust_host(
        &self,
        host: String,
        port: u16,
        expected_fingerprint: String,
    ) -> Result<String, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        self.rt
            .block_on(trust_host_key(
                &host,
                port,
                &state.storage,
                &expected_fingerprint,
            ))
            .map_err(|e| match e {
                unissh_ssh_transport::TransportError::FingerprintMismatch { got, .. } => {
                    FfiError::HostKeyMismatch {
                        host: host.clone(),
                        port,
                        fingerprint: got,
                    }
                }
                other => map_transport_err(other),
            })
    }

    /// Меняет мастер-пароль инстанса (re-wrap keyset под новый Unlock Key).
    /// Требует старые креды (`old_password` + `secret_key_hex`) — это проверяет
    /// их корректность и исключает «кирпич». `new_password = None` → беспарольный
    /// режим (SecretKeyOnly). Можно вызывать в заблокированном состоянии (работает
    /// с записью keyset на диске).
    ///
    /// Меняется только **обёртка** keyset: Secret Key, секреты keyset и ключ БД
    /// не меняются, поэтому текущая разблокированная сессия (если есть) остаётся
    /// валидной. Это re-wrap, а НЕ ротация ключей (ротация VK — ⏳ ПОТОМ).
    pub fn change_password(
        &self,
        old_password: Option<String>,
        new_password: Option<String>,
        secret_key_hex: String,
    ) -> Result<(), FfiError> {
        // Держим лок состояния на всё время read-compute-write записи keyset:
        // сериализует против параллельного unlock/второго change_password (TOCTOU).
        let mut guard = self.locked_state();
        let old_password = old_password.map(Zeroizing::new);
        let new_password = new_password.map(Zeroizing::new);
        let secret_key_hex = Zeroizing::new(secret_key_hex);

        let enc_bytes = std::fs::read(&self.keyset_path).map_err(|_| FfiError::NotFound)?;
        let enc = EncryptedKeyset::from_bytes(&enc_bytes).map_err(FfiError::other)?;
        let sk_bytes = Zeroizing::new(
            hex::decode(secret_key_hex.trim()).map_err(|_| FfiError::InvalidCredentials)?,
        );
        let secret_key =
            SecretKey::from_slice(&sk_bytes).map_err(|_| FfiError::InvalidCredentials)?;

        let new_enc = change_password(
            &enc,
            old_password.as_deref().map(|s| s.as_bytes()),
            new_password.as_deref().map(|s| s.as_bytes()),
            &secret_key,
            KdfParams::recommended(),
        )
        .map_err(|e| match e {
            unissh_keychain::KeychainError::InvalidCredentials
            | unissh_keychain::KeychainError::PasswordRequired => FfiError::InvalidCredentials,
            other => FfiError::other(other),
        })?;

        let new_bytes = new_enc.to_bytes().map_err(FfiError::other)?;
        write_keyset_atomic(&self.keyset_path, &new_bytes)?;

        // anti-rollback (server-tz §13.13b): поднимаем доверенный пол поколения до
        // новой generation, иначе старый (понижённый) keyset-блоб снова прошёл бы
        // unlock_account_checked / unlock_from_server_blob после смены пароля. Пол
        // живёт в storage-meta инстанса: если волт уже разблокирован — берём его
        // открытый storage; иначе открываем БД (db-ключ инвариантен к re-wrap'у —
        // секреты keyset не меняются — поэтому выводим его из old-enc, креды к
        // которому только что подтвердил change_password).
        if let Some(state) = guard.as_mut() {
            unissh_keychain::raise_floor_after_change_password(&state.storage, &new_enc)
                .map_err(map_keychain_err)?;
        } else {
            let unlocked = unlock_account(
                &enc,
                old_password.as_deref().map(|s| s.as_bytes()),
                &secret_key,
            )
            .map_err(map_keychain_err)?;
            let db_key = derive_db_key(&unlocked);
            let storage = Storage::open(&self.db_path, &db_key[..]).map_err(FfiError::other)?;
            unissh_keychain::raise_floor_after_change_password(&storage, &new_enc)
                .map_err(map_keychain_err)?;
        }
        Ok(())
    }

    /// Список волтов. Имена берутся из кэша; для незакэшированных волтов —
    /// один разворот VK (HPKE) с занесением в кэш.
    pub fn list_vaults(&self) -> Result<Vec<VaultInfo>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let mut out = Vec::new();
        for record in state.storage.list_vaults().map_err(FfiError::other)? {
            let name = match state.vault_names.get(&record.vault_id) {
                Some(n) => n.clone(),
                None => {
                    let vault = Vault::open(&state.storage, &state.keyset, &record.vault_id)
                        .map_err(FfiError::other)?;
                    let name = String::from_utf8_lossy(vault.name()).to_string();
                    state
                        .vault_names
                        .insert(record.vault_id.clone(), name.clone());
                    name
                }
            };
            // Cloud vault_id — UUIDv4 (сырые 16 байт, не UTF-8): отдаём как hex,
            // чтобы он совпадал с возвратом `create_cloud_vault` и принимался
            // cloud-методами (`decode_vid` ждёт hex). Local vault_id — осмысленная
            // UTF-8-строка (round-trip через `as_bytes`), отдаём как есть.
            let vault_id = match record.sync_target {
                SyncTarget::Cloud => hex::encode(&record.vault_id),
                _ => String::from_utf8_lossy(&record.vault_id).to_string(),
            };
            // sync_tenant хранится как байты base64-строки tenant_id (непрозрачная
            // метка маршрутизации). Пусто = не привязан → None. Иначе отдаём ту же
            // base64-строку обратно, чтобы UI сопоставил волт со связанным сервером.
            let sync_tenant = if record.sync_tenant.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&record.sync_tenant).to_string())
            };
            out.push(VaultInfo {
                vault_id,
                name,
                sync_target: FfiSyncTarget::from_core(record.sync_target),
                sync_tenant,
            });
        }
        Ok(out)
    }

    /// Генерирует SSH-ключ Ed25519 **в ядре**, кладёт приватник зашифрованным в
    /// волт и возвращает **публичный** ключ (OpenSSH). Приватник наружу не отдаётся.
    pub fn generate_ssh_key(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let (private_pem, public) = generate_ed25519_openssh().map_err(FfiError::ssh)?;
        ensure_item_type(
            &state.storage,
            &vault_id,
            item_id.as_bytes(),
            ITEM_TYPE_SSH_KEY,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .put_item(
                item_id.as_bytes(),
                ITEM_TYPE_SSH_KEY,
                private_pem.as_bytes(),
            )
            .map_err(FfiError::other)?;
        // Заменили материал ключа под тем же id → выгружаем прежний приватник из
        // агента (namespaced), иначе коннекты в этой сессии продолжат подписывать
        // СТАРЫМ ключом (load_key_into_agent короткозамыкается на agent.contains).
        state.agent.remove(&agent_key_id(&vault_id, &item_id));
        Ok(public)
    }

    /// Импортирует существующий OpenSSH-приватник в волт. Возвращает публичный
    /// ключ. (Вход приватника от UI допустим; обратно он не отдаётся.)
    pub fn import_ssh_key(
        &self,
        vault_id: String,
        item_id: String,
        openssh_private: String,
        passphrase: Option<String>,
    ) -> Result<String, FfiError> {
        // Приватник и пароль держим в Zeroizing — зануляются при выходе.
        let openssh_private = Zeroizing::new(openssh_private);
        let passphrase = passphrase.map(Zeroizing::new);
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        // Принимаем не только OpenSSH-контейнер, но и классические PEM
        // (PKCS#1 `BEGIN RSA PRIVATE KEY`, SEC1 `BEGIN EC PRIVATE KEY`,
        // PKCS#8 `BEGIN PRIVATE KEY`, в т.ч. зашифрованные паролем): приводим к
        // каноничному OpenSSH-приватнику. Без пароля для зашифрованного ключа
        // вернётся ошибка `Encrypted` — UI запросит пароль и повторит.
        let normalized = unissh_ssh_agent::normalize_private_key_with_passphrase(
            &openssh_private,
            passphrase.as_deref().map(|p| p.as_str()),
        )
        .map_err(FfiError::ssh)?;
        // валидируем и извлекаем публичный ключ через временный агент
        let mut tmp = InMemoryAgent::new();
        tmp.add_from_openssh(b"tmp".to_vec(), normalized.as_bytes())
            .map_err(FfiError::ssh)?;
        let public = tmp
            .public_key(b"tmp")
            .ok_or_else(|| FfiError::ssh("no public key"))?
            .to_openssh()
            .map_err(FfiError::ssh)?;
        ensure_item_type(
            &state.storage,
            &vault_id,
            item_id.as_bytes(),
            ITEM_TYPE_SSH_KEY,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .put_item(item_id.as_bytes(), ITEM_TYPE_SSH_KEY, normalized.as_bytes())
            .map_err(FfiError::other)?;
        // Заменили материал ключа под тем же id → выгружаем прежний приватник из
        // агента (namespaced), иначе коннекты в этой сессии продолжат подписывать
        // СТАРЫМ ключом (load_key_into_agent короткозамыкается на agent.contains).
        state.agent.remove(&agent_key_id(&vault_id, &item_id));
        Ok(public)
    }

    /// Привязывает OpenSSH user-сертификат к ключу `key_item_id` (хранится как
    /// item `<key_item_id>.cert`). При коннекте аутентификация пойдёт по
    /// сертификату (подпись делает агент, приватник не покидает ядро).
    pub fn import_ssh_certificate(
        &self,
        vault_id: String,
        key_item_id: String,
        cert_openssh: String,
    ) -> Result<(), FfiError> {
        // валидируем сертификат
        unissh_ssh_agent::ssh_key::Certificate::from_openssh(cert_openssh.trim())
            .map_err(|_| FfiError::ssh("invalid certificate"))?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let cert_id = cert_item_id(&key_item_id);
        ensure_item_type(
            &state.storage,
            &vault_id,
            cert_id.as_bytes(),
            ITEM_TYPE_SSH_CERT,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .put_item(
                cert_id.as_bytes(),
                ITEM_TYPE_SSH_CERT,
                cert_openssh.as_bytes(),
            )
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Возвращает **публичный** ключ (OpenSSH) и его SHA256-отпечаток для
    /// существующего item-ключа — чтобы UI мог показать/скопировать его в
    /// `authorized_keys`. Приватник наружу не отдаётся.
    pub fn get_public_key(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<PublicKeyInfo, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let item = {
            let vault = Vault::open(
                &state.storage,
                &state.keyset,
                &resolve_vid(&state.storage, &vault_id),
            )
            .map_err(FfiError::other)?;
            vault
                .get_item(item_id.as_bytes())
                .map_err(FfiError::other)?
                .ok_or(FfiError::NotFound)?
        };
        if item.item_type != ITEM_TYPE_SSH_KEY {
            return Err(FfiError::other("item is not an SSH key"));
        }
        // Извлекаем публичный ключ через временный агент (приватник в Zeroizing
        // DecryptedItem; временный агент дропается по выходу).
        let mut tmp = InMemoryAgent::new();
        tmp.add_from_item(b"x".to_vec(), &item)
            .map_err(FfiError::ssh)?;
        let pubkey = tmp
            .public_key(b"x")
            .ok_or_else(|| FfiError::ssh("no public key"))?;
        let openssh = pubkey.to_openssh().map_err(FfiError::ssh)?;
        let fingerprint = pubkey
            .fingerprint(unissh_ssh_agent::ssh_key::HashAlg::Sha256)
            .to_string();
        Ok(PublicKeyInfo {
            openssh,
            fingerprint,
        })
    }

    /// ⚠️ Экспортирует **приватный** OpenSSH-ключ item'а наружу (бэкап/миграция).
    /// По умолчанию приватник из ядра не отдаётся; это явный, по запросу
    /// пользователя, экспорт его собственных данных. Возвращаемая строка уходит
    /// за FFI-границу и не зануляется — UI отвечает за её судьбу (предупредить,
    /// не логировать, писать в файл, не в общий буфер по умолчанию).
    pub fn export_ssh_key(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let item = vault
            .get_item(item_id.as_bytes())
            .map_err(FfiError::other)?
            .ok_or(FfiError::NotFound)?;
        if item.item_type != ITEM_TYPE_SSH_KEY {
            return Err(FfiError::other("item is not an SSH key"));
        }
        String::from_utf8(item.content.to_vec())
            .map_err(|_| FfiError::other("key is not valid UTF-8"))
    }

    /// Ротирует SSH-ключ **на том же item id**: генерирует новую пару Ed25519 и
    /// перезаписывает приватник под тем же идентификатором, поэтому все хосты,
    /// ссылающиеся на этот item, автоматически начинают использовать новый ключ —
    /// без «замены везде». Возвращает **новый публичный** ключ (его надо
    /// установить на серверы). Привязанный сертификат (если был) после ротации
    /// больше не соответствует ключу — UI должен предупредить о переустановке.
    pub fn rotate_ssh_key(&self, vault_id: String, item_id: String) -> Result<String, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        // Ключ должен существовать и быть SSH-ключом — нельзя «ротировать» пустоту.
        let existing = vault
            .get_item(item_id.as_bytes())
            .map_err(FfiError::other)?
            .ok_or(FfiError::NotFound)?;
        if existing.item_type != ITEM_TYPE_SSH_KEY {
            return Err(FfiError::other("item is not an SSH key"));
        }
        let (private_pem, public) = generate_ed25519_openssh().map_err(FfiError::ssh)?;
        vault
            .put_item(
                item_id.as_bytes(),
                ITEM_TYPE_SSH_KEY,
                private_pem.as_bytes(),
            )
            .map_err(FfiError::other)?;
        // Привязанный сертификат больше не соответствует новой паре — удаляем его,
        // иначе `load_key_into_agent` переприкрепит несоответствующий cert при
        // следующем коннекте и cert-аутентификация молча сломается.
        let cert = cert_item_id(&item_id);
        if vault
            .get_item(cert.as_bytes())
            .map_err(FfiError::other)?
            .is_some()
        {
            vault
                .delete_item(cert.as_bytes())
                .map_err(FfiError::other)?;
        }
        // Выгружаем старый ключ из in-memory агента (как delete_item/rename_item),
        // иначе коннекты в этой сессии продолжат использовать прежнюю пару, т.к.
        // `load_key_into_agent` короткозамыкается на `agent.contains()`.
        // A4a namespace: агент хранит ключ под agent_key_id(vault_id,item_id), а не
        // под голым item_id — выгружать надо тем же ключом, иначе remove — no-op и
        // отозванный/ротированный приватник остаётся живым в агенте до конца сессии.
        state.agent.remove(&agent_key_id(&vault_id, &item_id));
        Ok(public)
    }

    /// Переименовывает (перемещает) item на новый id. Переносит привязанный
    /// сертификат (`<key>.cert`) и выгружает старый ключ из агента.
    pub fn rename_item(
        &self,
        vault_id: String,
        item_id: String,
        new_item_id: String,
    ) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .rename_item(item_id.as_bytes(), new_item_id.as_bytes())
            .map_err(map_vault_err)?;
        // Перенести сертификат, если он был привязан к старому id.
        let old_cert = cert_item_id(&item_id);
        if vault
            .get_item(old_cert.as_bytes())
            .map_err(FfiError::other)?
            .is_some()
        {
            vault
                .rename_item(old_cert.as_bytes(), cert_item_id(&new_item_id).as_bytes())
                .map_err(map_vault_err)?;
        }
        // A4a namespace: агент хранит ключ под agent_key_id(vault_id,item_id), а не
        // под голым item_id — выгружать надо тем же ключом, иначе remove — no-op и
        // отозванный/ротированный приватник остаётся живым в агенте до конца сессии.
        state.agent.remove(&agent_key_id(&vault_id, &item_id));
        Ok(())
    }

    /// Список items волта.
    pub fn list_items(&self, vault_id: String) -> Result<Vec<ItemInfo>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let metas = vault.list_items().map_err(FfiError::other)?;
        // Множество всех id — чтобы дёшево (без расшифровки) определить, есть ли у
        // ключа привязанный сертификат (`<key>.cert`).
        let ids: std::collections::HashSet<&[u8]> =
            metas.iter().map(|m| m.item_id.as_slice()).collect();
        Ok(metas
            .iter()
            .map(|m| {
                let item_id = String::from_utf8_lossy(&m.item_id).to_string();
                let has_certificate = m.item_type == ITEM_TYPE_SSH_KEY
                    && ids.contains(cert_item_id(&item_id).as_bytes());
                ItemInfo {
                    item_id,
                    item_type: m.item_type,
                    version: m.version,
                    created_at: m.created_at,
                    updated_at: m.updated_at,
                    has_certificate,
                }
            })
            .collect())
    }

    /// Подключается по SSH (опционально через ProxyJump-цепочку) и выполняет
    /// команду. Ключи берутся из волта в агент; наружу не отдаются.
    #[allow(clippy::too_many_arguments)]
    pub fn ssh_exec(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        command: String,
        jumps: Vec<JumpHost>,
    ) -> Result<SshExecResult, FfiError> {
        // Коннект+аутентификация — под локом Core (нужны agent+storage). Затем
        // лок отпускаем, и команду выполняем уже без него.
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let output = self
            .rt
            .block_on(client.exec(&command))
            .map_err(FfiError::ssh)?;
        let _ = self.rt.block_on(client.disconnect());

        Ok(SshExecResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_status: output.exit_status.map(|c| c as i32).unwrap_or(-1),
        })
    }

    /// Потоковый exec (без PTY): stdout/stderr стримятся в `observer` раздельно,
    /// код возврата — через `on_exit`. Возвращает хэндл для stdin/закрытия/опроса
    /// завершения. Лок Core держится только на время коннекта.
    #[allow(clippy::too_many_arguments)]
    pub fn ssh_exec_stream(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        command: String,
        jumps: Vec<JumpHost>,
        observer: Arc<dyn ExecObserver>,
    ) -> Result<Arc<ExecHandleFfi>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let sink: Arc<dyn unissh_ssh_transport::ExecSink> = Arc::new(ExecSinkBridge(observer));
        let handle = self
            .rt
            .block_on(client.exec_stream(&command, sink))
            .map_err(FfiError::ssh)?;
        Ok(Arc::new(ExecHandleFfi {
            _client: Mutex::new(client),
            handle,
            rt: self.rt.clone(),
        }))
    }

    /// Задаёт интервал SSH keepalive (секунды) для последующих подключений;
    /// `0` — выключить. Глобальная настройка (не требует разблокировки): касается
    /// всех новых сессий, туннелей и бродкаста. На уже открытые не влияет.
    pub fn set_keepalive_secs(&self, secs: u64) {
        unissh_ssh_transport::set_keepalive_secs(secs);
    }

    /// Открывает интерактивную PTY-сессию. Вывод терминала стримится в
    /// `observer` (callback). Возвращает объект сессии для ввода/ресайза/закрытия.
    /// Лок Core держится только на время коннекта, не на время сессии.
    #[allow(clippy::too_many_arguments)]
    pub fn open_session(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        term: String,
        cols: u32,
        rows: u32,
        observer: Arc<dyn SessionObserver>,
    ) -> Result<Arc<SshSession>, FfiError> {
        check_term_size(cols, rows)?;
        let client = self.connect_session(&auth, &jumps, host, port, user)?;

        let sink: Arc<dyn OutputSink> = Arc::new(ObserverSink(observer));
        let shell = self
            .rt
            .block_on(client.open_shell(&term, cols, rows, sink))
            .map_err(FfiError::ssh)?;

        Ok(Arc::new(SshSession {
            _client: Mutex::new(client),
            shell,
            rt: self.rt.clone(),
        }))
    }

    /// Открывает интерактивную PTY-сессию с авто-реконнектом: при обрыве (ошибка
    /// `write`) или по `reconnect()` сессия переустанавливается до `max_retries`
    /// раз с линейным backoff (`backoff_ms`). Креды переразрешаются из волта на
    /// каждой попытке; `HostKeyMismatch` не реконнектится. Начальный коннект тоже
    /// с ретраями; ошибка после исчерпания попыток возвращается.
    #[allow(clippy::too_many_arguments)]
    pub fn open_reconnecting_session(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        term: String,
        cols: u32,
        rows: u32,
        max_retries: u32,
        backoff_ms: u32,
        observer: Arc<dyn SessionObserver>,
    ) -> Result<Arc<ReconnectingSession>, FfiError> {
        check_term_size(cols, rows)?;
        let session = Arc::new(ReconnectingSession {
            state: self.state.clone(),
            rt: self.rt.clone(),
            host,
            port,
            user,
            auth,
            jumps,
            term,
            cols,
            rows,
            max_retries,
            backoff_ms,
            observer,
            current: Mutex::new(None),
            reconnect_lock: Mutex::new(()),
        });
        session.connect_with_retry()?;
        Ok(session)
    }

    /// Выполняет одну команду на нескольких хостах. Коннекты — последовательно
    /// (под локом Core), выполнение — конкурентно. Ошибка по хосту не валит
    /// остальные: она кладётся в `error` соответствующего результата.
    ///
    /// `max_concurrency` ограничивает число одновременно выполняемых команд
    /// (0 = без лимита). `timeout_secs` — per-host дедлайн на выполнение команды
    /// (0 = без таймаута); по истечении результат помечается `timed_out`, хост
    /// отключается, остальные продолжают. Защищает флот от исчерпания ресурсов и
    /// от зависших хостов.
    pub fn ssh_exec_multi(
        &self,
        targets: Vec<MultiExecTarget>,
        command: String,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<MultiExecResult>, FfiError> {
        if !self.is_unlocked() {
            return Err(FfiError::Locked);
        }

        // Фаза коннекта (под локом, последовательно).
        let mut connected: Vec<(String, SshClient)> = Vec::new();
        let mut results: Vec<MultiExecResult> = Vec::new();
        for t in &targets {
            match self.connect_session(&t.auth, &t.jumps, t.host.clone(), t.port, t.user.clone()) {
                Ok(client) => connected.push((t.host.clone(), client)),
                Err(e) => results.push(MultiExecResult {
                    host: t.host.clone(),
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_status: -1,
                    error: Some(e.to_string()),
                    duration_ms: 0,
                    timed_out: false,
                }),
            }
        }

        // Фаза выполнения (конкурентно, с опциональными лимитом и таймаутом).
        let timeout_dur =
            (timeout_secs > 0).then(|| tokio::time::Duration::from_secs(timeout_secs as u64));
        let sem = (max_concurrency > 0)
            .then(|| Arc::new(tokio::sync::Semaphore::new(max_concurrency as usize)));
        let exec_results = self.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for (host, client) in connected {
                let cmd = command.clone();
                let sem = sem.clone();
                set.spawn(async move {
                    // Пермит держим на всё время exec → не больше max_concurrency
                    // команд одновременно (acquire_owned не падает: семафор не
                    // закрывается).
                    let _permit = match &sem {
                        Some(s) => Some(s.clone().acquire_owned().await.expect("semaphore open")),
                        None => None,
                    };
                    let started = std::time::Instant::now();
                    // None → команда не уложилась в таймаут.
                    let outcome = match timeout_dur {
                        Some(d) => tokio::time::timeout(d, client.exec(&cmd)).await.ok(),
                        None => Some(client.exec(&cmd).await),
                    };
                    let elapsed = started.elapsed().as_millis() as u64;
                    let _ = client.disconnect().await;
                    (host, outcome, elapsed)
                });
            }
            let mut out = Vec::new();
            while let Some(joined) = set.join_next().await {
                if let Ok(triple) = joined {
                    out.push(triple);
                }
            }
            out
        });

        for (host, outcome, duration_ms) in exec_results {
            match outcome {
                Some(Ok(o)) => results.push(MultiExecResult {
                    host,
                    stdout: String::from_utf8_lossy(&o.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&o.stderr).to_string(),
                    exit_status: o.exit_status.map(|c| c as i32).unwrap_or(-1),
                    error: None,
                    duration_ms,
                    timed_out: false,
                }),
                Some(Err(e)) => results.push(MultiExecResult {
                    host,
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_status: -1,
                    error: Some(e.to_string()),
                    duration_ms,
                    timed_out: false,
                }),
                None => results.push(MultiExecResult {
                    host,
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_status: -1,
                    error: Some(format!("command timed out after {timeout_secs}s")),
                    duration_ms,
                    timed_out: true,
                }),
            }
        }
        Ok(results)
    }

    /// Строит цели multi-exec из профилей волта, чьи теги совпадают с запросом
    /// (`match_all`: все теги запроса ⊆ тегов профиля; иначе пересечение). Пустой
    /// запрос → пустой результат. Это выборка целей, не RBAC.
    ///
    /// `PromptPassword` исключается (нет заранее известного пароля — иначе
    /// пакетный прогон делал бы live-коннект с пустым паролем). `Personal`
    /// резолвится per-host (привязка + анти-редирект): привязанный включается с
    /// разрешёнными user+auth, непривязанный/редиректнутый молча пропускается
    /// (подключить индивидуально). Пустой пароль в пакет не уходит никогда.
    pub fn select_targets_by_tags(
        &self,
        vault_id: String,
        tags: Vec<String>,
        match_all: bool,
    ) -> Result<Vec<MultiExecTarget>, FfiError> {
        let profiles = self.list_connections(vault_id.clone())?;
        let mut out = Vec::new();
        for p in profiles
            .into_iter()
            .filter(|p| tags_match(&p.tags, &tags, match_all))
        {
            match &p.auth {
                ProfileAuth::PromptPassword => {}
                ProfileAuth::Personal => {
                    let dest = self.personal_destination(
                        p.host.clone(),
                        p.port,
                        p.username_template.clone(),
                        p.jumps.clone(),
                    );
                    if let Ok(pa) = self.resolve_personal_auth(
                        vault_id.clone(),
                        p.uid.clone(),
                        dest,
                        p.user.clone(),
                    ) {
                        let user =
                            self.apply_username_template(pa.user, p.username_template.clone());
                        out.push(MultiExecTarget {
                            host: p.host,
                            port: p.port,
                            user,
                            auth: pa.auth,
                            jumps: p.jumps,
                        });
                    }
                }
                _ => out.push(profile_to_target(&vault_id, p)),
            }
        }
        Ok(out)
    }

    /// Выполняет команду на всех профилях с подходящими тегами (см.
    /// [`Core::select_targets_by_tags`] и [`Core::ssh_exec_multi`]).
    #[allow(clippy::too_many_arguments)]
    pub fn ssh_exec_by_tags(
        &self,
        vault_id: String,
        tags: Vec<String>,
        match_all: bool,
        command: String,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<MultiExecResult>, FfiError> {
        let targets = self.select_targets_by_tags(vault_id, tags, match_all)?;
        self.ssh_exec_multi(targets, command, max_concurrency, timeout_secs)
    }

    /// Раскладывает один blob (`data`) в `remote_path` на множестве хостов через
    /// SFTP. `make_parent_dirs` — попытаться создать родительский каталог (ошибка
    /// «уже существует» проглатывается). Коннекты последовательно (под локом
    /// Core), запись конкурентно с `max_concurrency`/per-host `timeout_secs`.
    /// Ошибка по хосту не валит остальные — она в `error` его результата.
    #[allow(clippy::too_many_arguments)]
    pub fn sftp_put_multi(
        &self,
        targets: Vec<MultiExecTarget>,
        remote_path: String,
        data: Vec<u8>,
        make_parent_dirs: bool,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<SftpPutResult>, FfiError> {
        if !self.is_unlocked() {
            return Err(FfiError::Locked);
        }
        let mut connected: Vec<(String, SshClient)> = Vec::new();
        let mut results: Vec<SftpPutResult> = Vec::new();
        for t in &targets {
            match self.connect_session(&t.auth, &t.jumps, t.host.clone(), t.port, t.user.clone()) {
                Ok(client) => connected.push((t.host.clone(), client)),
                Err(e) => results.push(SftpPutResult {
                    host: t.host.clone(),
                    error: Some(e.to_string()),
                }),
            }
        }

        let data = Arc::new(data);
        let remote_path = Arc::new(remote_path);
        let timeout_dur =
            (timeout_secs > 0).then(|| tokio::time::Duration::from_secs(timeout_secs as u64));
        let sem = (max_concurrency > 0)
            .then(|| Arc::new(tokio::sync::Semaphore::new(max_concurrency as usize)));
        let put_results = self.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for (host, client) in connected {
                let data = data.clone();
                let path = remote_path.clone();
                let sem = sem.clone();
                set.spawn(async move {
                    let _permit = match &sem {
                        Some(s) => Some(s.clone().acquire_owned().await.expect("semaphore open")),
                        None => None,
                    };
                    // Весь put (open_sftp+mkdir+write) под единым таймаутом.
                    let res = match timeout_dur {
                        Some(d) => {
                            match tokio::time::timeout(
                                d,
                                sftp_put_one(&client, &path, &data, make_parent_dirs),
                            )
                            .await
                            {
                                Ok(r) => r,
                                Err(_) => Err("sftp put timed out".to_string()),
                            }
                        }
                        None => sftp_put_one(&client, &path, &data, make_parent_dirs).await,
                    };
                    let _ = client.disconnect().await;
                    (host, res)
                });
            }
            let mut out = Vec::new();
            while let Some(joined) = set.join_next().await {
                if let Ok(pair) = joined {
                    out.push(pair);
                }
            }
            out
        });
        for (host, res) in put_results {
            results.push(SftpPutResult {
                host,
                error: res.err(),
            });
        }
        Ok(results)
    }

    /// Открывает broadcast (cluster-ssh): по PTY-сессии на каждый хост; общий ввод
    /// фан-аутится во все. Вывод каждого хоста идёт в `observer` с его индексом.
    /// Хост, не прошедший коннект/открытие shell, отражается в `statuses()`, но не
    /// валит остальные. Лок Core держится только на фазу коннекта.
    pub fn open_broadcast(
        &self,
        targets: Vec<MultiExecTarget>,
        term: String,
        cols: u32,
        rows: u32,
        observer: Arc<dyn BroadcastObserver>,
    ) -> Result<Arc<BroadcastSession>, FfiError> {
        check_term_size(cols, rows)?;
        let mut sessions: Vec<(SshClient, ShellHandle)> = Vec::new();
        let mut statuses: Vec<BroadcastHostStatus> = Vec::new();
        for (i, t) in targets.iter().enumerate() {
            let index = i as u32;
            match self.connect_session(&t.auth, &t.jumps, t.host.clone(), t.port, t.user.clone()) {
                Ok(client) => {
                    let sink: Arc<dyn OutputSink> = Arc::new(TaggedSink {
                        observer: observer.clone(),
                        index,
                    });
                    match self.rt.block_on(client.open_shell(&term, cols, rows, sink)) {
                        Ok(shell) => {
                            sessions.push((client, shell));
                            statuses.push(BroadcastHostStatus {
                                host: t.host.clone(),
                                index,
                                connected: true,
                                error: None,
                            });
                        }
                        Err(e) => {
                            let _ = self.rt.block_on(client.disconnect());
                            statuses.push(BroadcastHostStatus {
                                host: t.host.clone(),
                                index,
                                connected: false,
                                error: Some(e.to_string()),
                            });
                        }
                    }
                }
                Err(e) => statuses.push(BroadcastHostStatus {
                    host: t.host.clone(),
                    index,
                    connected: false,
                    error: Some(e.to_string()),
                }),
            }
        }
        Ok(Arc::new(BroadcastSession {
            inner: Mutex::new(sessions),
            statuses,
            rt: self.rt.clone(),
        }))
    }

    // --- группы хостов ---

    /// Сохраняет/обновляет группу хостов (item типа «группа»). Только ссылки на
    /// профили/группы; секретов внутри нет. Отвергает само-членство, само-
    /// родительство и пустой `group_id`; `ensure_item_type` защищает от кросс-тип
    /// затирания.
    pub fn save_group(&self, vault_id: String, group: ServerGroup) -> Result<(), FfiError> {
        if group.group_id.is_empty() {
            return Err(FfiError::other("group_id must not be empty"));
        }
        if group.member_ids.contains(&group.group_id) {
            return Err(FfiError::other("a group cannot be a member of itself"));
        }
        if group.parent_id.as_deref() == Some(group.group_id.as_str()) {
            return Err(FfiError::other("a group cannot be its own parent"));
        }
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        ensure_item_type(
            &state.storage,
            &vault_id,
            group.group_id.as_bytes(),
            ITEM_TYPE_GROUP,
        )?;
        let stored = StoredGroup {
            label: group.label,
            member_ids: group.member_ids,
            parent_id: group.parent_id,
            color: None,
        };
        let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .put_item(group.group_id.as_bytes(), ITEM_TYPE_GROUP, &json)
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Список групп волта (битый JSON пропускается, tombstones не видны).
    pub fn list_groups(&self, vault_id: String) -> Result<Vec<ServerGroup>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let mut out = Vec::new();
        for m in vault.list_items().map_err(FfiError::other)? {
            if m.item_type != ITEM_TYPE_GROUP {
                continue;
            }
            if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                if let Ok(stored) = serde_json::from_slice::<StoredGroup>(&item.content) {
                    out.push(group_to_public(
                        String::from_utf8_lossy(&m.item_id).to_string(),
                        stored,
                    ));
                }
            }
        }
        Ok(out)
    }

    /// Возвращает одну группу.
    pub fn get_group(&self, vault_id: String, group_id: String) -> Result<ServerGroup, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let item = vault
            .get_item(group_id.as_bytes())
            .map_err(FfiError::other)?
            .filter(|i| i.item_type == ITEM_TYPE_GROUP)
            .ok_or(FfiError::NotFound)?;
        let stored: StoredGroup = serde_json::from_slice(&item.content).map_err(FfiError::other)?;
        Ok(group_to_public(group_id, stored))
    }

    /// Удаляет группу (tombstone). Висячие `parent_id`/`member_id` ссылки на неё
    /// у других групп остаются и игнорируются при резолве.
    pub fn delete_group(&self, vault_id: String, group_id: String) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .delete_item(group_id.as_bytes())
            .map_err(map_vault_err)?;
        Ok(())
    }

    /// Сухой прогон: разворачивает группу (рекурсивно, с защитой от циклов) в
    /// план целей БЕЗ коннекта, загрузки ключей в агент и расшифровки паролей.
    /// Для предпросмотра перед разрушительной массовой командой.
    pub fn dry_run_group(
        &self,
        vault_id: String,
        group_id: String,
    ) -> Result<Vec<GroupTargetPlan>, FfiError> {
        Ok(self.resolve_group(&vault_id, &group_id)?.1)
    }

    /// Выполняет команду на всех хостах группы (вложенные группы раскрываются).
    /// Нерезолвящиеся члены (висячая ссылка, цикл, `PromptPassword`) попадают в
    /// результат как `error`, а не теряются молча.
    pub fn ssh_exec_group(
        &self,
        vault_id: String,
        group_id: String,
        command: String,
        max_concurrency: u32,
        timeout_secs: u32,
    ) -> Result<Vec<MultiExecResult>, FfiError> {
        let (targets, plans) = self.resolve_group(&vault_id, &group_id)?;
        let mut results = self.ssh_exec_multi(targets, command, max_concurrency, timeout_secs)?;
        for plan in plans.iter().filter(|p| p.status != ResolveStatus::Ok) {
            let msg = match plan.status {
                ResolveStatus::Dangling => "unresolved member (no such profile/group)",
                ResolveStatus::CycleSkipped => "skipped: group cycle or depth limit",
                ResolveStatus::PromptPassword => {
                    "password prompt required; connect this host individually"
                }
                ResolveStatus::Personal => {
                    "personal-identity host; connect individually (fan-out identity \
                     resolution not yet supported)"
                }
                ResolveStatus::Ok => continue,
            };
            results.push(MultiExecResult {
                host: plan.member_id.clone(),
                stdout: String::new(),
                stderr: String::new(),
                exit_status: -1,
                error: Some(msg.to_string()),
                duration_ms: 0,
                timed_out: false,
            });
        }
        Ok(results)
    }

    // --- аудит целостности ---

    /// Read-only аудит целостности волта: пере-проверяет подписи vault-записи и
    /// всех items (включая tombstones) и сверяет автора с владельцем. Ловит
    /// порчу блобов и подмену автора. Отчёт не содержит секретов/plaintext.
    pub fn verify_vault_integrity(
        &self,
        vault_id: String,
    ) -> Result<VaultIntegrityReport, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let report = vault.verify_chain().map_err(FfiError::other)?;
        Ok(integrity_report_to_ffi(report))
    }

    /// Структурная проверка БД инстанса: `integrity_check` + орфаны + доменные
    /// инварианты. Read-only, отчёт без секретов.
    pub fn check_consistency(&self) -> Result<DbConsistencyReport, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let report = state.storage.check_consistency().map_err(FfiError::other)?;
        Ok(DbConsistencyReport {
            ok: report.ok,
            integrity_ok: report.integrity_ok,
            issues: report
                .issues
                .into_iter()
                .map(|i| DbConsistencyIssue {
                    kind: match i.kind {
                        unissh_storage::ConsistencyKind::OrphanItem => {
                            DbConsistencyKind::OrphanItem
                        }
                        unissh_storage::ConsistencyKind::BadVersion => {
                            DbConsistencyKind::BadVersion
                        }
                        unissh_storage::ConsistencyKind::BadAuthorLen => {
                            DbConsistencyKind::BadAuthorLen
                        }
                        unissh_storage::ConsistencyKind::BadSignatureLen => {
                            DbConsistencyKind::BadSignatureLen
                        }
                        unissh_storage::ConsistencyKind::TombstoneNotEmpty => {
                            DbConsistencyKind::TombstoneNotEmpty
                        }
                        unissh_storage::ConsistencyKind::StaleHistory => {
                            DbConsistencyKind::StaleHistory
                        }
                    },
                    vault_id_hex: i.vault_id_hex,
                    item_id_hex: i.item_id_hex,
                    detail: i.detail,
                })
                .collect(),
        })
    }

    // --- проброс портов (туннели) ---

    /// Локальный форвард: слушает `local_bind` (например `127.0.0.1:0`) и
    /// туннелирует на `remote_host:remote_port` со стороны сервера. Туннель живёт,
    /// пока живёт возвращённый объект (или до `close`).
    #[allow(clippy::too_many_arguments)]
    pub fn open_local_forward(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        local_bind: String,
        remote_host: String,
        remote_port: u16,
    ) -> Result<Arc<SshTunnel>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let guard = self
            .rt
            .block_on(client.local_forward(&local_bind, &remote_host, remote_port))
            .map_err(map_transport_err)?;
        let bind_addr = guard.local_addr().to_string();
        Ok(Arc::new(SshTunnel {
            client: Mutex::new(Some(client)),
            guard: Mutex::new(Some(guard)),
            rt: self.rt.clone(),
            bind_addr,
        }))
    }

    /// Динамический форвард (SOCKS5) на `local_bind`. **Адрес должен быть
    /// loopback** (SOCKS5 без аутентификации). Туннель живёт до `close`.
    #[allow(clippy::too_many_arguments)]
    pub fn open_dynamic_forward(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        local_bind: String,
    ) -> Result<Arc<SshTunnel>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let guard = self
            .rt
            .block_on(client.dynamic_forward(&local_bind))
            .map_err(map_transport_err)?;
        let bind_addr = guard.local_addr().to_string();
        Ok(Arc::new(SshTunnel {
            client: Mutex::new(Some(client)),
            guard: Mutex::new(Some(guard)),
            rt: self.rt.clone(),
            bind_addr,
        }))
    }

    /// Удалённый форвард: сервер слушает `remote_bind:remote_port` и доставляет
    /// входящие на локальный `local_host:local_port`. `bind_address` вернёт
    /// `remote_bind:<фактический порт>`. Туннель живёт до `close`.
    #[allow(clippy::too_many_arguments)]
    pub fn open_remote_forward(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        remote_bind: String,
        remote_port: u16,
        local_host: String,
        local_port: u16,
    ) -> Result<Arc<SshTunnel>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host, port, user)?;
        let assigned = self
            .rt
            .block_on(client.remote_forward(&remote_bind, remote_port, &local_host, local_port))
            .map_err(map_transport_err)?;
        Ok(Arc::new(SshTunnel {
            client: Mutex::new(Some(client)),
            guard: Mutex::new(None),
            rt: self.rt.clone(),
            bind_addr: format!("{remote_bind}:{assigned}"),
        }))
    }

    // --- SFTP ---

    /// Открывает SFTP-сессию к хосту (опц. через ProxyJump). Сессия живёт, пока
    /// жив возвращённый объект (или до `close`).
    #[allow(clippy::too_many_arguments)]
    /// `parallelism` — сколько SFTP-каналов держать поверх одного соединения для
    /// параллельных передач (K из настроек). Клампится в [1, 16]; 1 = прежнее строго
    /// последовательное поведение. Первый канал открывается сразу, остальные —
    /// лениво по мере спроса (см. [`SftpFfi`]).
    pub fn open_sftp(
        &self,
        host: String,
        port: u16,
        user: String,
        auth: AuthMethod,
        jumps: Vec<JumpHost>,
        parallelism: u32,
    ) -> Result<Arc<SftpFfi>, FfiError> {
        let client = self.connect_session(&auth, &jumps, host.clone(), port, user.clone())?;
        let sftp = self
            .rt
            .block_on(client.open_sftp())
            .map_err(map_transport_err)?;
        let max = (parallelism.clamp(1, 16)) as usize;
        Ok(Arc::new(SftpFfi {
            client: Mutex::new(Some(client)),
            pool: Mutex::new(SftpPool {
                idle: vec![sftp],
                created: 1,
                max,
                generation: 0,
                closed: false,
            }),
            pool_cv: Condvar::new(),
            rt: self.rt.clone(),
            state: self.state.clone(),
            host,
            port,
            user,
            auth,
            jumps,
            reconnect_lock: Mutex::new(()),
        }))
    }

    // --- профили соединений («хосты») ---

    /// Сохраняет/обновляет профиль соединения (хранится зашифрованным item-ом
    /// типа «соединение» в волте). Сам секрет в профиль не встраивается: для
    /// парольной аутентификации хранится только ссылка на пароль-item; jump-хост
    /// с inline-паролем (`AuthMethod::Password`) сохранить нельзя — ошибка.
    pub fn save_connection(
        &self,
        vault_id: String,
        profile: ConnectionProfile,
    ) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let ConnectionProfile {
            profile_id,
            uid,
            label,
            host,
            port,
            user,
            auth,
            username_template,
            jumps,
            tags,
        } = profile;
        if profile_id.is_empty() {
            return Err(FfiError::other("profile_id must not be empty"));
        }
        // Пустой uid = создание нового профиля → минтим неизменяемый id. Непустой
        // (правка: UI вернул uid из get_connection) сохраняем как есть — uid не
        // меняется при смене host/label.
        let uid = if uid.is_empty() {
            mint_profile_uid()
        } else {
            uid
        };
        let (key_item_id, password_item_id, personal) = match auth {
            ProfileAuth::Key { key_item_id } => (Some(key_item_id), None, false),
            ProfileAuth::VaultPassword { password_item_id } => {
                (None, Some(password_item_id), false)
            }
            ProfileAuth::PromptPassword => (None, None, false),
            ProfileAuth::Personal => (None, None, true),
        };
        let mut stored = StoredProfile {
            uid: Some(uid),
            label,
            host,
            port,
            user,
            key_item_id,
            password_item_id,
            personal,
            username_template,
            jumps: jumps
                .into_iter()
                .map(jump_to_stored)
                .collect::<Result<_, _>>()?,
            tags,
            extra: BTreeMap::new(),
        };
        ensure_item_type(
            &state.storage,
            &vault_id,
            profile_id.as_bytes(),
            ITEM_TYPE_CONNECTION,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        // Forward-compat: перенести неизвестные поля существующего профиля.
        stored.extra = preserved_extra::<StoredProfile>(
            &vault,
            profile_id.as_bytes(),
            ITEM_TYPE_CONNECTION,
            |sp| sp.extra,
        );
        let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
        vault
            .put_item(profile_id.as_bytes(), ITEM_TYPE_CONNECTION, &json)
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Список профилей соединений в волте.
    pub fn list_connections(&self, vault_id: String) -> Result<Vec<ConnectionProfile>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let mut out = Vec::new();
        for m in vault.list_items().map_err(FfiError::other)? {
            if m.item_type != ITEM_TYPE_CONNECTION {
                continue;
            }
            if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                if let Ok(stored) = serde_json::from_slice::<StoredProfile>(&item.content) {
                    out.push(stored_to_profile(
                        &vault_id,
                        String::from_utf8_lossy(&m.item_id).to_string(),
                        stored,
                    ));
                }
            }
        }
        Ok(out)
    }

    /// Возвращает один профиль соединения.
    pub fn get_connection(
        &self,
        vault_id: String,
        profile_id: String,
    ) -> Result<ConnectionProfile, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let item = vault
            .get_item(profile_id.as_bytes())
            .map_err(FfiError::other)?
            .filter(|i| i.item_type == ITEM_TYPE_CONNECTION)
            .ok_or(FfiError::NotFound)?;
        let stored: StoredProfile =
            serde_json::from_slice(&item.content).map_err(FfiError::other)?;
        Ok(stored_to_profile(&vault_id, profile_id, stored))
    }

    /// Удаляет профиль соединения.
    pub fn delete_connection(&self, vault_id: String, profile_id: String) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .delete_item(profile_id.as_bytes())
            .map_err(map_vault_err)?;
        Ok(())
    }

    // ---------- identities (personal SSH creds) ----------

    /// Сохраняет (создаёт или обновляет) личную идентичность. В контент item
    /// пишется только `StoredIdentity` (username + ссылки на ключ/пароль-item),
    /// сам секрет не встраивается. `identity_id` — item_id в волте.
    pub fn save_identity(&self, vault_id: String, identity: Identity) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let Identity {
            identity_id,
            label,
            user,
            key_item_id,
            password_item_id,
        } = identity;
        if identity_id.is_empty() {
            return Err(FfiError::other("identity_id must not be empty"));
        }
        // Privacy invariant (moved here from set_personal_vault): an identity must live
        // in a PRIVATE (single-member) vault — otherwise it syncs to a shared vault's
        // other members (leaked private cred). Refuse a shared/multi-member vault.
        let vid = resolve_vid(&state.storage, &vault_id);
        let owner_ed = state.keyset.signing.verifying.to_bytes().to_vec();
        let members = match state
            .storage
            .latest_membership_epoch(&vid)
            .map_err(FfiError::other)?
        {
            Some(latest) => verify_chain_to_epoch(&state.storage, &vid, latest, &owner_ed)
                .map_err(map_vault_err)?
                .members()
                .len(),
            None => 0, // local / not-yet-shared vault → single-member
        };
        if members > 1 {
            return Err(FfiError::other(
                "cannot store an identity in a shared (multi-member) vault — it would leak to the other members",
            ));
        }
        let mut stored = StoredIdentity {
            label,
            user,
            key_item_id,
            password_item_id,
            extra: BTreeMap::new(),
        };
        ensure_item_type(
            &state.storage,
            &vault_id,
            identity_id.as_bytes(),
            ITEM_TYPE_IDENTITY,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        stored.extra = preserved_extra::<StoredIdentity>(
            &vault,
            identity_id.as_bytes(),
            ITEM_TYPE_IDENTITY,
            |si| si.extra,
        );
        let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
        vault
            .put_item(identity_id.as_bytes(), ITEM_TYPE_IDENTITY, &json)
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Возвращает одну идентичность по id.
    pub fn get_identity(
        &self,
        vault_id: String,
        identity_id: String,
    ) -> Result<Identity, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let item = vault
            .get_item(identity_id.as_bytes())
            .map_err(FfiError::other)?
            .filter(|i| i.item_type == ITEM_TYPE_IDENTITY)
            .ok_or(FfiError::NotFound)?;
        let stored: StoredIdentity =
            serde_json::from_slice(&item.content).map_err(FfiError::other)?;
        Ok(stored.into_identity(identity_id))
    }

    /// Список личных идентичностей в волте.
    pub fn list_identities(&self, vault_id: String) -> Result<Vec<Identity>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let mut out = Vec::new();
        for m in vault.list_items().map_err(FfiError::other)? {
            if m.item_type != ITEM_TYPE_IDENTITY {
                continue;
            }
            if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&item.content) {
                    out.push(stored.into_identity(String::from_utf8_lossy(&m.item_id).to_string()));
                }
            }
        }
        Ok(out)
    }

    /// Удаляет личную идентичность.
    pub fn delete_identity(&self, vault_id: String, identity_id: String) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .delete_item(identity_id.as_bytes())
            .map_err(map_vault_err)?;
        Ok(())
    }

    // ---------- identity bindings (personal vault ↔ shared host) ----------

    /// Создаёт/обновляет привязку идентичности к shared-хосту в ЛИЧНОМ волте.
    /// item_id детерминирован от (team_vault_id, profile_uid) → одна привязка на
    /// пару. `destination_pin` задаёт вызывающий (отрендеренный host:port на
    /// момент привязки) — это анти-редирект-якорь.
    ///
    /// First-bind guard: если привязка уже есть с ДРУГИМ закреплённым
    /// назначением, пере-пин требует явного `allow_rebind=true` — молча не
    /// перепривязываем на изменившийся хост (анти-редирект на этапе bind). Первая
    /// привязка и идемпотентный пере-пин (то же назначение, напр. смена только
    /// идентичности) не требуют флага.
    pub fn set_binding(
        &self,
        personal_vault_id: String,
        binding: IdentityBinding,
        allow_rebind: bool,
    ) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let IdentityBinding {
            team_vault_id,
            profile_uid,
            identity_item_id,
            destination_pin,
        } = binding;
        if team_vault_id.is_empty() || profile_uid.is_empty() {
            return Err(FfiError::other(
                "binding requires non-empty team_vault_id and profile_uid",
            ));
        }
        let item_id = binding_item_id(&team_vault_id, &profile_uid);
        ensure_item_type(
            &state.storage,
            &personal_vault_id,
            item_id.as_bytes(),
            ITEM_TYPE_BINDING,
        )?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &personal_vault_id),
        )
        .map_err(FfiError::other)?;
        // First-bind guard: молча не перепривязываем на изменившееся назначение.
        if !allow_rebind {
            if let Some(existing) = vault
                .get_item(item_id.as_bytes())
                .map_err(FfiError::other)?
                .filter(|i| i.item_type == ITEM_TYPE_BINDING)
                .and_then(|i| serde_json::from_slice::<StoredBinding>(&i.content).ok())
            {
                if existing.destination_pin != destination_pin {
                    return Err(FfiError::other(format!(
                        "binding already pinned to {}; re-bind to {} requires \
                         explicit confirmation (allow_rebind)",
                        existing.destination_pin, destination_pin
                    )));
                }
            }
        }
        let mut stored = StoredBinding {
            team_vault_id,
            profile_uid,
            identity_item_id,
            destination_pin,
            extra: BTreeMap::new(),
        };
        // Forward-compat: перенести неизвестные поля существующей привязки.
        stored.extra =
            preserved_extra::<StoredBinding>(&vault, item_id.as_bytes(), ITEM_TYPE_BINDING, |sb| {
                sb.extra
            });
        let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
        vault
            .put_item(item_id.as_bytes(), ITEM_TYPE_BINDING, &json)
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Возвращает привязку по (team_vault_id, profile_uid), если она есть.
    pub fn get_binding(
        &self,
        personal_vault_id: String,
        team_vault_id: String,
        profile_uid: String,
    ) -> Result<Option<IdentityBinding>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let item_id = binding_item_id(&team_vault_id, &profile_uid);
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &personal_vault_id),
        )
        .map_err(FfiError::other)?;
        let Some(item) = vault
            .get_item(item_id.as_bytes())
            .map_err(FfiError::other)?
            .filter(|i| i.item_type == ITEM_TYPE_BINDING)
        else {
            return Ok(None);
        };
        let stored: StoredBinding =
            serde_json::from_slice(&item.content).map_err(FfiError::other)?;
        Ok(Some(stored.into_binding()))
    }

    /// Список всех привязок в личном волте.
    pub fn list_bindings(
        &self,
        personal_vault_id: String,
    ) -> Result<Vec<IdentityBinding>, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &personal_vault_id),
        )
        .map_err(FfiError::other)?;
        let mut out = Vec::new();
        for m in vault.list_items().map_err(FfiError::other)? {
            if m.item_type != ITEM_TYPE_BINDING {
                continue;
            }
            if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                if let Ok(stored) = serde_json::from_slice::<StoredBinding>(&item.content) {
                    out.push(stored.into_binding());
                }
            }
        }
        Ok(out)
    }

    /// Удаляет привязку по (team_vault_id, profile_uid).
    pub fn delete_binding(
        &self,
        personal_vault_id: String,
        team_vault_id: String,
        profile_uid: String,
    ) -> Result<(), FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let item_id = binding_item_id(&team_vault_id, &profile_uid);
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &personal_vault_id),
        )
        .map_err(FfiError::other)?;
        vault
            .delete_item(item_id.as_bytes())
            .map_err(map_vault_err)?;
        Ok(())
    }

    /// Резолвит привязку для коннекта к shared-хосту с анти-редирект-проверкой:
    /// сверяет `current_destination` (отрендеренный клиентом host:port на данный
    /// момент) с закреплённым в привязке. `Redirected` означает, что shared-хост
    /// переклеили после привязки — клиент показывает re-bind и НЕ шлёт личный
    /// кред. `Matched` → логиниться идентичностью `identity_item_id`. Строгую
    /// in-core-защиту при коннекте доведёт Personal-auth (B4).
    pub fn resolve_host_binding(
        &self,
        personal_vault_id: String,
        team_vault_id: String,
        profile_uid: String,
        current_destination: String,
    ) -> Result<BindingResolution, FfiError> {
        let binding = self.get_binding(personal_vault_id, team_vault_id, profile_uid)?;
        Ok(resolve_binding(binding.as_ref(), &current_destination))
    }

    /// Ищет, в КАКОМ приватном волте аккаунта лежит привязка к хосту
    /// `(team_vault_id, profile_uid)` — по детерминированному id binding-item'а. Это
    /// метаданная-проверка (`item_type`/`tombstone` открыты, БЕЗ расшифровки): первый
    /// волт, где такой binding-item жив, и держит привязку+идентичность (co-location).
    /// Так разные хосты могут логиниться идентичностями из РАЗНЫХ приватных волтов
    /// (per-context) без единого «личного волта». Возвращает display-id волта (hex
    /// для cloud, UTF-8 для local — как `list_vaults`).
    fn find_binding_vault(
        &self,
        team_vault_id: &str,
        profile_uid: &str,
    ) -> Result<Option<String>, FfiError> {
        let item_id = binding_item_id(team_vault_id, profile_uid);
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        for rec in state.storage.list_vaults().map_err(FfiError::other)? {
            if let Some(item) = state
                .storage
                .get_item(&rec.vault_id, item_id.as_bytes())
                .map_err(FfiError::other)?
            {
                if item.item_type == ITEM_TYPE_BINDING && !item.tombstone {
                    return Ok(Some(match rec.sync_target {
                        SyncTarget::Cloud => hex::encode(&rec.vault_id),
                        _ => String::from_utf8_lossy(&rec.vault_id).to_string(),
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Разрешает Personal-аутентификацию для коннекта к shared-хосту (B4):
    /// находит волт с привязкой (co-location, [`Self::find_binding_vault`]), резолвит по
    /// (`team_vault_id`, `profile_uid`) и ПРОВЕРЯЕТ анти-редирект против
    /// `current_destination`. Личный кред разворачивается ТОЛЬКО если назначение
    /// совпало с закреплённым — при `Redirected` возвращается ошибка, и клиент
    /// НЕ шлёт кред на переклеенный хост (in-core enforcement). При `Unbound` —
    /// ошибка «нужно связать идентичность». Собирает vault-квалифицированный
    /// [`AuthMethod`] из личной идентичности + username (identity → fallback
    /// профиля → account-default).
    ///
    /// Замечание: метод не держит лок сам — вызывает публичные геттеры
    /// последовательно (иначе повторный захват `Mutex` был бы дедлоком).
    pub fn resolve_personal_auth(
        &self,
        team_vault_id: String,
        profile_uid: String,
        current_destination: String,
        profile_user_fallback: String,
    ) -> Result<PersonalAuth, FfiError> {
        // Co-location: the binding lives in the SAME private vault as the identity it
        // points to. Search the account's vaults for this host's binding (a metadata
        // check — no decryption), then read binding/identity/creds from that vault.
        // This is what lets different hosts use identities from different private vaults
        // (per-context) — there is no single "personal vault" anymore.
        let vault = self
            .find_binding_vault(&team_vault_id, &profile_uid)?
            .ok_or_else(|| {
                FfiError::other("host is not bound to a personal identity; bind one first")
            })?;
        let binding = self.get_binding(vault.clone(), team_vault_id, profile_uid)?;
        match resolve_binding(binding.as_ref(), &current_destination) {
            BindingResolution::Unbound => Err(FfiError::other(
                "host is not bound to a personal identity; bind one first",
            )),
            BindingResolution::Redirected { pinned, current } => Err(FfiError::other(format!(
                "destination changed since binding (pinned {pinned}, now {current}); \
                 re-bind required before using the personal credential",
            ))),
            BindingResolution::Matched { identity_item_id } => {
                let identity = self.get_identity(vault.clone(), identity_item_id)?;
                let auth = if let Some(key_item_id) = identity.key_item_id.filter(|s| !s.is_empty())
                {
                    AuthMethod::Agent {
                        vault_id: vault,
                        key_item_id,
                    }
                } else if let Some(password_item_id) =
                    identity.password_item_id.filter(|s| !s.is_empty())
                {
                    AuthMethod::VaultPassword {
                        vault_id: vault,
                        password_item_id,
                    }
                } else {
                    return Err(FfiError::other(
                        "bound identity has neither a key nor a password",
                    ));
                };
                let account_default = self.get_account_default_username()?;
                let user = pick_username(
                    &identity.user,
                    &profile_user_fallback,
                    account_default.as_deref(),
                );
                Ok(PersonalAuth { user, auth })
            }
        }
    }

    /// Каноническое назначение для anti-redirect (bind-пин И connect-сверка).
    /// Шаблон входит в назначение → его правка = смена назначения.
    /// Клиент рендерит этим И `destination_pin` в [`Core::set_binding`], И
    /// `current_destination` в [`Core::resolve_personal_auth`] — форматы совпадают.
    pub fn personal_destination(
        &self,
        host: String,
        port: u16,
        username_template: Option<String>,
        jumps: Vec<JumpHost>,
    ) -> String {
        personal_destination(&host, port, username_template.as_deref(), &jumps)
    }

    /// Финальный username коннекта по шаблону (`%u` → base_user), или
    /// просто `base_user` без шаблона. Клиент применяет к
    /// [`PersonalAuth::user`], используя тот же `username_template`, что и у пина.
    pub fn apply_username_template(
        &self,
        base_user: String,
        username_template: Option<String>,
    ) -> String {
        apply_username_template(&base_user, username_template.as_deref())
    }

    /// Импортирует `~/.ssh/config`: для каждого конкретного `Host`-алиаса создаёт
    /// профиль соединения с пустым `key_item_id` (ядро не читает файлы). Ключи,
    /// указанные в `IdentityFile`, читает и импортирует UI-слой: он подтягивает
    /// приватный ключ через [`Core::import_ssh_key`] и привязывает его к профилю
    /// повторным [`Core::save_connection`]. Возвращает id созданных профилей.
    pub fn import_ssh_config(
        &self,
        vault_id: String,
        config_text: String,
    ) -> Result<Vec<String>, FfiError> {
        let cfg = SshConfig::parse(&config_text).map_err(FfiError::other)?;
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;
        let mut created = Vec::new();
        for alias in cfg.host_aliases() {
            // Не затираем существующий item другого типа (напр. ключ с тем же id):
            // такой алиас пропускаем, не включая в созданные.
            if ensure_item_type(
                &state.storage,
                &vault_id,
                alias.as_bytes(),
                ITEM_TYPE_CONNECTION,
            )
            .is_err()
            {
                continue;
            }
            // #9: перезапись существующего профиля ДОЛЖНА сохранять его
            // неизменяемый uid — на него завязаны personal-binding'и и hop_ref'ы
            // (B2.1/B2.2); свежий uid осиротил бы их. Реюзаем uid существующего
            // профиля, иначе минтим новый.
            let existing_uid = vault
                .get_item(alias.as_bytes())
                .ok()
                .flatten()
                .and_then(|it| serde_json::from_slice::<StoredProfile>(&it.content).ok())
                .and_then(|sp| sp.uid)
                .filter(|u| !u.is_empty());
            let s = cfg.resolve(&alias);
            let stored = StoredProfile {
                uid: Some(existing_uid.unwrap_or_else(mint_profile_uid)),
                label: alias.clone(),
                host: s.hostname.unwrap_or_else(|| alias.clone()),
                port: s.port.unwrap_or(22),
                user: s.user.unwrap_or_default(),
                key_item_id: None,
                password_item_id: None,
                personal: false,
                username_template: None,
                jumps: parse_proxy_jump(s.proxy_jump.as_deref()),
                tags: Vec::new(),
                extra: std::collections::BTreeMap::new(),
            };
            let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
            vault
                .put_item(alias.as_bytes(), ITEM_TYPE_CONNECTION, &json)
                .map_err(FfiError::other)?;
            created.push(alias);
        }
        Ok(created)
    }

    /// Рендерит профили волта в текст `~/.ssh/config` (инверс
    /// [`Core::import_ssh_config`]). Приватные ключи не экспортируются — только
    /// Host/HostName/Port/User/ProxyJump; для ключевой аутентификации ключ
    /// остаётся в волте (в конфиг идёт лишь комментарий). Round-trip-совместим с
    /// импортом.
    pub fn export_ssh_config(&self, vault_id: String) -> Result<String, FfiError> {
        let profiles = self.list_connections(vault_id)?;
        let mut out = String::new();
        for p in profiles {
            // OpenSSH `Host` — это паттерны, разделённые пробелами, со спецсмыслом
            // у `* ? !`. profile_id с такими символами не представим как один
            // алиас и сломал бы round-trip → пропускаем с пометкой.
            if p.profile_id
                .contains(|c: char| c.is_whitespace() || matches!(c, '*' | '?' | '!'))
            {
                out.push_str(&format!(
                    "# пропущен профиль '{}': id содержит пробел/glob-символ\n\n",
                    p.profile_id
                ));
                continue;
            }
            out.push_str(&format!("Host {}\n", p.profile_id));
            out.push_str(&format!("    HostName {}\n", p.host));
            if p.port != 22 {
                out.push_str(&format!("    Port {}\n", p.port));
            }
            if !p.user.is_empty() {
                out.push_str(&format!("    User {}\n", p.user));
            }
            if !p.jumps.is_empty() {
                let hops: Vec<String> = p.jumps.iter().map(format_proxy_hop).collect();
                out.push_str(&format!("    ProxyJump {}\n", hops.join(",")));
            }
            if let ProfileAuth::Key { key_item_id } = &p.auth {
                out.push_str(&format!(
                    "    # IdentityFile: ключ '{key_item_id}' в волте\n"
                ));
            }
            out.push('\n');
        }
        Ok(out)
    }

    /// Импортирует текст `~/.ssh/known_hosts`: каждый (host, port) с
    /// не-hashed-именем закрепляется в TOFU-хранилище. Ключ канонизируется тем же
    /// `russh`, что и пиннинг при живом коннекте (байт-совпадение). Hashed-строки
    /// (`|1|…`) и невалидные пропускаются с подсчётом.
    pub fn import_known_hosts(&self, text: String) -> Result<KnownHostsImport, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let mut imported = 0u32;
        let mut skipped_hashed = 0u32;
        let mut skipped_invalid = 0u32;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut tok = line.split_whitespace();
            let (Some(hosts), Some(keytype), Some(keyblob)) = (tok.next(), tok.next(), tok.next())
            else {
                skipped_invalid += 1;
                continue;
            };
            // @cert-authority / @revoked маркеры — не обычный пин, пропускаем.
            if hosts.starts_with('@') {
                skipped_invalid += 1;
                continue;
            }
            if hosts.contains('|') {
                skipped_hashed += 1;
                continue;
            }
            let key_bytes = match canonical_host_key(&format!("{keytype} {keyblob}")) {
                Ok(b) => b,
                Err(_) => {
                    skipped_invalid += 1;
                    continue;
                }
            };
            let mut any = false;
            for entry in hosts.split(',') {
                let (host, port) = split_host_port(entry);
                if host.is_empty() {
                    continue;
                }
                // Глоб/негация (`*`/`?`/`!`) НЕ матчится точечным TOFU-lookup'ом —
                // закреплять такой токен бессмысленно (мёртвая запись, вводящая в
                // заблуждение «хост запиннен»). Пропускаем (учтётся как skipped).
                if host.contains(['*', '?', '!']) {
                    continue;
                }
                if state
                    .storage
                    .put_known_host(&host, port, &key_bytes)
                    .is_ok()
                {
                    imported += 1;
                    any = true;
                }
            }
            if !any {
                skipped_invalid += 1;
            }
        }
        Ok(KnownHostsImport {
            imported,
            skipped_hashed,
            skipped_invalid,
        })
    }

    /// Импортирует экспорт сессий PuTTY (`.reg`): каждая SSH-сессия становится
    /// профилем соединения. Не-SSH сессии, без хоста и коллизии id пропускаются.
    /// `ProxyMethod=6` (SSH) с `ProxyHost` превращается в один jump-хоп.
    pub fn import_putty_sessions(
        &self,
        vault_id: String,
        reg_text: String,
    ) -> Result<HostImportReport, FfiError> {
        let sessions = parse_putty_reg(&reg_text);
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vid = resolve_vid(&state.storage, &vault_id);
        let vault = Vault::open(&state.storage, &state.keyset, &vid).map_err(FfiError::other)?;
        let mut created_ids = Vec::new();
        let mut skipped = 0u32;
        for s in sessions {
            let proto = if s.protocol.is_empty() {
                "ssh"
            } else {
                s.protocol.as_str()
            };
            if proto != "ssh" || s.host.is_empty() || s.name.is_empty() {
                skipped += 1;
                continue;
            }
            // Любой существующий живой item с этим id (в т.ч. профиль того же
            // типа) — не затираем; импорт только создаёт новое.
            let occupied = state
                .storage
                .get_item(&vid, s.name.as_bytes())
                .map_err(FfiError::other)?
                .map(|r| !r.tombstone)
                .unwrap_or(false);
            if occupied {
                skipped += 1;
                continue;
            }
            let jumps = if s.proxy_method == 6 && !s.proxy_host.is_empty() {
                vec![StoredJump {
                    host: s.proxy_host.clone(),
                    port: if s.proxy_port == 0 {
                        22
                    } else {
                        s.proxy_port as u16
                    },
                    user: s.proxy_user.clone(),
                    key_item_id: None,
                    password_item_id: None,
                    extra: std::collections::BTreeMap::new(),
                    hop_ref: None,
                }]
            } else {
                Vec::new()
            };
            let stored = StoredProfile {
                uid: Some(mint_profile_uid()),
                label: s.name.clone(),
                host: s.host.clone(),
                port: if s.port == 0 { 22 } else { s.port as u16 },
                user: s.user.clone(),
                key_item_id: None,
                password_item_id: None,
                personal: false,
                username_template: None,
                jumps,
                tags: Vec::new(),
                extra: std::collections::BTreeMap::new(),
            };
            let json = serde_json::to_vec(&stored).map_err(FfiError::other)?;
            vault
                .put_item(s.name.as_bytes(), ITEM_TYPE_CONNECTION, &json)
                .map_err(FfiError::other)?;
            created_ids.push(s.name);
        }
        Ok(HostImportReport {
            created_ids,
            skipped,
        })
    }

    /// Экспортирует волт в портативный зашифрованный файл-бэкап (НЕ синк): все
    /// живые items расшифровываются и кладутся в bundle, который шифруется
    /// AEAD-ключом, выведенным из `passphrase` (Argon2id). Открывается только
    /// этой passphrase, без keyset исходного аккаунта.
    pub fn export_vault(&self, vault_id: String, passphrase: String) -> Result<Vec<u8>, FfiError> {
        let passphrase = Zeroizing::new(passphrase);
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, &vault_id),
        )
        .map_err(FfiError::other)?;

        let mut items_buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut count = 0u32;
        for m in vault.list_items().map_err(FfiError::other)? {
            if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
                put_len_bytes(&mut items_buf, &item.item_id);
                items_buf.extend_from_slice(&item.item_type.to_be_bytes());
                put_len_bytes(&mut items_buf, &item.content);
                count += 1;
            }
        }
        let mut bundle: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        put_len_bytes(&mut bundle, vault.name());
        bundle.extend_from_slice(&count.to_be_bytes());
        bundle.extend_from_slice(&items_buf);

        let params = KdfParams::recommended();
        let key = derive_key(passphrase.as_bytes(), &params).map_err(FfiError::other)?;
        let kdf_blob = params.to_blob().map_err(FfiError::other)?;
        // AAD покрывает magic+version+kdf_blob → подмена KDF-параметров/заголовка
        // детектится при расшифровке (а не только смена vault_id).
        let aad = backup_aad(vault_id.as_bytes(), &kdf_blob);
        let ciphertext = aead_encrypt(&key, &bundle, &aad).map_err(FfiError::other)?;

        let mut out = Vec::new();
        out.extend_from_slice(BACKUP_MAGIC);
        out.push(BACKUP_VERSION);
        put_len_bytes(&mut out, &kdf_blob);
        put_len_bytes(&mut out, vault_id.as_bytes());
        put_len_bytes(&mut out, &ciphertext);
        Ok(out)
    }

    /// Импортирует бэкап в новый волт `new_vault_id` текущего инстанса: расшифровка
    /// passphrase-ключом, items пере-шифровываются под новый VK и переподписываются
    /// текущим владельцем. Неверная passphrase/порча → ошибка. Не затирает
    /// существующий волт.
    pub fn import_vault(
        &self,
        backup: Vec<u8>,
        passphrase: String,
        new_vault_id: String,
    ) -> Result<(), FfiError> {
        let passphrase = Zeroizing::new(passphrase);
        let mut r = ByteReader::new(&backup);
        if r.take(4)? != BACKUP_MAGIC {
            return Err(FfiError::other("invalid backup format"));
        }
        if r.u8()? != BACKUP_VERSION {
            return Err(FfiError::other("unsupported backup version"));
        }
        let kdf_blob = r.bytes()?;
        let orig_vault_id = r.bytes()?;
        let ciphertext = r.bytes()?;

        // KdfParams::from_blob отвергает запредельные параметры (DoS-защита) ДО
        // деривации; AAD покрывает kdf_blob → подмена параметров не пройдёт.
        let params = KdfParams::from_blob(kdf_blob).map_err(FfiError::other)?;
        let key = derive_key(passphrase.as_bytes(), &params).map_err(FfiError::other)?;
        let aad = backup_aad(orig_vault_id, kdf_blob);
        // Неверная passphrase или порча (в т.ч. заголовка/KDF) → AEAD не сходится.
        let bundle = Zeroizing::new(
            aead_decrypt(&key, ciphertext, &aad).map_err(|_| FfiError::InvalidCredentials)?,
        );

        // Парсим bundle в owned-значения ДО транзакции (контент — в Zeroizing).
        let mut br = ByteReader::new(&bundle);
        let name = br.bytes()?.to_vec();
        let count = br.u32()?;
        let mut items: Vec<(Vec<u8>, u32, Zeroizing<Vec<u8>>)> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let item_id = br.bytes()?.to_vec();
            let item_type = br.u32()?;
            let content = Zeroizing::new(br.bytes()?.to_vec());
            items.push((item_id, item_type, content));
        }

        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        // Любой существующий volume-id (живой ИЛИ tombstone) занят: создать поверх
        // нельзя (anti-rollback всё равно отвергнет), поэтому отдаём ясную ошибку.
        if state
            .storage
            .get_vault(new_vault_id.as_bytes())
            .map_err(FfiError::other)?
            .is_some()
        {
            return Err(FfiError::AlreadyExists);
        }
        // Атомарно: создание волта + все items в одной транзакции — частичный сбой
        // не оставит полу-импортированный волт.
        state
            .storage
            .transaction(|| {
                let vault = Vault::create(
                    &state.storage,
                    &state.keyset,
                    new_vault_id.as_bytes().to_vec(),
                    &name,
                )?;
                for (item_id, item_type, content) in &items {
                    vault.put_item(item_id, *item_type, content)?;
                }
                Ok::<(), unissh_vault::VaultError>(())
            })
            .map_err(map_vault_err)?;
        state.vault_names.insert(
            new_vault_id.into_bytes(),
            String::from_utf8_lossy(&name).to_string(),
        );
        Ok(())
    }
}

impl Core {
    /// Берёт лок состояния, восстанавливаясь после отравления мьютекса (данные
    /// под локом — обычные, не инвариантные), чтобы единичная паника не
    /// «заклинила» весь Core навсегда при вызовах через FFI.
    fn locked_state(&self) -> std::sync::MutexGuard<'_, Option<CoreState>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Читает + расшифровывает текущее per-account состояние (A3.2), если есть.
    fn read_account_state(&self) -> Result<Option<AccountStatePayload>, FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let author = state.keyset.signing.verifying.to_bytes().to_vec();
        match state
            .storage
            .get_account_state(&author)
            .map_err(FfiError::other)?
        {
            Some(row) => {
                let plain =
                    open_account_payload(&state.keyset, &row.payload).map_err(map_vault_err)?;
                Ok(Some(AccountStatePayload::decode(&plain)?))
            }
            None => Ok(None),
        }
    }

    /// Read-modify-write per-account состояния (A3.2): расшифровать текущее (или
    /// пустое), применить мутацию, пере-seal+sign с version+1, сохранить. Синкается
    /// на устройства аккаунта при следующем sync_push.
    fn update_account_state(
        &self,
        mutate: impl FnOnce(&mut AccountStatePayload),
    ) -> Result<(), FfiError> {
        let guard = self.locked_state();
        let state = guard.as_ref().ok_or(FfiError::Locked)?;
        let author = state.keyset.signing.verifying.to_bytes().to_vec();
        let (mut payload, cur_version) = match state
            .storage
            .get_account_state(&author)
            .map_err(FfiError::other)?
        {
            Some(row) => {
                let plain =
                    open_account_payload(&state.keyset, &row.payload).map_err(map_vault_err)?;
                (AccountStatePayload::decode(&plain)?, row.version)
            }
            None => (AccountStatePayload::default(), 0),
        };
        mutate(&mut payload);
        let sealed =
            seal_account_payload(&state.keyset, &payload.encode()).map_err(map_vault_err)?;
        let new_version = cur_version.saturating_add(1);
        let sig = sign_account_state(&state.keyset, new_version, &sealed).map_err(map_vault_err)?;
        state
            .storage
            .set_account_state(&author, new_version, &sealed, &sig)
            .map_err(FfiError::other)?;
        Ok(())
    }

    /// Коннект+аутентификация под локом Core (нужны agent+storage: ключи грузятся
    /// в агент, пароли из волта разворачиваются в память ядра). Возвращает
    /// владеемый клиент; вызывающий освобождает лок сразу после.
    fn connect_session(
        &self,
        auth: &AuthMethod,
        jumps: &[JumpHost],
        host: String,
        port: u16,
        user: String,
    ) -> Result<SshClient, FfiError> {
        connect_with_state(&self.state, &self.rt, auth, jumps, host, port, user)
    }

    /// Reveal конкретной версии UTF-8-секрета из истории, type-gated к
    /// `expected_type` (чужой тип — в т.ч. ключ — через этот путь не читается).
    fn read_item_version(
        &self,
        vault_id: &str,
        item_id: &str,
        version: u64,
        expected_type: u32,
        what: &str,
    ) -> Result<String, FfiError> {
        let mut guard = self.locked_state();
        let state = guard.as_mut().ok_or(FfiError::Locked)?;
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, vault_id),
        )
        .map_err(FfiError::other)?;
        let item = vault
            .get_item_version(item_id.as_bytes(), version)
            .map_err(FfiError::other)?
            .ok_or(FfiError::NotFound)?;
        if item.item_type != expected_type {
            return Err(FfiError::other(format!("item is not {what}")));
        }
        let s = std::str::from_utf8(&item.content)
            .map_err(|_| FfiError::other(format!("{what} is not valid UTF-8")))?;
        Ok(s.to_string())
    }

    /// Разворачивает группу (рекурсивно, дедуп + защита от циклов/глубины) в
    /// `(цели для exec, полный план)`. Цели — только профили, готовые к коннекту
    /// (не `PromptPassword`); план включает каждый член с его статусом. Чистое
    /// чтение волта: ни коннекта, ни загрузки ключей, ни расшифровки паролей.
    fn resolve_group(
        &self,
        vault_id: &str,
        group_id: &str,
    ) -> Result<(Vec<MultiExecTarget>, Vec<GroupTargetPlan>), FfiError> {
        let groups: std::collections::HashMap<String, Vec<String>> = self
            .list_groups(vault_id.to_string())?
            .into_iter()
            .map(|g| (g.group_id, g.member_ids))
            .collect();
        if !groups.contains_key(group_id) {
            return Err(FfiError::NotFound);
        }
        let profiles_map: std::collections::HashMap<String, ConnectionProfile> = self
            .list_connections(vault_id.to_string())?
            .into_iter()
            .map(|p| (p.profile_id.clone(), p))
            .collect();
        let profiles_set: std::collections::HashSet<String> =
            profiles_map.keys().cloned().collect();
        let (member_ids, issues) =
            flatten_group_members(&groups, &profiles_set, group_id, GROUP_MAX_DEPTH);

        let mut targets = Vec::new();
        let mut plans = Vec::new();
        for pid in member_ids {
            let p = profiles_map
                .get(&pid)
                .expect("flattened member is a profile");
            match &p.auth {
                // Нет заранее известного пароля → в пакет не идёт (интерактив).
                ProfileAuth::PromptPassword => {
                    plans.push(GroupTargetPlan {
                        member_id: pid,
                        host: p.host.clone(),
                        port: p.port,
                        user: p.user.clone(),
                        status: ResolveStatus::PromptPassword,
                    });
                }
                // Personal: резолвим личную идентичность per-host (привязка +
                // анти-редирект). Привязан → в пакет с разрешёнными user+auth;
                // без привязки/при редиректе → исключаем (подключить
                // индивидуально — там будет точная ошибка), НЕ шлём пустой пароль.
                ProfileAuth::Personal => {
                    let dest = self.personal_destination(
                        p.host.clone(),
                        p.port,
                        p.username_template.clone(),
                        p.jumps.clone(),
                    );
                    match self.resolve_personal_auth(
                        vault_id.to_string(),
                        p.uid.clone(),
                        dest,
                        p.user.clone(),
                    ) {
                        Ok(pa) => {
                            let user =
                                self.apply_username_template(pa.user, p.username_template.clone());
                            plans.push(GroupTargetPlan {
                                member_id: pid,
                                host: p.host.clone(),
                                port: p.port,
                                user: user.clone(),
                                status: ResolveStatus::Ok,
                            });
                            targets.push(MultiExecTarget {
                                host: p.host.clone(),
                                port: p.port,
                                user,
                                auth: pa.auth,
                                jumps: p.jumps.clone(),
                            });
                        }
                        Err(_) => {
                            plans.push(GroupTargetPlan {
                                member_id: pid,
                                host: p.host.clone(),
                                port: p.port,
                                user: p.user.clone(),
                                status: ResolveStatus::Personal,
                            });
                        }
                    }
                }
                _ => {
                    plans.push(GroupTargetPlan {
                        member_id: pid,
                        host: p.host.clone(),
                        port: p.port,
                        user: p.user.clone(),
                        status: ResolveStatus::Ok,
                    });
                    targets.push(profile_to_target(vault_id, p.clone()));
                }
            }
        }
        for (member_id, status) in issues {
            plans.push(GroupTargetPlan {
                member_id,
                host: String::new(),
                port: 0,
                user: String::new(),
                status,
            });
        }
        Ok((targets, plans))
    }
}

/// Коннект+аутентификация против разделяемого распакованного состояния (под его
/// локом). Используется и [`Core::connect_session`], и [`ReconnectingSession`] —
/// последняя переразрешает креды из волта на каждый реконнект (plaintext не
/// кэшируется между попытками).
///
/// Замечание о параллелизме: лок состояния держится на всё время `block_on`
/// SSH-хендшейка (до `HANDSHAKE_TIMEOUT`=30с), т.е. коннекты сериализуются. Это
/// присуще модели: `storage` (rusqlite `Connection`) и встроенный агент — `!Sync`
/// и живут под этим локом, а проверка host key в TOFU дёргает `storage` прямо во
/// время хендшейка. Для однопользовательского клиента коннекты и так
/// последовательны; вынос сети из-под лока потребовал бы Sync-хранилища.
#[allow(clippy::too_many_arguments)]
fn connect_with_state(
    state: &Arc<Mutex<Option<CoreState>>>,
    rt: &tokio::runtime::Runtime,
    auth: &AuthMethod,
    jumps: &[JumpHost],
    host: String,
    port: u16,
    user: String,
) -> Result<SshClient, FfiError> {
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    let st = guard.as_mut().ok_or(FfiError::Locked)?;
    let mut chain = Vec::with_capacity(jumps.len());
    for j in jumps {
        // Host-chain (B2.2): ref-хоп резолвится из другого профиля-бастиона (host/
        // port/user/auth берутся оттуда); обычный хоп — inline, как раньше.
        let (host, port, user, auth) = match &j.hop_ref {
            Some(hr) => {
                let prof = resolve_profile_by_uid(st, &hr.vault_id, &hr.profile_uid)?;
                let auth = match prof.auth {
                    ProfileAuth::Key { key_item_id } => AuthMethod::Agent {
                        vault_id: hr.vault_id.clone(),
                        key_item_id,
                    },
                    ProfileAuth::VaultPassword { password_item_id } => AuthMethod::VaultPassword {
                        vault_id: hr.vault_id.clone(),
                        password_item_id,
                    },
                    ProfileAuth::PromptPassword | ProfileAuth::Personal => {
                        return Err(FfiError::other(
                            "referenced bastion profile has no stored credential usable as a hop",
                        ))
                    }
                };
                (prof.host, prof.port, prof.user, auth)
            }
            None => (j.host.clone(), j.port, j.user.clone(), j.auth.clone()),
        };
        let a = resolve_auth(st, &auth)?;
        chain.push(ConnectOptions::new(host, port, user, a));
    }
    let target_auth = resolve_auth(st, auth)?;
    let target = ConnectOptions::new(host, port, user, target_auth);
    rt.block_on(SshClient::connect_through(
        &chain,
        &target,
        &st.agent,
        &st.storage,
    ))
    .map_err(map_transport_err)
}

/// Линейный backoff: задержка перед попыткой `attempt` (0-based) = `base_ms *
/// (attempt+1)`.
fn retry_backoff_ms(attempt: u32, base_ms: u32) -> u64 {
    base_ms as u64 * (attempt as u64 + 1)
}

/// Переводит FFI-способ аутентификации в транспортный: ключ грузится в агент,
/// пароль из волта расшифровывается в `Zeroizing` (plaintext не покидает ядро).
fn resolve_auth(state: &mut CoreState, auth: &AuthMethod) -> Result<Auth, FfiError> {
    Ok(match auth {
        AuthMethod::Agent {
            vault_id,
            key_item_id,
        } => {
            load_key_into_agent(state, vault_id, key_item_id)?;
            Auth::Agent {
                key_id: agent_key_id(vault_id, key_item_id),
            }
        }
        AuthMethod::Password { password } => Auth::Password {
            password: Zeroizing::new(password.clone()),
        },
        AuthMethod::VaultPassword {
            vault_id,
            password_item_id,
        } => Auth::Password {
            password: read_password_item(state, vault_id, password_item_id)?,
        },
    })
}

/// Читает item типа «пароль» из волта. Только для внутреннего использования при
/// коннекте и для явного reveal ([`Core::get_password`]); чужой тип item (в т.ч.
/// SSH-ключ) через этот путь не читается.
fn read_password_item(
    state: &CoreState,
    vault_id: &str,
    item_id: &str,
) -> Result<Zeroizing<String>, FfiError> {
    read_utf8_item(state, vault_id, item_id, ITEM_TYPE_PASSWORD, "a password")
}

/// Читает UTF-8-контент item заданного типа (пароль/заметка). Type-gate: item
/// другого типа (в т.ч. приватный ключ) через этот путь не читается — инвариант
/// «plaintext-ключи не пересекают FFI» сохраняется. Контент в `Zeroizing`.
fn read_utf8_item(
    state: &CoreState,
    vault_id: &str,
    item_id: &str,
    expected_type: u32,
    what: &str,
) -> Result<Zeroizing<String>, FfiError> {
    let vault = Vault::open(
        &state.storage,
        &state.keyset,
        &resolve_vid(&state.storage, vault_id),
    )
    .map_err(FfiError::other)?;
    let item = vault
        .get_item(item_id.as_bytes())
        .map_err(FfiError::other)?
        .ok_or(FfiError::NotFound)?;
    if item.item_type != expected_type {
        return Err(FfiError::other(format!("item is not {what}")));
    }
    let s = std::str::from_utf8(&item.content)
        .map_err(|_| FfiError::other(format!("{what} is not valid UTF-8")))?;
    Ok(Zeroizing::new(s.to_string()))
}

/// Раскладка одного файла на один хост: открыть SFTP, опц. создать родительский
/// каталог (ошибку «существует» глотаем), записать. Ошибки в `String` (для
/// единообразия с веткой таймаута в [`Core::sftp_put_multi`]).
async fn sftp_put_one(
    client: &SshClient,
    remote_path: &str,
    data: &[u8],
    make_parent_dirs: bool,
) -> Result<(), String> {
    let mut sftp = client.open_sftp().await.map_err(|e| e.to_string())?;
    if make_parent_dirs {
        if let Some(parent) = parent_dir(remote_path) {
            let _ = sftp.mkdir(&parent).await;
        }
    }
    sftp.write_file(remote_path, data)
        .await
        .map_err(|e| e.to_string())
}

/// Родительский каталог пути (один уровень). `None`, если родителя нет.
fn parent_dir(path: &str) -> Option<String> {
    let p = path.trim_end_matches('/');
    p.rfind('/').map(|i| {
        if i == 0 {
            "/".to_string()
        } else {
            p[..i].to_string()
        }
    })
}

/// Совпадение тегов хоста с запросом. `match_all` → запрос ⊆ тегов хоста (AND);
/// иначе пересечение непусто (OR). Пустой запрос → не выбираем ничего (защита от
/// случайного «exec на все хосты»).
fn tags_match(host_tags: &[String], query: &[String], match_all: bool) -> bool {
    if query.is_empty() {
        return false;
    }
    if match_all {
        query.iter().all(|q| host_tags.contains(q))
    } else {
        query.iter().any(|q| host_tags.contains(q))
    }
}

/// Рекурсивное раскрытие вложенных групп в плоский упорядоченный список профилей.
/// Член — id профиля (в `profiles`) или id вложенной группы (ключ `groups`).
/// `visited_groups` рвёт циклы, `seen_profiles` дедуплицирует, `max_depth`
/// ограничивает глубину. Возвращает (профили по порядку обхода, проблемы).
fn flatten_group_members(
    groups: &std::collections::HashMap<String, Vec<String>>,
    profiles: &std::collections::HashSet<String>,
    root: &str,
    max_depth: u32,
) -> (Vec<String>, Vec<(String, ResolveStatus)>) {
    struct Flattener<'a> {
        groups: &'a std::collections::HashMap<String, Vec<String>>,
        profiles: &'a std::collections::HashSet<String>,
        max_depth: u32,
        result: Vec<String>,
        seen_profiles: std::collections::HashSet<String>,
        visited_groups: std::collections::HashSet<String>,
        issues: Vec<(String, ResolveStatus)>,
    }
    impl Flattener<'_> {
        fn walk(&mut self, gid: &str, depth: u32) {
            if depth > self.max_depth {
                self.issues
                    .push((gid.to_string(), ResolveStatus::CycleSkipped));
                return;
            }
            let Some(members) = self.groups.get(gid) else {
                return;
            };
            for m in members.clone() {
                if self.groups.contains_key(&m) {
                    // Вложенная группа: впервые — спускаемся; повторно — цикл.
                    if self.visited_groups.insert(m.clone()) {
                        self.walk(&m, depth + 1);
                    } else {
                        self.issues.push((m, ResolveStatus::CycleSkipped));
                    }
                } else if self.profiles.contains(&m) {
                    if self.seen_profiles.insert(m.clone()) {
                        self.result.push(m);
                    }
                } else {
                    self.issues.push((m, ResolveStatus::Dangling));
                }
            }
        }
    }
    let mut f = Flattener {
        groups,
        profiles,
        max_depth,
        result: Vec::new(),
        seen_profiles: std::collections::HashSet::new(),
        visited_groups: std::collections::HashSet::from([root.to_string()]),
        issues: Vec::new(),
    };
    f.walk(root, 0);
    (f.result, f.issues)
}

/// Профиль → цель multi-exec в том же волте. `PromptPassword` не имеет хранимого
/// секрета → пустой `Password` (помечается отдельно в резолве групп/тегов; в
/// прогоне без интерактива даст ошибку аутентификации, а не молчаливый успех).
fn profile_to_target(vault_id: &str, p: ConnectionProfile) -> MultiExecTarget {
    MultiExecTarget {
        host: p.host,
        port: p.port,
        user: p.user,
        auth: profile_auth_to_method(vault_id, p.auth),
        jumps: p.jumps,
    }
}

/// Ссылку профиля на креды (`ProfileAuth`, vault-относительную) переводит в
/// vault-квалифицированный [`AuthMethod`], проставляя `vault_id` того волта, где
/// живёт профиль. `PromptPassword` → пустой inline-`Password` (в неинтерактивном
/// прогоне даст ошибку аутентификации, а не молчаливый успех).
fn profile_auth_to_method(vault_id: &str, auth: ProfileAuth) -> AuthMethod {
    match auth {
        ProfileAuth::Key { key_item_id } => AuthMethod::Agent {
            vault_id: vault_id.to_string(),
            key_item_id,
        },
        ProfileAuth::VaultPassword { password_item_id } => AuthMethod::VaultPassword {
            vault_id: vault_id.to_string(),
            password_item_id,
        },
        ProfileAuth::PromptPassword => AuthMethod::Password {
            password: String::new(),
        },
        // Personal сюда в норме НЕ доходит: fan-out-пути (resolve_group,
        // select_targets_by_tags) исключают его до profile_to_target, а
        // индивидуальный коннект идёт через resolve_personal_auth (с проверкой
        // анти-редиректа). Оставляем защитный fail-safe (пустой Password даст
        // ошибку аутентификации на обычном сервере), а не молчаливый успех.
        // Корректный резолв Personal в fan-out — B6.
        ProfileAuth::Personal => AuthMethod::Password {
            password: String::new(),
        },
    }
}

/// Маппинг ошибок транспорта: рассинхрон host key выделяем отдельно для UI.
fn map_transport_err(e: unissh_ssh_transport::TransportError) -> FfiError {
    match e {
        unissh_ssh_transport::TransportError::HostKeyMismatch {
            host,
            port,
            fingerprint,
        } => FfiError::HostKeyMismatch {
            host,
            port,
            fingerprint,
        },
        other => FfiError::ssh(other),
    }
}

/// Защита от кросс-типового затирания: если по `item_id` уже есть **живой** item
/// другого типа, отказываем (иначе, напр., профиль соединения с id существующего
/// ключа молча уничтожил бы ключ). Проверка по сырой записи storage — без
/// расшифровки/проверки подписи.
fn ensure_item_type(
    storage: &Storage,
    vault_id: &str,
    item_id: &[u8],
    expected_type: u32,
) -> Result<(), FfiError> {
    let vid = resolve_vid(storage, vault_id);
    if let Some(rec) = storage.get_item(&vid, item_id).map_err(FfiError::other)? {
        if !rec.tombstone && rec.item_type != expected_type {
            return Err(FfiError::AlreadyExists);
        }
    }
    Ok(())
}

/// Маппинг ошибок vault: not-found/already-exists выделяем для UI.
fn map_vault_err(e: unissh_vault::VaultError) -> FfiError {
    match e {
        unissh_vault::VaultError::NotFound => FfiError::NotFound,
        unissh_vault::VaultError::AlreadyExists => FfiError::AlreadyExists,
        other => FfiError::other(other),
    }
}

/// Расшифрованное содержимое per-account состояния (A3.2): указатель на личный
/// волт + account-default username. Кодировка: `put(vault_id) || put(username_utf8)`
/// (u32-BE длины). Пустой vault_id/username = «не задано».
#[derive(Default)]
struct AccountStatePayload {
    personal_vault_id: Vec<u8>,
    default_username: String,
}

impl AccountStatePayload {
    fn encode(&self) -> Vec<u8> {
        let user = self.default_username.as_bytes();
        let mut out = Vec::with_capacity(8 + self.personal_vault_id.len() + user.len());
        out.extend_from_slice(&(self.personal_vault_id.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.personal_vault_id);
        out.extend_from_slice(&(user.len() as u32).to_be_bytes());
        out.extend_from_slice(user);
        out
    }

    fn decode(b: &[u8]) -> Result<Self, FfiError> {
        let fmt = || FfiError::Other {
            msg: "malformed account-state payload".into(),
        };
        let take = |b: &[u8]| -> Result<(Vec<u8>, usize), FfiError> {
            if b.len() < 4 {
                return Err(fmt());
            }
            let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
            if b.len() < 4 + len {
                return Err(fmt());
            }
            Ok((b[4..4 + len].to_vec(), 4 + len))
        };
        let (vid, n1) = take(b)?;
        let (user, n2) = take(&b[n1..])?;
        if n1 + n2 != b.len() {
            return Err(fmt());
        }
        Ok(AccountStatePayload {
            personal_vault_id: vid,
            default_username: String::from_utf8(user).map_err(|_| fmt())?,
        })
    }
}

/// Маппинг ошибок keychain: невалидные креды/откат поколения — отдельно для UI.
fn map_keychain_err(e: unissh_keychain::KeychainError) -> FfiError {
    use unissh_keychain::KeychainError as K;
    match e {
        K::InvalidCredentials | K::PasswordRequired => FfiError::InvalidCredentials,
        other => FfiError::other(other),
    }
}

/// Маппинг ошибок sync: фатальные → Other с сообщением (детали — в отчёте, не тут).
fn map_sync_err(e: unissh_sync::SyncError) -> FfiError {
    FfiError::Other { msg: e.to_string() }
}

/// Декодирует hex-`vault_id` (cloud UUIDv4) в сырые байты. Битый hex → Other.
fn decode_vid(vault_id_hex: &str) -> Result<Vec<u8>, FfiError> {
    hex::decode(vault_id_hex.trim()).map_err(|_| FfiError::other("invalid hex vault_id"))
}

/// Резолвит идентификатор волта в **сырые байты** для item-операций. Local-волт
/// адресуется произвольной UTF-8-строкой (используется как есть); cloud-волт —
/// hex'ом UUIDv4 (`create_cloud_vault`/`list_vaults` отдают hex, а хранится он под
/// сырыми 16 байтами). Если строка декодируется как 16-байтный hex И такой волт
/// существует — это cloud-id, берём декодированные байты; иначе — local, берём
/// байты строки. Коллизия (local-id, совпадающий с hex существующего cloud-UUID)
/// практически невозможна (это был бы UUID, заданный пользователем как имя id).
fn resolve_vid(storage: &Storage, vault_id: &str) -> Vec<u8> {
    if let Ok(raw) = hex::decode(vault_id.trim()) {
        if raw.len() == 16 && matches!(storage.get_vault(&raw), Ok(Some(_))) {
            return raw;
        }
    }
    vault_id.as_bytes().to_vec()
}

/// Декодирует hex-pubkey фиксированной длины (32 байта Ed25519/X25519). Иначе Other.
fn decode_pubkey32(label: &str, hex_str: &str) -> Result<Vec<u8>, FfiError> {
    let b =
        hex::decode(hex_str.trim()).map_err(|_| FfiError::other(format!("invalid hex {label}")))?;
    if b.len() != 32 {
        return Err(FfiError::other(format!("{label} must be 32 bytes")));
    }
    Ok(b)
}

/// Возвращает персистентный account-id инстанса, генерируя и сохраняя его при
/// первом обращении (идемпотентно; server-tz §2.1). Открытый id, не секрет.
fn ensure_account_id(storage: &Storage) -> Result<[u8; 16], FfiError> {
    match load_account_id(storage).map_err(map_keychain_err)? {
        Some(id) => Ok(id),
        None => {
            let id = generate_account_id();
            store_account_id(storage, &id).map_err(map_keychain_err)?;
            Ok(id)
        }
    }
}

/// Общий конвертер отчёта целостности `vault` → FFI-Record (для local- и
/// cloud/member-путей: `verify_vault_integrity` и `verify_chain`).
fn integrity_report_to_ffi(report: unissh_vault::IntegrityReport) -> VaultIntegrityReport {
    VaultIntegrityReport {
        ok: report.ok,
        checked: report.checked,
        issues: report
            .issues
            .into_iter()
            .map(|i| IntegrityIssueInfo {
                item_id: String::from_utf8_lossy(&i.item_id).to_string(),
                version: i.version,
                tombstone: i.tombstone,
                failure: match i.failure {
                    unissh_vault::IntegrityFailure::SignatureInvalid => {
                        IntegrityFailureKind::SignatureInvalid
                    }
                    unissh_vault::IntegrityFailure::AuthorMismatch => {
                        IntegrityFailureKind::AuthorMismatch
                    }
                    unissh_vault::IntegrityFailure::Malformed => IntegrityFailureKind::Malformed,
                    // non_exhaustive: будущая причина → консервативно Malformed.
                    _ => IntegrityFailureKind::Malformed,
                },
            })
            .collect(),
    }
}

/// Открывает файл keyset с правами `0600` (на unix): приватный сайдкар не должен
/// быть доступен другим локальным пользователям — даже зашифрованный, это снижает
/// риск офлайн-перебора Argon2. `exclusive` → `create_new` (O_EXCL).
fn open_keyset_file(path: &std::path::Path, exclusive: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    if exclusive {
        o.create_new(true);
    } else {
        o.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Атомарно перезаписывает сайдкар keyset: пишем во временный файл и
/// переименовываем поверх (на одной ФС rename атомарен; при сбое до rename
/// оригинал цел). Имя temp уникально (pid), чтобы параллельные/осиротевшие temp
/// не сталкивались; после rename — fsync каталога для durability.
fn write_keyset_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), FfiError> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = open_keyset_file(&tmp, false).map_err(FfiError::other)?;
        f.write_all(bytes).map_err(FfiError::other)?;
        f.sync_all().map_err(FfiError::other)?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(FfiError::other(e));
    }
    // fsync каталога — чтобы запись о переименовании дошла до диска.
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Бэкапит keyset-сайдкар в `<path>.pre-migration.bak` ПЕРЕД миграционной
/// перезаписью — делает единственную пишущую операцию миграции (re-wrap на v3)
/// полностью обратимой. Best-effort: при сбое — `warn` и продолжаем (миграция и
/// так brick-safe — новая v3-запись самосогласована, старый блоб не теряется до
/// атомарного rename). Логируется ТОЛЬКО путь (метаданные ФС), НЕ содержимое
/// keyset (сам блоб зашифрован, но в логи крипто-блобы не пишем — см. SECURITY.md).
fn backup_keyset_sidecar(path: &std::path::Path) {
    if !path.exists() {
        return; // нечего бэкапить (первый онбординг — сайдкара ещё нет)
    }
    let mut bak = path.as_os_str().to_owned();
    bak.push(".pre-migration.bak");
    let bak = PathBuf::from(bak);
    match std::fs::copy(path, &bak) {
        Ok(_) => log::info!(
            "keyset sidecar backed up before migration: {}",
            bak.display()
        ),
        Err(e) => log::warn!(
            "keyset sidecar backup failed (migration still safe, proceeding): {} ({e})",
            bak.display()
        ),
    }
}

/// Inline-пароль в jump-хосте профиля → ошибка: секрет не должен попадать в
/// JSON профиля (для хранимого пароля есть ссылка `VaultPassword`).
///
/// `vault_id` метода здесь отбрасывается: хранимый jump vault-относителен (item
/// живёт в волте профиля, тот же `vault_id` восстанавливается при чтении в
/// [`stored_to_profile`]). Кросс-волтовые хопы — отдельная модель (`HopRef`).
fn jump_to_stored(j: JumpHost) -> Result<StoredJump, FfiError> {
    let hop_ref = j.hop_ref.map(|hr| StoredHopRef {
        vault_id: hr.vault_id,
        profile_uid: hr.profile_uid,
    });
    // Ref-хоп: inline-auth игнорируется, ничего не сохраняем из неё (сам auth —
    // placeholder). Обычный хоп: как раньше (только ссылки, inline-пароль нельзя).
    let (key_item_id, password_item_id) = if hop_ref.is_some() {
        (None, None)
    } else {
        match j.auth {
            AuthMethod::Agent { key_item_id, .. } => (Some(key_item_id), None),
            AuthMethod::VaultPassword {
                password_item_id, ..
            } => (None, Some(password_item_id)),
            AuthMethod::Password { .. } => {
                return Err(FfiError::other(
                    "inline password cannot be stored in a profile; save it as a vault item",
                ))
            }
        }
    };
    Ok(StoredJump {
        host: j.host,
        port: j.port,
        user: j.user,
        key_item_id,
        password_item_id,
        hop_ref,
        extra: std::collections::BTreeMap::new(),
    })
}

/// Валидирует размер терминала на FFI-границе: оба измерения > 0, иначе мусор
/// (например 0×0 от не инициализированного UI) уйдёт на сервер.
fn check_term_size(cols: u32, rows: u32) -> Result<(), FfiError> {
    if cols == 0 || rows == 0 {
        return Err(FfiError::other("terminal size must be non-zero"));
    }
    Ok(())
}

fn group_to_public(group_id: String, s: StoredGroup) -> ServerGroup {
    ServerGroup {
        group_id,
        label: s.label,
        member_ids: s.member_ids,
        parent_id: s.parent_id,
    }
}

/// Минтит новый неизменяемый uid профиля: 16 криптослучайных байт в hex.
/// СЛУЧАЙНЫЙ (не производный от item_id) — рециклированный после tombstone
/// item_id (ssh-config импорт берёт alias как id) не даёт коллизию uid со старым
/// профилем, так что чужой binding не приклеится к новому хосту.
fn mint_profile_uid() -> String {
    hex::encode(unissh_crypto::random_bytes::<16>())
}

/// Читает сохранённые «неизвестные поля» (`extra`) существующего item того же
/// типа, чтобы ПЕРЕНЕСТИ их в перезаписываемое тело (forward-compat: клиент не
/// вырезает поля, добавленные будущей версией → нет молчаливого LWW-даунгрейда,
/// напр. потери `personal`/`username_template`). Пусто, если item нет / другого
/// типа / не распарсился.
fn preserved_extra<T>(
    vault: &Vault,
    item_id: &[u8],
    item_type: u32,
    pick: impl FnOnce(T) -> BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value>
where
    T: serde::de::DeserializeOwned,
{
    vault
        .get_item(item_id)
        .ok()
        .flatten()
        .filter(|i| i.item_type == item_type)
        .and_then(|i| serde_json::from_slice::<T>(&i.content).ok())
        .map(pick)
        .unwrap_or_default()
}

/// Детерминированный uid для легаси-профиля без сохранённого uid: sha256 от
/// (len-prefixed vault_id ‖ item_id), первые 16 байт в hex. Стабилен между
/// устройствами до первого пере-сохранения (тогда закрепляется в теле). Рецикл в
/// этом окне невозможен: item_id занят живым профилем, для которого и считается.
fn legacy_profile_uid(vault_id: &str, item_id: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update((vault_id.len() as u64).to_be_bytes());
    h.update(vault_id.as_bytes());
    h.update(item_id.as_bytes());
    hex::encode(&h.finalize()[..16])
}

fn stored_to_profile(vault_id: &str, profile_id: String, s: StoredProfile) -> ConnectionProfile {
    let uid = s
        .uid
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| legacy_profile_uid(vault_id, &profile_id));
    ConnectionProfile {
        uid,
        profile_id,
        label: s.label,
        host: s.host,
        port: s.port,
        user: s.user,
        tags: s.tags,
        username_template: s.username_template,
        // Personal приоритетнее key/password-ссылок (у Personal их и нет).
        auth: if s.personal {
            ProfileAuth::Personal
        } else {
            match (s.password_item_id, s.key_item_id) {
                (Some(password_item_id), _) => ProfileAuth::VaultPassword { password_item_id },
                (None, Some(key_item_id)) => ProfileAuth::Key { key_item_id },
                (None, None) => ProfileAuth::PromptPassword,
            }
        },
        jumps: s
            .jumps
            .into_iter()
            .map(|j| JumpHost {
                host: j.host,
                port: j.port,
                user: j.user,
                // Хопы хранимого профиля vault-относительны: их item'ы живут в том
                // же волте, что и профиль. Проставляем этот `vault_id`.
                auth: match (j.password_item_id, j.key_item_id) {
                    (Some(password_item_id), _) => AuthMethod::VaultPassword {
                        vault_id: vault_id.to_string(),
                        password_item_id,
                    },
                    (None, Some(key_item_id)) => AuthMethod::Agent {
                        vault_id: vault_id.to_string(),
                        key_item_id,
                    },
                    // Легаси-импорт мог оставить ключ не назначенным: пустой id
                    // сохраняет прежнюю семантику «UI назначит позже» (коннект с
                    // ним даст NotFound).
                    (None, None) => AuthMethod::Agent {
                        vault_id: vault_id.to_string(),
                        key_item_id: String::new(),
                    },
                },
                hop_ref: j.hop_ref.map(|hr| HopRef {
                    vault_id: hr.vault_id,
                    profile_uid: hr.profile_uid,
                }),
            })
            .collect(),
    }
}

/// Резолвит профиль-бастион по (vault_id, profile_uid) для host-chain (B2.2):
/// сканирует connection-профили волта и находит с совпадающим неизменяемым uid.
/// Не рекурсирует по цепочке референса (берётся только сам хоп-профиль).
fn resolve_profile_by_uid(
    state: &CoreState,
    vault_id: &str,
    profile_uid: &str,
) -> Result<ConnectionProfile, FfiError> {
    let vault = Vault::open(
        &state.storage,
        &state.keyset,
        &resolve_vid(&state.storage, vault_id),
    )
    .map_err(FfiError::other)?;
    for m in vault.list_items().map_err(FfiError::other)? {
        if m.item_type != ITEM_TYPE_CONNECTION {
            continue;
        }
        if let Some(item) = vault.get_item(&m.item_id).map_err(FfiError::other)? {
            if let Ok(sp) = serde_json::from_slice::<StoredProfile>(&item.content) {
                let prof = stored_to_profile(
                    vault_id,
                    String::from_utf8_lossy(&m.item_id).to_string(),
                    sp,
                );
                if prof.uid == profile_uid {
                    return Ok(prof);
                }
            }
        }
    }
    Err(FfiError::NotFound)
}

/// Магия файла бэкапа волта.
const BACKUP_MAGIC: &[u8; 4] = b"UNVB";
/// Версия формата бэкапа.
const BACKUP_VERSION: u8 = 1;

/// AAD бэкапа: связывает шифротекст с vault_id и заголовком (magic+version+
/// kdf_blob), чтобы подмена KDF-параметров/версии детектилась при расшифровке.
fn backup_aad(vault_id: &[u8], kdf_blob: &[u8]) -> AssociatedData {
    let mut tag = Vec::with_capacity(BACKUP_MAGIC.len() + 1 + kdf_blob.len());
    tag.extend_from_slice(BACKUP_MAGIC);
    tag.push(BACKUP_VERSION);
    tag.extend_from_slice(kdf_blob);
    AssociatedData::new(vault_id.to_vec(), tag, BACKUP_VERSION as u64)
}

/// Дописывает length-prefixed (u32 BE) блоб.
fn put_len_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Читатель length-prefixed framing бэкапа (с проверкой границ).
struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], FfiError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| FfiError::other("backup overflow"))?;
        if end > self.buf.len() {
            return Err(FfiError::other("truncated backup"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, FfiError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, FfiError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn bytes(&mut self) -> Result<&'a [u8], FfiError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// Разобранная PuTTY-сессия (внутреннее представление).
#[derive(Default)]
struct PuttySession {
    name: String,
    host: String,
    port: u32,
    user: String,
    protocol: String,
    proxy_method: u32,
    proxy_host: String,
    proxy_port: u32,
    proxy_user: String,
}

/// Разбирает экспорт PuTTY (`.reg`) в список сессий. Блок начинается со строки
/// `[...\Sessions\<name>]` (имя url-кодировано), далее `"Key"="value"` /
/// `"Key"=dword:hex`.
fn parse_putty_reg(text: &str) -> Vec<PuttySession> {
    let mut out = Vec::new();
    let mut cur: Option<PuttySession> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(s) = cur.take() {
                out.push(s);
            }
            if let Some(idx) = rest.find("\\Sessions\\") {
                let name_enc = rest[idx + "\\Sessions\\".len()..].trim_end_matches(']');
                cur = Some(PuttySession {
                    name: putty_unescape(name_enc),
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(s) = cur.as_mut() else {
            continue;
        };
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        let val = val.trim();
        match key {
            "HostName" => s.host = unquote_reg(val),
            "PortNumber" => s.port = parse_dword(val),
            "UserName" => s.user = unquote_reg(val),
            "Protocol" => s.protocol = unquote_reg(val),
            "ProxyMethod" => s.proxy_method = parse_dword(val),
            "ProxyHost" => s.proxy_host = unquote_reg(val),
            "ProxyPort" => s.proxy_port = parse_dword(val),
            "ProxyUsername" => s.proxy_user = unquote_reg(val),
            _ => {}
        }
    }
    if let Some(s) = cur.take() {
        out.push(s);
    }
    out
}

/// Снимает кавычки со строкового значения `.reg`.
fn unquote_reg(v: &str) -> String {
    v.trim().trim_matches('"').to_string()
}

/// Парсит `dword:0000XXXX` (hex) в `u32`; иначе 0.
fn parse_dword(v: &str) -> u32 {
    v.trim()
        .strip_prefix("dword:")
        .and_then(|h| u32::from_str_radix(h.trim(), 16).ok())
        .unwrap_or(0)
}

/// Декодирует `%XX`-экранирование имени сессии PuTTY.
fn putty_unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Рендерит jump-хост в элемент `ProxyJump` (`user@host:port`, IPv6 в скобках).
/// Обратимо к [`parse_proxy_jump`].
fn format_proxy_hop(j: &JumpHost) -> String {
    let hostport = if j.host.contains(':') && !j.host.starts_with('[') {
        format!("[{}]:{}", j.host, j.port)
    } else {
        format!("{}:{}", j.host, j.port)
    };
    if j.user.is_empty() {
        hostport
    } else {
        format!("{}@{hostport}", j.user)
    }
}

/// Разбирает `ProxyJump` (`a,b,c`, элементы вида `user@host:port`) в jump-хосты.
/// Аутентификацию оставляем не назначенной — ключ/пароль назначит UI (импорт не
/// знает items волта).
fn parse_proxy_jump(spec: Option<&str>) -> Vec<StoredJump> {
    let mut out = Vec::new();
    let Some(spec) = spec else {
        return out;
    };
    for hop in spec.split(',') {
        let hop = hop.trim();
        if hop.is_empty() {
            continue;
        }
        let (user, hostport) = match hop.split_once('@') {
            Some((u, hp)) => (u.to_string(), hp),
            None => (String::new(), hop),
        };
        let (host, port) = split_host_port(hostport);
        out.push(StoredJump {
            host,
            port,
            user,
            key_item_id: None,
            password_item_id: None,
            extra: std::collections::BTreeMap::new(),
            hop_ref: None,
        });
    }
    out
}

/// Разбирает `host[:port]` с поддержкой IPv6: `[2001:db8::1]:2222`, `[2001:db8::1]`,
/// голый `2001:db8::1` (несколько `:` без скобок → весь как host), иначе
/// `host:port`. Порт по умолчанию — 22.
///
/// Скобки IPv6 всегда снимаются: тот же «голый» host-строкой уходит и в коннект
/// (`russh`), и в lookup/pin known_hosts — идентичность хоста для пиннинга
/// сохраняется (важно не смешивать `[ip]` и `ip` в разных путях).
fn split_host_port(s: &str) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            return (h.to_string(), p.parse().unwrap_or(22));
        }
        if let Some(h) = rest.strip_suffix(']') {
            return (h.to_string(), 22);
        }
    }
    // Голый IPv6-литерал (>1 двоеточия, без скобок) — порт не указан.
    if s.matches(':').count() > 1 {
        return (s.to_string(), 22);
    }
    match s.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(22)),
        None => (s.to_string(), 22),
    }
}

/// Наблюдатель интерактивной сессии (реализуется UI; UniFFI callback interface).
#[uniffi::export(with_foreign)]
pub trait SessionObserver: Send + Sync {
    /// Данные из сессии (вывод терминала).
    fn on_data(&self, data: Vec<u8>);
    /// Сессия закрыта; код возврата (или -1).
    fn on_close(&self, exit_status: i32);
}

struct ObserverSink(Arc<dyn SessionObserver>);

impl OutputSink for ObserverSink {
    fn on_data(&self, data: Vec<u8>) {
        self.0.on_data(data);
    }
    fn on_close(&self, exit_status: Option<u32>) {
        self.0.on_close(exit_status.map(|c| c as i32).unwrap_or(-1));
    }
}

/// Наблюдатель потокового exec: stdout/stderr раздельно + код возврата.
#[uniffi::export(with_foreign)]
pub trait ExecObserver: Send + Sync {
    /// Данные stdout.
    fn on_stdout(&self, data: Vec<u8>);
    /// Данные stderr.
    fn on_stderr(&self, data: Vec<u8>);
    /// Команда завершилась; код возврата (или -1).
    fn on_exit(&self, exit_status: i32);
}

struct ExecSinkBridge(Arc<dyn ExecObserver>);

impl unissh_ssh_transport::ExecSink for ExecSinkBridge {
    fn on_stdout(&self, data: Vec<u8>) {
        self.0.on_stdout(data);
    }
    fn on_stderr(&self, data: Vec<u8>) {
        self.0.on_stderr(data);
    }
    fn on_exit(&self, exit_status: Option<u32>) {
        self.0.on_exit(exit_status.map(|c| c as i32).unwrap_or(-1));
    }
}

/// Наблюдатель broadcast-сессии: вывод каждого хоста помечается его индексом
/// (позиция в `targets`). Реализуется UI.
#[uniffi::export(with_foreign)]
pub trait BroadcastObserver: Send + Sync {
    /// Данные из сессии хоста `host_index`.
    fn on_data(&self, host_index: u32, data: Vec<u8>);
    /// Сессия хоста `host_index` закрыта; код возврата (или -1).
    fn on_close(&self, host_index: u32, exit_status: i32);
}

/// Sink, тегирующий вывод одного хоста его индексом и делегирующий в
/// [`BroadcastObserver`]. Навешивается per-client в ffi — крейт транспорта о
/// broadcast не знает.
struct TaggedSink {
    observer: Arc<dyn BroadcastObserver>,
    index: u32,
}

impl OutputSink for TaggedSink {
    fn on_data(&self, data: Vec<u8>) {
        self.observer.on_data(self.index, data);
    }
    fn on_close(&self, exit_status: Option<u32>) {
        self.observer
            .on_close(self.index, exit_status.map(|c| c as i32).unwrap_or(-1));
    }
}

/// Интерактивная SSH-сессия (PTY). Управляет вводом/ресайзом/закрытием; вывод
/// идёт в зарегистрированный observer. Не держит лок Core.
#[derive(uniffi::Object)]
pub struct SshSession {
    _client: Mutex<SshClient>,
    shell: ShellHandle,
    rt: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl SshSession {
    /// Отправляет ввод (нажатия клавиш) в сессию.
    pub fn write(&self, data: Vec<u8>) -> Result<(), FfiError> {
        self.rt
            .block_on(self.shell.write(&data))
            .map_err(FfiError::ssh)
    }

    /// Меняет размер окна терминала. `cols`/`rows` должны быть > 0.
    ///
    /// Best-effort: `window-change` уходит на сервер без подтверждения, поэтому
    /// `Ok(())` означает «нотификация отправлена», а не «сервер применил размер».
    /// Ошибку вернёт только обрыв канала/транспорта. UI не должен ждать ack.
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        check_term_size(cols, rows)?;
        self.rt
            .block_on(self.shell.resize(cols, rows))
            .map_err(FfiError::ssh)
    }

    /// Закрывает сессию.
    pub fn close(&self) -> Result<(), FfiError> {
        self.rt.block_on(self.shell.close()).map_err(FfiError::ssh)
    }
}

/// Хэндл потокового exec: stdin, опрос завершения, закрытие. Вывод идёт в
/// `ExecObserver`. Не держит лок Core.
#[derive(uniffi::Object)]
pub struct ExecHandleFfi {
    _client: Mutex<SshClient>,
    handle: ExecHandle,
    rt: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl ExecHandleFfi {
    /// Пишет в stdin команды.
    pub fn write_stdin(&self, data: Vec<u8>) -> Result<(), FfiError> {
        self.rt
            .block_on(self.handle.write_stdin(&data))
            .map_err(FfiError::ssh)
    }

    /// Ждёт завершения команды до `timeout_ms` мс. `true` — завершилась (и
    /// `on_exit` доставлен), `false` — таймаут.
    pub fn wait_exit(&self, timeout_ms: u32) -> Result<bool, FfiError> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
        loop {
            if self.handle.has_exited() {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Закрывает канал (EOF stdin + close).
    pub fn close(&self) -> Result<(), FfiError> {
        self.rt.block_on(self.handle.close()).map_err(FfiError::ssh)
    }
}

/// Интерактивная PTY-сессия с авто-реконнектом. Хранит параметры подключения и
/// при обрыве (ошибка `write`) или по явному `reconnect()` переустанавливает
/// сессию с backoff. `Agent`/`VaultPassword`-креды переразрешаются из волта на
/// каждой попытке (plaintext не кэшируется); inline-`Password` (если им открыли
/// сессию) хранится в `auth` на всё время жизни сессии — для реконнекта.
/// `HostKeyMismatch` НЕ реконнектится (возможный MITM → стоп).
#[derive(uniffi::Object)]
pub struct ReconnectingSession {
    state: Arc<Mutex<Option<CoreState>>>,
    rt: Arc<tokio::runtime::Runtime>,
    host: String,
    port: u16,
    user: String,
    auth: AuthMethod,
    jumps: Vec<JumpHost>,
    term: String,
    cols: u32,
    rows: u32,
    max_retries: u32,
    backoff_ms: u32,
    observer: Arc<dyn SessionObserver>,
    current: Mutex<Option<(SshClient, ShellHandle)>>,
    // Сериализует reconnect: два одновременных reconnect() (напр. из гонки
    // write-fail) не должны создать лишний коннект-сирота.
    reconnect_lock: Mutex<()>,
}

impl ReconnectingSession {
    fn connect_once(&self) -> Result<(), FfiError> {
        let client = connect_with_state(
            &self.state,
            &self.rt,
            &self.auth,
            &self.jumps,
            self.host.clone(),
            self.port,
            self.user.clone(),
        )?;
        let sink: Arc<dyn OutputSink> = Arc::new(ObserverSink(self.observer.clone()));
        let shell = self
            .rt
            .block_on(client.open_shell(&self.term, self.cols, self.rows, sink))
            .map_err(FfiError::ssh)?;
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some((client, shell));
        Ok(())
    }

    fn connect_with_retry(&self) -> Result<(), FfiError> {
        let mut last = FfiError::other("no connection attempt");
        for attempt in 0..=self.max_retries {
            match self.connect_once() {
                Ok(()) => return Ok(()),
                // MITM не лечится реконнектом — отдаём ошибку сразу.
                Err(e @ FfiError::HostKeyMismatch { .. }) => return Err(e),
                Err(e) => {
                    last = e;
                    if attempt < self.max_retries {
                        std::thread::sleep(std::time::Duration::from_millis(retry_backoff_ms(
                            attempt,
                            self.backoff_ms,
                        )));
                    }
                }
            }
        }
        Err(last)
    }

    fn try_write(&self, data: &[u8]) -> Result<(), FfiError> {
        let guard = self.current.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some((_client, shell)) => self.rt.block_on(shell.write(data)).map_err(FfiError::ssh),
            None => Err(FfiError::other("not connected")),
        }
    }

    fn teardown(&self) {
        let _enter = self.rt.enter();
        let mut guard = self.current.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((client, shell)) = guard.take() {
            let _ = self.rt.block_on(shell.close());
            let _ = self.rt.block_on(client.disconnect());
        }
    }
}

#[uniffi::export]
impl ReconnectingSession {
    /// Есть ли сейчас живая сессия.
    pub fn is_connected(&self) -> bool {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Отправляет ввод; при ошибке (обрыв) автоматически реконнектится и повторяет.
    pub fn write(&self, data: Vec<u8>) -> Result<(), FfiError> {
        if self.try_write(&data).is_ok() {
            return Ok(());
        }
        self.reconnect()?;
        self.try_write(&data)
    }

    /// Ресайз текущей сессии (`cols`/`rows` > 0).
    pub fn resize(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        check_term_size(cols, rows)?;
        let guard = self.current.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some((_client, shell)) => self
                .rt
                .block_on(shell.resize(cols, rows))
                .map_err(FfiError::ssh),
            None => Err(FfiError::other("not connected")),
        }
    }

    /// Явно пересоздаёт сессию (рвёт старую, подключается заново с backoff).
    pub fn reconnect(&self) -> Result<(), FfiError> {
        // Сериализуем: параллельные reconnect() не создают коннект-сирот.
        let _g = self
            .reconnect_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.teardown();
        self.connect_with_retry()
    }

    /// Закрывает сессию и рвёт соединение.
    pub fn close(&self) {
        self.teardown();
    }
}

impl Drop for ReconnectingSession {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Broadcast-сессия (cluster-ssh): держит PTY-сессии нескольких хостов; ввод
/// фан-аутится во все. Не держит лок Core. Вывод — в `BroadcastObserver` с
/// индексом хоста.
#[derive(uniffi::Object)]
pub struct BroadcastSession {
    inner: Mutex<Vec<(SshClient, ShellHandle)>>,
    statuses: Vec<BroadcastHostStatus>,
    rt: Arc<tokio::runtime::Runtime>,
}

#[uniffi::export]
impl BroadcastSession {
    /// Статусы всех целей (включая не подключившиеся).
    pub fn statuses(&self) -> Vec<BroadcastHostStatus> {
        self.statuses.clone()
    }

    /// Отправляет ввод во все активные сессии (best-effort: мёртвый хост не
    /// блокирует остальные).
    pub fn write_all(&self, data: Vec<u8>) -> Result<(), FfiError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for (_client, shell) in guard.iter() {
            let _ = self.rt.block_on(shell.write(&data));
        }
        Ok(())
    }

    /// Ресайзит все активные сессии (`cols`/`rows` > 0). Best-effort.
    pub fn resize_all(&self, cols: u32, rows: u32) -> Result<(), FfiError> {
        check_term_size(cols, rows)?;
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for (_client, shell) in guard.iter() {
            let _ = self.rt.block_on(shell.resize(cols, rows));
        }
        Ok(())
    }

    /// Закрывает все сессии и рвёт соединения.
    pub fn close(&self) {
        // block_on входит в контекст рантайма (Drop канала russh может
        // tokio::spawn — без enter дроп вне рантайма паникует).
        let _enter = self.rt.enter();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for (client, shell) in guard.drain(..) {
            let _ = self.rt.block_on(shell.close());
            let _ = self.rt.block_on(client.disconnect());
        }
    }
}

impl Drop for BroadcastSession {
    fn drop(&mut self) {
        let _enter = self.rt.enter();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.clear();
    }
}

/// Активный туннель (проброс портов). Держит SSH-соединение живым. `close()` —
/// чистый disconnect; при Drop без `close()` listener детерминированно
/// останавливается (ForwardGuard) и соединение рвётся (без вежливого disconnect).
#[derive(uniffi::Object)]
pub struct SshTunnel {
    client: Mutex<Option<SshClient>>,
    guard: Mutex<Option<ForwardGuard>>,
    rt: Arc<tokio::runtime::Runtime>,
    bind_addr: String,
}

#[uniffi::export]
impl SshTunnel {
    /// Адрес, на котором слушает форвард: `host:port` (local/dynamic) либо
    /// `remote_bind:assigned_port` (remote).
    pub fn bind_address(&self) -> String {
        self.bind_addr.clone()
    }

    /// Закрывает туннель и соединение.
    pub fn close(&self) {
        // Останавливаем listener (Drop ForwardGuard), затем штатно рвём соединение.
        // SshClient/ForwardGuard дропаются безопасно вне рантайма; block_on сам
        // входит в контекст рантайма (поэтому без отдельного enter — иначе вложенный
        // block_on паникует).
        let _ = self.guard.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(c) = self.client.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = self.rt.block_on(c.disconnect());
        }
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        // Детерминированно останавливаем listener (ForwardGuard.abort при Drop).
        // SshClient (= Arc<Handle>) дропается безопасно вне рантайма; чистый
        // disconnect делает только close() (block_on в Drop здесь не зовём).
        let _ = self.guard.lock().unwrap_or_else(|e| e.into_inner()).take();
        let _ = self.client.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

/// Callback прогресса SFTP-передачи (реализуется UI).
#[uniffi::export(with_foreign)]
pub trait SftpProgressObserver: Send + Sync {
    /// `transferred` байт из `total` (0, если размер неизвестен).
    fn on_progress(&self, transferred: u64, total: u64);
}

struct ProgressBridge(Arc<dyn SftpProgressObserver>);

impl unissh_ssh_transport::SftpProgress for ProgressBridge {
    fn on_progress(&self, transferred: u64, total: u64) {
        self.0.on_progress(transferred, total);
    }
}

/// Токен кооперативной отмены передачи. Создаётся UI, передаётся в
/// `sftp_download`/`sftp_upload`, отменяется из другого потока.
#[derive(uniffi::Object)]
pub struct CancelToken {
    flag: Arc<std::sync::atomic::AtomicBool>,
}

#[uniffi::export]
impl CancelToken {
    /// Новый (не отменённый) токен.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Запрашивает отмену (передача остановится между чанками).
    pub fn cancel(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Запрошена ли отмена.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }
}

struct CancelBridge(Arc<std::sync::atomic::AtomicBool>);

impl unissh_ssh_transport::SftpCancel for CancelBridge {
    fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// === Веха-2: синк через коллбэк-интерфейс ===

/// **Коллбэк-интерфейс синка** (реализуется приложением — server-tz §3.1): узкий
/// контракт «недоверенного ящика блобов». Ядро НЕ доверяет ни порядку, ни
/// `server_seq`, ни содержимому — `sync_now` верифицирует каждый объект перед
/// применением. Объекты пересекают границу как непрозрачные байты
/// (`SyncObject::to_bytes`); ядро сериализует/десериализует на своей стороне.
#[uniffi::export(with_foreign)]
pub trait FfiSyncTransport: Send + Sync {
    /// Отдаёт объекты серверу; возвращает назначенные `server_seq` в порядке входа.
    fn push_objects(&self, objects: Vec<Vec<u8>>) -> Result<Vec<u64>, FfiError>;
    /// Отдаёт всё со `server_seq > cursor` (порядок не гарантируется — ядро сортирует).
    fn delta_since(&self, cursor: u64) -> Vec<SyncDeltaItem>;
    /// Сообщает максимальный назначенный `server_seq` (справочно, не доверенный).
    fn report_version(&self) -> u64;
}

/// Адаптер: foreign-`FfiSyncTransport` → `unissh_sync::SyncTransport`. Сериализует
/// `SyncObject` в байты на границе FFI и мапит ошибки. Битый объект из дельты →
/// пропускается (движок и так верифицирует каждый объект перед применением).
struct ForeignTransportAdapter {
    inner: Arc<dyn FfiSyncTransport>,
    /// Последняя ошибка push (коллбэк может бросить) — пробрасывается из sync_push.
    push_err: Mutex<Option<FfiError>>,
}

impl SyncTransport for ForeignTransportAdapter {
    fn push_objects(&mut self, objects: &[SyncObject]) -> Result<Vec<u64>, unissh_sync::SyncError> {
        let mut blobs = Vec::with_capacity(objects.len());
        for o in objects {
            blobs.push(o.to_bytes().map_err(|_| unissh_sync::SyncError::Format)?);
        }
        match self.inner.push_objects(blobs) {
            Ok(seqs) => Ok(seqs),
            Err(e) => {
                *self.push_err.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
                Err(unissh_sync::SyncError::Format)
            }
        }
    }
    fn delta_since(&self, cursor: u64) -> Vec<(u64, SyncObject)> {
        self.inner
            .delta_since(cursor)
            .into_iter()
            .filter_map(|item| {
                SyncObject::from_bytes(&item.object)
                    .ok()
                    .map(|o| (item.server_seq, o))
            })
            .collect()
    }
    fn report_version(&self) -> u64 {
        self.inner.report_version()
    }
}

// === Веха-2: онбординг Path B (PAKE device-to-device) ===
//
// Дизайн-замечание (uniffi 0.31): `#[uniffi::constructor]` обязан возвращать
// `Self`/`Arc<Self>`/`Result<Arc<Self>>` — НЕ произвольный Record. Поэтому
// конструктор сразу выполняет PAKE-шаг и кладёт исходящее сообщение (`msg1`/
// `msg2`) ВНУТРЬ хэндла; релей-блоб отдаётся отдельным геттером `msg()`. Это
// согласованный fallback к плановой паре «handle + bytes» без изменения семантики
// (сообщения по-прежнему непрозрачные релей-блобы; состояние одноразовое).

/// Хэндл initiator-стороны PAKE-онбординга (Path B). Одноразовый: `start` создаёт
/// состояние + `msg1` (геттер `msg()`); `Core::onboard_confirm_and_seal`
/// потребляет состояние.
#[derive(uniffi::Object)]
pub struct OnboardInitiatorHandle {
    inner: Mutex<Option<OnboardInitiator>>,
    msg1: Vec<u8>,
}

#[uniffi::export]
impl OnboardInitiatorHandle {
    /// Стартует онбординг на существующем устройстве по OOB-коду. Возвращает хэндл,
    /// держащий состояние initiator и `msg1` (взять геттером [`Self::msg`]).
    #[uniffi::constructor]
    pub fn start(code: Vec<u8>) -> Arc<Self> {
        let code = Zeroizing::new(code);
        let (init, msg1) = OnboardInitiator::start(&code);
        Arc::new(OnboardInitiatorHandle {
            inner: Mutex::new(Some(init)),
            msg1,
        })
    }

    /// `msg1` — непрозрачный релей-блоб для responder'а.
    pub fn msg(&self) -> Vec<u8> {
        self.msg1.clone()
    }
}

/// Хэндл responder-стороны PAKE-онбординга (новое устройство). Одноразовый:
/// `respond` создаёт состояние + `msg2` (геттер `msg()`); `Core::
/// onboard_finish_install` потребляет состояние.
#[derive(uniffi::Object)]
pub struct OnboardResponderHandle {
    inner: Mutex<Option<OnboardResponder>>,
    msg2: Vec<u8>,
}

#[uniffi::export]
impl OnboardResponderHandle {
    /// Новое устройство принимает `msg1` по OOB-коду и формирует `msg2` (релей
    /// назад initiator'у; взять геттером [`Self::msg`]).
    #[uniffi::constructor]
    pub fn respond(code: Vec<u8>, msg1: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let code = Zeroizing::new(code);
        let (resp, msg2) = OnboardResponder::respond(&code, &msg1).map_err(map_keychain_err)?;
        Ok(Arc::new(OnboardResponderHandle {
            inner: Mutex::new(Some(resp)),
            msg2,
        }))
    }

    /// `msg2` — непрозрачный релей-блоб обратно initiator'у.
    pub fn msg(&self) -> Vec<u8> {
        self.msg2.clone()
    }
}

/// Пул idle SFTP-каналов поверх ОДНОГО SSH-соединения. russh мультиплексирует
/// много каналов на одном транспорте, поэтому параллельные передачи файлов не
/// требуют новых хендшейков/аутентификаций — только новые каналы.
///
/// Инвариант `created` = idle + арендованные (leased). Растёт лениво до `max`:
/// первый канал открыт при коннекте, остальные — по мере спроса. `generation`
/// растёт при полном `reconnect()`; канал старого поколения при возврате из аренды
/// не кладётся обратно в пул, а выбрасывается (его транспорт уже мёртв). `closed`
/// (close/Drop) заставляет аренду немедленно падать.
///
/// `max` — потолок числа каналов (K из настроек). Может **уменьшиться** во время
/// работы: если сервер отклоняет открытие нового канала (напр. `MaxSessions` →
/// `AdministrativelyProhibited`), пул ужимается до фактически разрешённого числа и
/// переиспользует уже открытые каналы (деградация к менее параллельному/
/// последовательному режиму) вместо провала передачи.
struct SftpPool {
    idle: Vec<SftpSession>,
    created: usize,
    max: usize,
    generation: u64,
    closed: bool,
}

/// SFTP-подключение: одно SSH-соединение + пул каналов ([`SftpPool`]). Операции
/// арендуют канал из пула, поэтому до `SftpPool::max` из них идут параллельно
/// (главный рычаг для сценария «много файлов»); при `max == 1` поведение
/// эквивалентно прежней строго последовательной сессии.
///
/// Каналы закрываются под `rt.enter()` (в `close`/Drop/при выбросе): внутренний
/// поток канала russh при Drop делает `tokio::spawn`, которому нужен контекст
/// рантайма — иначе паника при дропе вне рантайма.
#[derive(uniffi::Object)]
pub struct SftpFfi {
    client: Mutex<Option<SshClient>>,
    /// Пул каналов + условная переменная для блокирующей аренды: аренда вызывается
    /// с blocking-потоков Tauri (`spawn_blocking`), поэтому ждём через `Condvar`,
    /// а не через async-семафор.
    pool: Mutex<SftpPool>,
    pool_cv: Condvar,
    rt: Arc<tokio::runtime::Runtime>,
    // Reconnect inputs (mirror ReconnectingSession): when the whole SSH connection
    // dies on a long-idle session, `reopen()` rebuilds the client from these — a
    // bare channel reopen can't help once the transport itself is gone (russh then
    // surfaces "Channel send error" on every channel_open). `Agent`/`VaultPassword`
    // creds are re-resolved from the vault on each reconnect (plaintext isn't
    // cached); an inline `Password` lives in `auth` for the session's lifetime.
    state: Arc<Mutex<Option<CoreState>>>,
    host: String,
    port: u16,
    user: String,
    auth: AuthMethod,
    jumps: Vec<JumpHost>,
    // Serializes reopen(): two racing callers must not fan out into two full
    // reconnects (would orphan a connection). Mirrors ReconnectingSession.
    reconnect_lock: Mutex<()>,
}

/// Fast-path channel-reopen bound: if the server never OPEN-CONFIRMs (a silently
/// dead TCP with keepalive off never surfaces an error on its own), fail fast and
/// fall through to the timeout-bounded full reconnect instead of hanging forever
/// while holding the session locks.
const REOPEN_CHANNEL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Сколько раз повторить открытие канала, когда в пуле НЕ осталось ни одного
/// живого канала для отката, а сервер отказал в новом. Отказ обычно переходный:
/// слот сессии только что закрытого (выброшенного) канала ещё не освобождён на
/// сервере (`MaxSessions` → `AdministrativelyProhibited`). Ретраи с backoff
/// переживают это; реально мёртвое соединение исчерпает их и ошибка всплывёт.
const OPEN_RETRY_MAX: u32 = 6;
/// Линейный шаг backoff между ретраями открытия (attempt * шаг). Итого при
/// OPEN_RETRY_MAX=6 ожидание ~0.15+0.3+…+0.9 ≈ 3.1 c до отказа.
const OPEN_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(150);

impl SftpFfi {
    /// Арендует канал из пула, выполняет `f`, возвращает канал. До `SftpPool::max`
    /// операций идут параллельно; при насыщении блокирует вызывающий blocking-поток
    /// до освобождения канала. Канал возвращается в пул, если его поток не
    /// десинхронизирован (`!is_poisoned`) и поколение актуально — в т.ч. после
    /// ЧИСТОЙ файловой ошибки. Испорченный (обрыв/таймаут/прерванный конвейер)
    /// выбрасывается; пул само-лечится, открыв свежий при следующей аренде.
    fn with_sftp<T, F>(&self, f: F) -> Result<T, FfiError>
    where
        F: FnOnce(&Arc<tokio::runtime::Runtime>, &mut SftpSession) -> Result<T, FfiError>,
    {
        let (mut ch, gen) = self.lease()?;
        let r = f(&self.rt, &mut ch);
        // Возвращаем канал в пул, пока его поток НЕ десинхронизирован — даже при
        // ошибке операции. Чистая файловая ошибка (нет прав/файла, каталог уже
        // существует) не портит канал, и выбрасывать его незачем: именно
        // выбрасывание годных каналов (с переоткрытием) создавало channel-churn,
        // упиравшийся в серверный `MaxSessions`. Испорченный (обрыв/таймаут/
        // прерванный конвейер) канал выбрасываем — переиспользовать его нельзя.
        let healthy = !ch.is_poisoned();
        self.giveback(ch, gen, healthy);
        r
    }

    /// Блокирующая аренда канала. Возвращает канал и его поколение (для проверки
    /// актуальности при возврате).
    fn lease(&self) -> Result<(SftpSession, u64), FfiError> {
        let mut open_retries: u32 = 0;
        let mut p = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if p.closed {
                return Err(FfiError::other("sftp session closed"));
            }
            if let Some(ch) = p.idle.pop() {
                return Ok((ch, p.generation));
            }
            if p.created < p.max {
                // Резервируем слот и открываем канал ВНЕ лока пула: открытие делает
                // block_on и лочит client — держать при этом лок пула нельзя (иначе
                // сериализовали бы все аренды на время открытия).
                p.created += 1;
                let gen = p.generation;
                drop(p);
                match self.open_channel() {
                    Ok(ch) => return Ok((ch, gen)),
                    Err(e) => {
                        p = self.pool.lock().unwrap_or_else(|e| e.into_inner());
                        p.created -= 1;
                        if p.created > 0 {
                            // Есть живой канал для отката. Сервер отказал в НОВОМ
                            // (типично `MaxSessions` → `AdministrativelyProhibited`):
                            // ужимаем потолок до разрешённого и переиспользуем
                            // существующие — деградация, а не провал передачи. НЕ ждём
                            // здесь напрямую: пока канал открывался (лок был отпущен),
                            // другой поток мог вернуть свой и его notify ушёл вхолостую
                            // — возвращаемся в начало цикла, где idle.pop() под тем же
                            // локом либо заберёт канал, либо уйдёт в wait без гонки.
                            if p.max > p.created {
                                p.max = p.created;
                            }
                            continue;
                        }
                        // Ни одного живого канала для отката. Обычно отказ переходный:
                        // слот только что выброшенного канала ещё не освобождён на
                        // сервере. Повторяем открытие с backoff; исчерпав ретраи (реально
                        // мёртвое соединение) — отдаём ошибку.
                        open_retries += 1;
                        if open_retries > OPEN_RETRY_MAX {
                            drop(p);
                            self.pool_cv.notify_one();
                            return Err(e);
                        }
                        drop(p);
                        std::thread::sleep(OPEN_RETRY_BACKOFF * open_retries);
                        p = self.pool.lock().unwrap_or_else(|e| e.into_inner());
                    }
                }
            } else {
                // Все каналы созданы и заняты — ждём, пока кто-то вернёт свой.
                p = self.pool_cv.wait(p).unwrap_or_else(|e| e.into_inner());
            }
        }
    }

    /// Возвращает канал в пул (успех) либо выбрасывает его (ошибка / закрытие /
    /// устаревшее поколение), уменьшая `created`. В обоих случаях будит одного
    /// ожидающего аренды.
    fn giveback(&self, ch: SftpSession, gen: u64, healthy: bool) {
        let mut p = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        if healthy && !p.closed && gen == p.generation {
            p.idle.push(ch);
            drop(p);
            self.pool_cv.notify_one();
        } else {
            p.created = p.created.saturating_sub(1);
            drop(p);
            self.pool_cv.notify_one();
            // Мёртвый/устаревший канал дропаем под rt.enter() — teardown канала
            // делает tokio::spawn.
            let _enter = self.rt.enter();
            drop(ch);
        }
    }

    /// Открывает один новый SFTP-канал на текущем соединении. block_on нельзя звать
    /// в контексте рантайма (паника) — здесь мы на blocking-потоке, контекста нет.
    /// Bounded таймаутом: молча-мёртвое соединение (keepalive off, без RST) иначе
    /// ждало бы OPEN-CONFIRM вечно.
    fn open_channel(&self) -> Result<SftpSession, FfiError> {
        let client_guard = self.client.lock().unwrap_or_else(|e| e.into_inner());
        let client = client_guard
            .as_ref()
            .ok_or_else(|| FfiError::other("sftp client closed"))?;
        self.rt
            .block_on(async {
                tokio::time::timeout(REOPEN_CHANNEL_TIMEOUT, client.open_sftp()).await
            })
            .map_err(|_| FfiError::other("sftp channel open timed out"))?
            .map_err(map_transport_err)
    }

    /// Полный реконнект: пересобирает SSH-соединение из сохранённых параметров
    /// (креды переразрешаются из волта). Нужен, когда простаивающее соединение
    /// умерло целиком — открытие канала на мёртвом `Handle` не спасёт (russh отдаёт
    /// «Channel send error»). Бампает `generation`, поэтому арендованные каналы
    /// старого поколения при возврате выбрасываются, а idle-каналы дропаются здесь.
    fn reconnect(&self) -> Result<(), FfiError> {
        // Сеть/handshake вне контекста рантайма (внутри block_on connect_with_state).
        let client = connect_with_state(
            &self.state,
            &self.rt,
            &self.auth,
            &self.jumps,
            self.host.clone(),
            self.port,
            self.user.clone(),
        )?;
        let old_idle = {
            let mut p = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            let old_idle = std::mem::take(&mut p.idle);
            p.created = p.created.saturating_sub(old_idle.len());
            p.generation = p.generation.wrapping_add(1);
            p.closed = false;
            old_idle
        };
        let old_client = self
            .client
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(client);
        // Пробудить всех ждущих аренды: слоты освободились (created уменьшен).
        self.pool_cv.notify_all();
        // Старые idle-каналы и клиент дропаются под rt.enter() (teardown → spawn).
        let _enter = self.rt.enter();
        drop(old_idle);
        drop(old_client);
        Ok(())
    }

    /// Закрывает пул и соединение: помечает `closed`, дропает все idle-каналы
    /// (арендованные закроются при возврате, увидев `closed`) и клиента — всё под
    /// `rt.enter()`. Общая реализация для [`Self::close`] и `Drop`.
    fn teardown(&self) {
        let _enter = self.rt.enter();
        let old_idle = {
            let mut p = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            p.closed = true;
            let old_idle = std::mem::take(&mut p.idle);
            p.created = p.created.saturating_sub(old_idle.len());
            old_idle
        };
        self.pool_cv.notify_all();
        drop(old_idle);
        let _ = self.client.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

#[uniffi::export]
impl SftpFfi {
    /// Список каталога.
    pub fn list_dir(&self, path: String) -> Result<Vec<SftpEntry>, FfiError> {
        self.with_sftp(|rt, s| {
            let entries = rt.block_on(s.list_dir(&path)).map_err(map_transport_err)?;
            Ok(entries
                .into_iter()
                .map(|e| SftpEntry {
                    filename: e.filename,
                    is_dir: e.is_dir,
                    size: e.size,
                    mode: e.mode,
                    mtime: e.mtime,
                })
                .collect())
        })
    }

    /// Скачивает файл целиком.
    pub fn read_file(&self, path: String) -> Result<Vec<u8>, FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.read_file(&path)).map_err(map_transport_err))
    }

    /// Загружает файл (создаёт/перезаписывает).
    pub fn write_file(&self, path: String, data: Vec<u8>) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| {
            rt.block_on(s.write_file(&path, &data))
                .map_err(map_transport_err)
        })
    }

    /// Удаляет файл.
    pub fn remove(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.remove(&path)).map_err(map_transport_err))
    }

    /// Создаёт каталог.
    pub fn mkdir(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.mkdir(&path)).map_err(map_transport_err))
    }

    /// Возобновляемое скачивание `remote_path` → локальный `local_path` с `offset`
    /// (для докачки), с прогрессом и отменой. Возвращает `true`, если завершено;
    /// `false` — если прервано отменой (можно продолжить с нового offset).
    /// `known_size` — размер удалённого файла, если он уже известен вызывающему
    /// (напр. из листинга при рекурсивной выгрузке папки): позволяет ядру
    /// пропустить `stat` и сэкономить round-trip на файл. `None` → ядро сделает
    /// `stat` само.
    pub fn sftp_download(
        &self,
        remote_path: String,
        local_path: String,
        offset: u64,
        known_size: Option<u64>,
        progress: Option<Arc<dyn SftpProgressObserver>>,
        cancel: Option<Arc<CancelToken>>,
    ) -> Result<bool, FfiError> {
        let prog = progress
            .map(|p| Arc::new(ProgressBridge(p)) as Arc<dyn unissh_ssh_transport::SftpProgress>);
        let canc = cancel.map(|c| {
            Arc::new(CancelBridge(c.flag.clone())) as Arc<dyn unissh_ssh_transport::SftpCancel>
        });
        self.with_sftp(move |rt, s| {
            let outcome = rt
                .block_on(s.download_to(&remote_path, &local_path, offset, known_size, prog, canc))
                .map_err(map_transport_err)?;
            Ok(outcome == unissh_ssh_transport::TransferOutcome::Completed)
        })
    }

    /// Возобновляемая загрузка локального `local_path` → `remote_path` с `offset`,
    /// с прогрессом и отменой. Не использует TRUNC — докачка не затирает префикс.
    pub fn sftp_upload(
        &self,
        local_path: String,
        remote_path: String,
        offset: u64,
        progress: Option<Arc<dyn SftpProgressObserver>>,
        cancel: Option<Arc<CancelToken>>,
    ) -> Result<bool, FfiError> {
        let prog = progress
            .map(|p| Arc::new(ProgressBridge(p)) as Arc<dyn unissh_ssh_transport::SftpProgress>);
        let canc = cancel.map(|c| {
            Arc::new(CancelBridge(c.flag.clone())) as Arc<dyn unissh_ssh_transport::SftpCancel>
        });
        self.with_sftp(move |rt, s| {
            let outcome = rt
                .block_on(s.upload_from(&local_path, &remote_path, offset, prog, canc))
                .map_err(map_transport_err)?;
            Ok(outcome == unissh_ssh_transport::TransferOutcome::Completed)
        })
    }

    /// Удаляет каталог.
    pub fn rmdir(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.rmdir(&path)).map_err(map_transport_err))
    }

    /// Рекурсивно удаляет каталог со всем содержимым (как `rm -rf`).
    pub fn rmdir_recursive(&self, path: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.remove_tree(&path)).map_err(map_transport_err))
    }

    /// Переименовывает/перемещает.
    pub fn rename(&self, from: String, to: String) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.rename(&from, &to)).map_err(map_transport_err))
    }

    /// chmod: меняет права (низшие 12 бит st_mode).
    pub fn chmod(&self, path: String, mode: u32) -> Result<(), FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.chmod(&path, mode)).map_err(map_transport_err))
    }

    /// stat по пути.
    pub fn stat(&self, path: String) -> Result<SftpFileStat, FfiError> {
        self.with_sftp(|rt, s| {
            let st = rt.block_on(s.stat(&path)).map_err(map_transport_err)?;
            Ok(SftpFileStat {
                size: st.size,
                is_dir: st.is_dir,
                mode: st.mode,
                mtime: st.mtime,
            })
        })
    }

    /// Канонизирует путь.
    pub fn realpath(&self, path: String) -> Result<String, FfiError> {
        self.with_sftp(|rt, s| rt.block_on(s.realpath(&path)).map_err(map_transport_err))
    }

    /// Восстанавливает рабочую SFTP-сессию. Сначала дёшево пробует переоткрыть
    /// канал поверх живого соединения (сервер прибил простаивающий канал); если
    /// само соединение мертво — типичный случай долгого простоя, когда транспорт
    /// уже умер и russh отдаёт «Channel send error», — пересобирает соединение с
    /// нуля и открывает новый канал. `HostKeyMismatch` реконнектом НЕ лечится
    /// (возможный MITM → стоп), пробрасывается как есть.
    pub fn reopen(&self) -> Result<(), FfiError> {
        // Serialize concurrent reopens so two racing callers can't each rebuild the
        // connection (one would be orphaned). Held across the whole escalation.
        let _g = self
            .reconnect_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Быстрый путь: открыть свежий канал на текущем соединении — это и проверка
        // живости транспорта, и «прогрев» пула. Успех кладём в пул как idle.
        match self.open_channel() {
            Ok(ch) => {
                let mut p = self.pool.lock().unwrap_or_else(|e| e.into_inner());
                if p.closed {
                    drop(p);
                    let _enter = self.rt.enter();
                    drop(ch);
                    return Ok(());
                }
                p.created += 1;
                p.idle.push(ch);
                drop(p);
                self.pool_cv.notify_one();
                Ok(())
            }
            // Канал не открылся — вероятно, мёртво само соединение: полный реконнект
            // (он же пробрасывает HostKeyMismatch при пересборке).
            Err(_) => self.reconnect(),
        }
    }

    /// Закрывает пул каналов и соединение.
    pub fn close(&self) {
        self.teardown();
    }
}

impl Drop for SftpFfi {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Идентификатор ключа во встроенном агенте, НАМЕСПЕЙСНУТЫЙ по `(vault_id, item_id)`
/// (A4, sec-review): агент переживает переключения волта и коннекты, а item_id не
/// уникальны между волтами (напр. все зовут ключ `id_ed25519`). Без namespace второй
/// `load` короткозамыкался бы на `contains()` и подписывал НЕ тем ключом. Длина-
/// префикс vault_id гарантирует однозначность. Тот же id строит `Auth::Agent`.
fn agent_key_id(vault_id: &str, key_item_id: &str) -> Vec<u8> {
    let v = vault_id.as_bytes();
    let k = key_item_id.as_bytes();
    let mut out = Vec::with_capacity(4 + v.len() + k.len());
    out.extend_from_slice(&(v.len() as u32).to_be_bytes());
    out.extend_from_slice(v);
    out.extend_from_slice(k);
    out
}

fn load_key_into_agent(
    state: &mut CoreState,
    vault_id: &str,
    key_item_id: &str,
) -> Result<(), FfiError> {
    let akid = agent_key_id(vault_id, key_item_id);
    if state.agent.contains(&akid) {
        return Ok(());
    }
    // Достаём ключ и (если есть) сертификат внутри одной области видимости vault,
    // чтобы заимствование storage/keyset завершилось до &mut agent ниже.
    let (key_item, cert_str) = {
        let vault = Vault::open(
            &state.storage,
            &state.keyset,
            &resolve_vid(&state.storage, vault_id),
        )
        .map_err(FfiError::other)?;
        let key_item = vault
            .get_item(key_item_id.as_bytes())
            .map_err(FfiError::other)?
            .ok_or(FfiError::NotFound)?;
        let cert_str = vault
            .get_item(cert_item_id(key_item_id).as_bytes())
            .map_err(FfiError::other)?
            .map(|c| String::from_utf8_lossy(c.content.as_slice()).to_string());
        (key_item, cert_str)
    };

    state
        .agent
        .add_from_item(akid.clone(), &key_item)
        .map_err(FfiError::ssh)?;
    if let Some(cert) = cert_str {
        state
            .agent
            .attach_certificate(&akid, &cert)
            .map_err(FfiError::ssh)?;
    }
    Ok(())
}

/// Ключ SQLCipher выводится из секретов keyset (нужна разблокировка, чтобы
/// открыть БД). HKDF-SHA256 поверх приватных X25519+Ed25519. Все промежуточные
/// копии секретов и сам ключ — в `Zeroizing`, зануляются при выходе/Drop.
fn derive_db_key(keyset: &unissh_keychain::UnlockedKeyset) -> Zeroizing<[u8; 32]> {
    let x_secret = Zeroizing::new(keyset.encryption.secret.expose_to_bytes());
    let e_secret = Zeroizing::new(keyset.signing.signing.expose_to_bytes());
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x_secret.as_ref());
    ikm.extend_from_slice(e_secret.as_ref());

    let hk = Hkdf::<Sha256>::new(Some(b"unissh-db-key-salt-v1"), ikm.as_ref());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"unissh-db-key-v1", key.as_mut())
        .expect("32 is a valid HKDF length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_keyset_sidecar_copies_and_is_noop_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keyset");
        let bak = {
            let mut p = path.as_os_str().to_owned();
            p.push(".pre-migration.bak");
            std::path::PathBuf::from(p)
        };
        // Сайдкара нет → no-op (без паники, без .bak).
        backup_keyset_sidecar(&path);
        assert!(!bak.exists(), "нет бэкапа, если сайдкара ещё нет");
        // Сайдкар есть → создаётся .bak с тем же содержимым.
        std::fs::write(&path, b"OLD-KEYSET-BLOB").unwrap();
        backup_keyset_sidecar(&path);
        assert_eq!(std::fs::read(&bak).unwrap(), b"OLD-KEYSET-BLOB");
    }

    #[test]
    fn account_state_payload_roundtrip_and_reject_malformed() {
        let p = AccountStatePayload {
            personal_vault_id: vec![1, 2, 3, 4],
            default_username: "deploy".into(),
        };
        let dec = AccountStatePayload::decode(&p.encode()).unwrap();
        assert_eq!(dec.personal_vault_id, p.personal_vault_id);
        assert_eq!(dec.default_username, "deploy");

        // Пустые поля = «не задано».
        let de = AccountStatePayload::decode(&AccountStatePayload::default().encode()).unwrap();
        assert!(de.personal_vault_id.is_empty() && de.default_username.is_empty());

        // Битый вход отвергается (не паникует).
        assert!(AccountStatePayload::decode(&[0, 0, 0, 9, 1, 2, 3]).is_err()); // len>data
        assert!(AccountStatePayload::decode(&[]).is_err());
        let mut trailing = p.encode();
        trailing.push(0xFF);
        assert!(AccountStatePayload::decode(&trailing).is_err());
    }

    #[test]
    fn agent_key_id_namespaces_by_vault_and_item() {
        // Одинаковый item_id в РАЗНЫХ волтах → разные agent-id (нет aliasing).
        assert_ne!(
            agent_key_id("vaultA", "id_ed25519"),
            agent_key_id("vaultB", "id_ed25519")
        );
        // Одна пара → один id (load и Auth::Agent совпадают).
        assert_eq!(agent_key_id("v", "k"), agent_key_id("v", "k"));
        // Длина-префикс исключает склейку: ("v","aultk") != ("va","ultk").
        assert_ne!(agent_key_id("v", "aultk"), agent_key_id("va", "ultk"));
    }

    /// Регрессия (A4a namespace): delete_item и замена материала ключа ДОЛЖНЫ
    /// выгружать приватник из in-memory агента под тем же namespaced-ключом
    /// agent_key_id(vault,item), которым он был загружен — иначе remove — no-op и
    /// отозванный/заменённый ключ остаётся живым и подписывающим до конца сессии.
    #[test]
    fn revoking_key_evicts_it_from_agent() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();

        // delete_item выгружает загруженный ключ.
        core.generate_ssh_key("v".into(), "k".into()).unwrap();
        let akid = agent_key_id("v", "k");
        {
            let mut guard = core.locked_state();
            load_key_into_agent(guard.as_mut().unwrap(), "v", "k").unwrap();
            assert!(
                guard.as_ref().unwrap().agent.contains(&akid),
                "ключ загружен под namespaced id"
            );
        }
        core.delete_item("v".into(), "k".into()).unwrap();
        assert!(
            !core.locked_state().as_ref().unwrap().agent.contains(&akid),
            "delete_item обязан выгрузить ключ из агента (иначе обход отзыва)"
        );

        // Замена материала под тем же id (generate поверх) тоже выгружает старый.
        core.generate_ssh_key("v".into(), "k2".into()).unwrap();
        let akid2 = agent_key_id("v", "k2");
        {
            let mut guard = core.locked_state();
            load_key_into_agent(guard.as_mut().unwrap(), "v", "k2").unwrap();
            assert!(guard.as_ref().unwrap().agent.contains(&akid2));
        }
        core.generate_ssh_key("v".into(), "k2".into()).unwrap();
        assert!(
            !core.locked_state().as_ref().unwrap().agent.contains(&akid2),
            "замена материала обязана выгрузить прежний ключ"
        );
    }

    /// #9: повторный import_ssh_config сохраняет неизменяемый uid профиля —
    /// binding'и и hop_ref'ы завязаны на него, свежий uid при перезаписи
    /// осиротил бы их.
    #[test]
    fn import_ssh_config_preserves_uid_on_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();

        core.import_ssh_config(
            "v".into(),
            "Host web\n  HostName web.example\n  Port 22\n  User deploy\n".into(),
        )
        .unwrap();
        let uid1 = core.get_connection("v".into(), "web".into()).unwrap().uid;
        assert!(!uid1.is_empty());

        // Перезапись тем же алиасом (сменился порт) — uid обязан сохраниться.
        core.import_ssh_config(
            "v".into(),
            "Host web\n  HostName web.example\n  Port 2222\n  User deploy\n".into(),
        )
        .unwrap();
        let p2 = core.get_connection("v".into(), "web".into()).unwrap();
        assert_eq!(p2.uid, uid1, "uid сохраняется при перезаписи (#9)");
        assert_eq!(p2.port, 2222, "остальные поля обновились");
    }

    /// Легаси-профиль (до password-items): `key_item_id` плоским полем, у jump —
    /// обязательной строкой (возможно пустой). Должен читаться без миграции.
    #[test]
    fn legacy_stored_profile_deserializes() {
        let legacy = r#"{
            "label":"L","host":"h","port":22,"user":"u",
            "key_item_id":"k1",
            "jumps":[{"host":"j","port":2200,"user":"ju","key_item_id":"k2"},
                     {"host":"j2","port":22,"user":"","key_item_id":""}]
        }"#;
        let stored: StoredProfile = serde_json::from_str(legacy).unwrap();
        let prof = stored_to_profile("vaultA", "p1".to_string(), stored);
        assert!(matches!(
            &prof.auth,
            ProfileAuth::Key { key_item_id } if key_item_id == "k1"
        ));
        // Хоп профиля vault-квалифицирован волтом профиля.
        assert!(matches!(
            &prof.jumps[0].auth,
            AuthMethod::Agent { vault_id, key_item_id } if vault_id == "vaultA" && key_item_id == "k2"
        ));
        // пустой key_item_id (импорт ssh-config) — семантика «не назначен»
        assert!(matches!(
            &prof.jumps[1].auth,
            AuthMethod::Agent { vault_id, key_item_id } if vault_id == "vaultA" && key_item_id.is_empty()
        ));

        // легаси «парольный» профиль: key_item_id = null → спросить при коннекте
        let legacy_pw = r#"{"label":"L","host":"h","port":22,"user":"u",
                            "key_item_id":null,"jumps":[]}"#;
        let stored: StoredProfile = serde_json::from_str(legacy_pw).unwrap();
        let prof = stored_to_profile("vaultA", "p2".to_string(), stored);
        assert!(matches!(prof.auth, ProfileAuth::PromptPassword));
    }

    /// Новый формат: ссылка на пароль-item приоритетнее ключа и переживает
    /// сериализацию туда-обратно.
    #[test]
    fn vault_password_profile_roundtrip() {
        let prof = ConnectionProfile {
            profile_id: "p".to_string(),
            uid: "uid-fixed".to_string(),
            label: "L".to_string(),
            host: "h".to_string(),
            port: 22,
            user: "u".to_string(),
            auth: ProfileAuth::VaultPassword {
                password_item_id: "pw1".to_string(),
            },
            username_template: None,
            jumps: vec![JumpHost {
                host: "j".to_string(),
                port: 22,
                user: "ju".to_string(),
                auth: AuthMethod::VaultPassword {
                    vault_id: "vp".to_string(),
                    password_item_id: "pw2".to_string(),
                },
                hop_ref: None,
            }],
            tags: vec!["prod".to_string()],
        };
        let (key_item_id, password_item_id) = match prof.auth.clone() {
            ProfileAuth::Key { key_item_id } => (Some(key_item_id), None),
            ProfileAuth::VaultPassword { password_item_id } => (None, Some(password_item_id)),
            ProfileAuth::PromptPassword | ProfileAuth::Personal => (None, None),
        };
        let stored = StoredProfile {
            uid: Some(prof.uid.clone()),
            label: prof.label.clone(),
            host: prof.host.clone(),
            port: prof.port,
            user: prof.user.clone(),
            key_item_id,
            password_item_id,
            personal: false,
            username_template: None,
            jumps: prof
                .jumps
                .clone()
                .into_iter()
                .map(|j| jump_to_stored(j).unwrap())
                .collect(),
            tags: prof.tags.clone(),
            extra: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredProfile = serde_json::from_str(&json).unwrap();
        let prof2 = stored_to_profile("vp", "p".to_string(), back);
        assert!(matches!(
            &prof2.auth,
            ProfileAuth::VaultPassword { password_item_id } if password_item_id == "pw1"
        ));
        // Хоп восстанавливается с волтом профиля (vault-относительное хранение).
        assert!(matches!(
            &prof2.jumps[0].auth,
            AuthMethod::VaultPassword { vault_id, password_item_id }
                if vault_id == "vp" && password_item_id == "pw2"
        ));
        // uid переживает round-trip (не переминчивается при чтении сохранённого).
        assert_eq!(prof2.uid, "uid-fixed");
        assert_eq!(prof2.tags, vec!["prod".to_string()]);
    }

    /// Inline-пароль в jump-хосте не сериализуется в профиль — ошибка.
    #[test]
    fn inline_jump_password_is_rejected() {
        let jump = JumpHost {
            host: "j".to_string(),
            port: 22,
            user: "u".to_string(),
            auth: AuthMethod::Password {
                password: "sekret".to_string(),
            },
            hop_ref: None,
        };
        assert!(jump_to_stored(jump).is_err());
    }

    /// A4b: ссылка профиля на креды получает `vault_id` того волта, где живёт
    /// профиль, — чтобы цель и хопы могли резолвиться против РАЗНЫХ волтов.
    #[test]
    fn profile_auth_is_vault_qualified() {
        assert!(matches!(
            profile_auth_to_method("teamvault", ProfileAuth::Key { key_item_id: "k".into() }),
            AuthMethod::Agent { vault_id, key_item_id } if vault_id == "teamvault" && key_item_id == "k"
        ));
        assert!(matches!(
            profile_auth_to_method(
                "personal",
                ProfileAuth::VaultPassword { password_item_id: "pw".into() }
            ),
            AuthMethod::VaultPassword { vault_id, password_item_id }
                if vault_id == "personal" && password_item_id == "pw"
        ));
        // PromptPassword не привязан к волту (inline, спрашивается при коннекте).
        assert!(matches!(
            profile_auth_to_method("any", ProfileAuth::PromptPassword),
            AuthMethod::Password { password } if password.is_empty()
        ));
    }

    /// B2.2: host-chain-ссылка хопа переживает jump_to_stored → stored_to_profile.
    #[test]
    fn hop_ref_roundtrip() {
        let j = JumpHost {
            host: String::new(),
            port: 0,
            user: String::new(),
            auth: AuthMethod::Agent {
                vault_id: String::new(),
                key_item_id: String::new(),
            },
            hop_ref: Some(HopRef {
                vault_id: "teamvault".into(),
                profile_uid: "uid-bastion".into(),
            }),
        };
        let stored = jump_to_stored(j).unwrap();
        assert!(stored.hop_ref.is_some());
        let sp = StoredProfile {
            uid: Some("u".into()),
            label: "L".into(),
            host: "h".into(),
            port: 22,
            user: "x".into(),
            key_item_id: None,
            password_item_id: None,
            personal: false,
            username_template: None,
            jumps: vec![stored],
            tags: vec![],
            extra: std::collections::BTreeMap::new(),
        };
        let prof = stored_to_profile("va", "p".into(), sp);
        let hr = prof.jumps[0].hop_ref.as_ref().unwrap();
        assert_eq!(hr.vault_id, "teamvault");
        assert_eq!(hr.profile_uid, "uid-bastion");
    }

    /// B2.2: resolve_profile_by_uid находит профиль-бастион по его uid.
    #[test]
    fn resolve_profile_by_uid_finds_bastion() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        core.save_connection(
            "v".into(),
            ConnectionProfile {
                profile_id: "bastion".into(),
                uid: String::new(),
                label: "B".into(),
                host: "gw.example".into(),
                port: 2222,
                user: "jump".into(),
                auth: ProfileAuth::PromptPassword,
                username_template: None,
                jumps: vec![],
                tags: vec![],
            },
        )
        .unwrap();
        let bastion = core.get_connection("v".into(), "bastion".into()).unwrap();
        // По uid находим бастион.
        {
            let guard = core.locked_state();
            let state = guard.as_ref().unwrap();
            let found = resolve_profile_by_uid(state, "v", &bastion.uid).unwrap();
            assert_eq!(found.host, "gw.example");
            assert_eq!(found.port, 2222);
            assert_eq!(found.user, "jump");
        }
        // Неизвестный uid → NotFound.
        {
            let guard = core.locked_state();
            let state = guard.as_ref().unwrap();
            assert!(resolve_profile_by_uid(state, "v", "nope").is_err());
        }
    }

    /// B1: тело идентичности сериализуется туда-обратно; отсутствующие
    /// опциональные ссылки читаются как `None` (forward-совместимость).
    #[test]
    fn stored_identity_roundtrip_and_into() {
        let stored = StoredIdentity {
            label: "Prod login".into(),
            user: "alice".into(),
            key_item_id: Some("id_ed25519".into()),
            password_item_id: None,
            extra: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredIdentity = serde_json::from_str(&json).unwrap();
        let id = back.into_identity("ident1".into());
        assert_eq!(id.identity_id, "ident1");
        assert_eq!(id.user, "alice");
        assert_eq!(id.key_item_id.as_deref(), Some("id_ed25519"));
        assert!(id.password_item_id.is_none());
        // минимальное тело (без ссылок) — обе ссылки None.
        let minimal = r#"{"label":"L","user":"bob"}"#;
        let m: StoredIdentity = serde_json::from_str(minimal).unwrap();
        assert!(m.key_item_id.is_none() && m.password_item_id.is_none());
    }

    /// B2: uid профиля. Легаси-fallback детерминирован (стабилен между
    /// устройствами и вызовами); свежеминченный — уникален и непуст.
    #[test]
    fn profile_uid_legacy_deterministic_and_mint_unique() {
        let a = legacy_profile_uid("vault1", "prod-web");
        assert_eq!(a, legacy_profile_uid("vault1", "prod-web"));
        assert_eq!(a.len(), 32); // 16 байт в hex
                                 // Длина-префикс vault_id исключает склейку соседних полей.
        assert_ne!(
            legacy_profile_uid("vault1", "prod-web"),
            legacy_profile_uid("vault", "1prod-web")
        );
        assert_ne!(
            legacy_profile_uid("vault1", "prod-web"),
            legacy_profile_uid("vault1", "prod-db")
        );
        // Минт: непуст, уникален между вызовами (с подавляющей вероятностью).
        let m1 = mint_profile_uid();
        assert_eq!(m1.len(), 32);
        assert_ne!(m1, mint_profile_uid());
    }

    /// B3.1: анти-редирект-логика. Расхождение назначения НИКОГДА не «обучается»
    /// молча — всегда `Redirected` (нужен явный re-bind).
    #[test]
    fn resolve_binding_anti_redirect() {
        let b = IdentityBinding {
            team_vault_id: "team".into(),
            profile_uid: "uid1".into(),
            identity_item_id: "ident1".into(),
            destination_pin: "prod-web:22".into(),
        };
        // Нет привязки → fallback.
        assert_eq!(
            resolve_binding(None, "prod-web:22"),
            BindingResolution::Unbound
        );
        // Совпало → можно логиниться личной идентичностью.
        assert_eq!(
            resolve_binding(Some(&b), "prod-web:22"),
            BindingResolution::Matched {
                identity_item_id: "ident1".into()
            }
        );
        // Хост переклеен (host in-place) → отказ, а не молчаливая переотправка кредов.
        assert_eq!(
            resolve_binding(Some(&b), "evil-host:22"),
            BindingResolution::Redirected {
                pinned: "prod-web:22".into(),
                current: "evil-host:22".into()
            }
        );
        // Смена порта тоже считается редиректом.
        assert!(matches!(
            resolve_binding(Some(&b), "prod-web:2222"),
            BindingResolution::Redirected { .. }
        ));
    }

    /// B3.1: item_id привязки детерминирован от (team_vault_id, profile_uid) и
    /// не склеивает соседние поля (длина-префикс).
    #[test]
    fn binding_item_id_deterministic_and_unambiguous() {
        assert_eq!(
            binding_item_id("team", "uid1"),
            binding_item_id("team", "uid1")
        );
        assert_ne!(
            binding_item_id("team", "uid1"),
            binding_item_id("team", "uid2")
        );
        // ("team","1uid1") != ("team1","uid1") — благодаря len-префиксу.
        assert_ne!(
            binding_item_id("team", "1uid1"),
            binding_item_id("team1", "uid1")
        );
        assert!(binding_item_id("team", "uid1").starts_with("binding:"));
    }

    /// B3.1: тело привязки переживает сериализацию туда-обратно.
    #[test]
    fn stored_binding_roundtrip() {
        let stored = StoredBinding {
            team_vault_id: "team".into(),
            profile_uid: "uid1".into(),
            identity_item_id: "ident1".into(),
            destination_pin: "h:22".into(),
            extra: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&stored).unwrap();
        let back: StoredBinding = serde_json::from_str(&json).unwrap();
        let b = back.into_binding();
        assert_eq!(b.team_vault_id, "team");
        assert_eq!(b.profile_uid, "uid1");
        assert_eq!(b.identity_item_id, "ident1");
        assert_eq!(b.destination_pin, "h:22");
    }

    /// B7: forward-compat. Неизвестное поле (от будущей версии) захватывается в
    /// `extra` и переживает deserialize→serialize; пустой `extra` не добавляет
    /// ключей (существующие подписанные items байт-в-байт не меняются).
    #[test]
    fn stored_profile_preserves_unknown_fields() {
        let json = r#"{"uid":"u","label":"L","host":"h","port":22,"user":"x",
                       "jumps":[],"tags":[],"future_field":"keep","future_num":7}"#;
        let sp: StoredProfile = serde_json::from_str(json).unwrap();
        assert_eq!(
            sp.extra.get("future_field").and_then(|v| v.as_str()),
            Some("keep")
        );
        assert_eq!(sp.extra.get("future_num").and_then(|v| v.as_i64()), Some(7));
        let out = serde_json::to_string(&sp).unwrap();
        assert!(out.contains("future_field") && out.contains("future_num"));
        // Пустой extra → никаких лишних ключей.
        let sp0: StoredProfile = serde_json::from_str(
            r#"{"label":"L","host":"h","port":22,"user":"x","jumps":[],"tags":[]}"#,
        )
        .unwrap();
        assert!(sp0.extra.is_empty());
        assert!(!serde_json::to_string(&sp0).unwrap().contains("extra"));
    }

    /// B7: правка профиля клиентом, НЕ знающим поле будущей версии, СОХРАНЯЕТ его
    /// (merge-on-save) — нет молчаливого LWW-даунгрейда.
    #[test]
    fn save_connection_preserves_future_fields_on_edit() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        core.save_connection(
            "v".into(),
            ConnectionProfile {
                profile_id: "p".into(),
                uid: String::new(),
                label: "L".into(),
                host: "h".into(),
                port: 22,
                user: "x".into(),
                auth: ProfileAuth::PromptPassword,
                username_template: None,
                jumps: vec![],
                tags: vec![],
            },
        )
        .unwrap();
        // Инжектим «поле будущей версии» прямо в сохранённый JSON (как более
        // новый клиент), в обход публичного API.
        let read_future = || -> Option<String> {
            let mut guard = core.locked_state();
            let st = guard.as_mut().unwrap();
            let vid = resolve_vid(&st.storage, "v");
            let vault = Vault::open(&st.storage, &st.keyset, &vid).unwrap();
            let item = vault.get_item(b"p").unwrap().unwrap();
            let sp: StoredProfile = serde_json::from_slice(&item.content).unwrap();
            sp.extra
                .get("future")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        {
            let mut guard = core.locked_state();
            let st = guard.as_mut().unwrap();
            let vid = resolve_vid(&st.storage, "v");
            let vault = Vault::open(&st.storage, &st.keyset, &vid).unwrap();
            let item = vault.get_item(b"p").unwrap().unwrap();
            let mut sp: StoredProfile = serde_json::from_slice(&item.content).unwrap();
            sp.extra.insert("future".into(), serde_json::json!("keep"));
            let json = serde_json::to_vec(&sp).unwrap();
            vault.put_item(b"p", ITEM_TYPE_CONNECTION, &json).unwrap();
        }
        assert_eq!(read_future(), Some("keep".to_string()));
        // Текущий клиент (не знает "future") правит профиль.
        let mut p = core.get_connection("v".into(), "p".into()).unwrap();
        p.label = "renamed".into();
        core.save_connection("v".into(), p).unwrap();
        // Поле пережило правку.
        assert_eq!(read_future(), Some("keep".to_string()));
    }

    /// B3.1/B3.2: binding CRUD против живого Core + first-bind guard (молчаливый
    /// пере-пин на другое назначение без allow_rebind отвергается).
    #[test]
    fn binding_crud_and_first_bind_guard() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("personal".into(), "Personal".into())
            .unwrap();
        let b = IdentityBinding {
            team_vault_id: "team".into(),
            profile_uid: "uid1".into(),
            identity_item_id: "ident1".into(),
            destination_pin: "prod-web:22".into(),
        };
        // Первая привязка — ок.
        core.set_binding("personal".into(), b.clone(), false)
            .unwrap();
        let got = core
            .get_binding("personal".into(), "team".into(), "uid1".into())
            .unwrap()
            .unwrap();
        assert_eq!(got.identity_item_id, "ident1");
        assert_eq!(got.destination_pin, "prod-web:22");
        // Идемпотентный пере-пин (то же назначение, смена только идентичности) —
        // без флага ок.
        let mut b2 = b.clone();
        b2.identity_item_id = "ident2".into();
        core.set_binding("personal".into(), b2, false).unwrap();
        // Пере-пин на ДРУГОЕ назначение без allow_rebind — отказ.
        let mut b3 = b.clone();
        b3.destination_pin = "evil:22".into();
        assert!(core
            .set_binding("personal".into(), b3.clone(), false)
            .is_err());
        // С allow_rebind=true — ок.
        core.set_binding("personal".into(), b3, true).unwrap();
        // resolve_host_binding отражает пин: совпало → Matched, иначе → Redirected.
        assert!(matches!(
            core.resolve_host_binding(
                "personal".into(),
                "team".into(),
                "uid1".into(),
                "evil:22".into()
            )
            .unwrap(),
            BindingResolution::Matched { .. }
        ));
        assert!(matches!(
            core.resolve_host_binding(
                "personal".into(),
                "team".into(),
                "uid1".into(),
                "prod-web:22".into()
            )
            .unwrap(),
            BindingResolution::Redirected { .. }
        ));
        assert_eq!(core.list_bindings("personal".into()).unwrap().len(), 1);
        // Удаление.
        core.delete_binding("personal".into(), "team".into(), "uid1".into())
            .unwrap();
        assert!(core
            .get_binding("personal".into(), "team".into(), "uid1".into())
            .unwrap()
            .is_none());
    }

    /// Username-шаблон: `%u` → username идентичности; шаблон входит в destination-пин
    /// (правка шаблона → смена назначения → анти-редирект). Гейтвей-агностично.
    #[test]
    fn username_template_render_destination_and_username() {
        let nj: &[JumpHost] = &[];
        // Без шаблона: обычные host:port и base username.
        assert_eq!(personal_destination("h", 22, None, nj), "h:22");
        assert_eq!(personal_destination("h", 22, Some(""), nj), "h:22");
        assert_eq!(apply_username_template("alice", None), "alice");
        // С шаблоном: он входит в назначение, а %u раскрывается в username.
        assert_eq!(
            personal_destination("gw", 22, Some("%u:prod-db"), nj),
            "gw:22#%u:prod-db"
        );
        assert_eq!(
            apply_username_template("alice", Some("%u:prod-db")),
            "alice:prod-db"
        );
        // Другой формат гейтвея — тоже работает (не только warpgate `:`).
        assert_eq!(
            apply_username_template("alice", Some("%u@edge")),
            "alice@edge"
        );
        // Разные шаблоны → разные назначения (правка ловится анти-редиректом).
        assert_ne!(
            personal_destination("gw", 22, Some("%u:prod-db"), nj),
            personal_destination("gw", 22, Some("%u:prod-web"), nj)
        );
        // trim по краям.
        assert_eq!(apply_username_template("alice", Some("  %u:x ")), "alice:x");

        // Анти-редирект по ЦЕПОЧКЕ ПРЫЖКОВ (#1): вставка прыжка меняет назначение
        // даже при том же host:port — иначе админ увёл бы личный кред через
        // MITM-хоп. Хост без прыжков даёт прежнюю строку (обратная совместимость).
        let jump = JumpHost {
            host: "attacker.com".into(),
            port: 22,
            user: "x".into(),
            auth: AuthMethod::Agent {
                vault_id: "v".into(),
                key_item_id: "k".into(),
            },
            hop_ref: None,
        };
        assert_eq!(personal_destination("h", 22, None, nj), "h:22");
        assert_ne!(
            personal_destination("h", 22, None, nj),
            personal_destination("h", 22, None, std::slice::from_ref(&jump)),
            "появление прыжка обязано менять пин (fail-safe анти-редирект)"
        );
        assert!(
            personal_destination("h", 22, None, std::slice::from_ref(&jump))
                .starts_with("h:22|via=")
        );
    }

    /// B4: username-цепочка. Первый непустой (trim) из
    /// identity → fallback профиля → account-default.
    #[test]
    fn pick_username_chain() {
        assert_eq!(pick_username("alice", "prof", Some("acct")), "alice");
        assert_eq!(pick_username("  ", "prof", Some("acct")), "prof");
        assert_eq!(pick_username("", "", Some("acct")), "acct");
        assert_eq!(pick_username("", "", None), "");
        assert_eq!(pick_username("", "", Some("  ")), "");
    }

    /// Co-location / multi-vault: идентичность+привязка могут лежать в ЛЮБОМ приватном
    /// волте, а НЕ в «личном» указателе (его тут вообще не ставим). resolve ищет по
    /// волтам аккаунта и находит — так разные хосты логинятся из разных волтов.
    #[test]
    fn resolve_personal_auth_finds_binding_in_any_private_vault() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        // Рабочий приватный волт — НЕ назначенный личным (set_personal_vault не зовём).
        let work = "aabbccddeeff00112233445566778899";
        core.create_vault(work.into(), "Work".into()).unwrap();
        core.save_identity(
            work.into(),
            Identity {
                identity_id: "work-id".into(),
                label: "Work".into(),
                user: "alice-work".into(),
                key_item_id: Some("workkey".into()),
                password_item_id: None,
            },
        )
        .unwrap();
        core.set_binding(
            work.into(),
            IdentityBinding {
                team_vault_id: "team".into(),
                profile_uid: "uidW".into(),
                identity_item_id: "work-id".into(),
                destination_pin: "corp:22".into(),
            },
            false,
        )
        .unwrap();
        let pa = core
            .resolve_personal_auth("team".into(), "uidW".into(), "corp:22".into(), "fb".into())
            .unwrap();
        assert_eq!(pa.user, "alice-work");
        match &pa.auth {
            AuthMethod::Agent {
                vault_id,
                key_item_id,
            } => {
                assert_eq!(
                    vault_id, work,
                    "creds from the Work vault, not a 'personal' one"
                );
                assert_eq!(key_item_id, "workkey");
            }
            _ => panic!("expected Agent auth"),
        }
    }

    /// B4: resolve_personal_auth разворачивает личный кред ТОЛЬКО для
    /// закреплённого назначения; при редиректе/без привязки — ошибка (кред не
    /// уходит на переклеенный хост).
    #[test]
    fn resolve_personal_auth_enforces_anti_redirect() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        // Личный волт — cloud-волт (hex-id); set_personal_vault ждёт hex.
        let pv = "00112233445566778899aabbccddeeff";
        core.create_vault(pv.into(), "Personal".into()).unwrap();
        core.set_personal_vault(pv.into()).unwrap();
        core.save_identity(
            pv.into(),
            Identity {
                identity_id: "ident1".into(),
                label: "L".into(),
                user: "alice".into(),
                key_item_id: Some("mykey".into()),
                password_item_id: None,
            },
        )
        .unwrap();
        core.set_binding(
            pv.into(),
            IdentityBinding {
                team_vault_id: "team".into(),
                profile_uid: "uid1".into(),
                identity_item_id: "ident1".into(),
                destination_pin: "prod-web:22".into(),
            },
            false,
        )
        .unwrap();
        // Назначение совпало → личный кред + username из идентичности.
        let pa = core
            .resolve_personal_auth(
                "team".into(),
                "uid1".into(),
                "prod-web:22".into(),
                "fallbackuser".into(),
            )
            .unwrap();
        assert_eq!(pa.user, "alice");
        if let AuthMethod::Agent {
            vault_id,
            key_item_id,
        } = &pa.auth
        {
            assert_eq!(vault_id.as_str(), pv);
            assert_eq!(key_item_id.as_str(), "mykey");
        } else {
            panic!("expected Agent auth from personal vault");
        }
        // Хост переклеен → ОШИБКА (кред не разворачивается для чужого хоста).
        assert!(core
            .resolve_personal_auth(
                "team".into(),
                "uid1".into(),
                "evil:22".into(),
                "fallbackuser".into(),
            )
            .is_err());
        // Нет привязки для этого uid → ошибка «нужно связать».
        assert!(core
            .resolve_personal_auth(
                "team".into(),
                "uid-unbound".into(),
                "prod-web:22".into(),
                "fallbackuser".into(),
            )
            .is_err());
    }

    /// B4.3-fix: Personal-хост НЕ уходит в fan-out с пустым паролем — исключается
    /// из tag- и group-путей (иначе был бы live-коннект без привязки/анти-редиректа).
    #[test]
    fn personal_host_excluded_from_fanout() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "V".into()).unwrap();
        let mk = |id: &str, host: &str, auth: ProfileAuth| ConnectionProfile {
            profile_id: id.into(),
            uid: String::new(),
            label: id.into(),
            host: host.into(),
            port: 22,
            user: "u".into(),
            auth,
            username_template: None,
            jumps: vec![],
            tags: vec!["prod".into()],
        };
        core.save_connection("v".into(), mk("personal-host", "gw", ProfileAuth::Personal))
            .unwrap();
        core.save_connection(
            "v".into(),
            mk(
                "key-host",
                "web",
                ProfileAuth::Key {
                    key_item_id: "k".into(),
                },
            ),
        )
        .unwrap();
        // Tag fan-out: Personal исключён → только key-host в целях.
        let targets = core
            .select_targets_by_tags("v".into(), vec!["prod".into()], false)
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "web");
        // Group fan-out: dry-run помечает Personal-члена статусом Personal (исключён).
        core.save_group(
            "v".into(),
            ServerGroup {
                group_id: "g".into(),
                label: "G".into(),
                member_ids: vec!["personal-host".into(), "key-host".into()],
                parent_id: None,
            },
        )
        .unwrap();
        let plans = core.dry_run_group("v".into(), "g".into()).unwrap();
        let personal = plans
            .iter()
            .find(|p| p.member_id == "personal-host")
            .unwrap();
        assert_eq!(personal.status, ResolveStatus::Personal);
        let keyh = plans.iter().find(|p| p.member_id == "key-host").unwrap();
        assert_eq!(keyh.status, ResolveStatus::Ok);
    }

    /// B6: BOUND Personal-хост попадает в fan-out с РАЗРЕШЁННЫМИ user+auth
    /// (личная идентичность из привязки), непривязанный — исключается.
    #[test]
    fn personal_host_bound_included_in_fanout() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(
            dir.path().join("i.db").to_string_lossy().to_string(),
            dir.path().join("i.keyset").to_string_lossy().to_string(),
        );
        core.create_account(None).unwrap();
        core.create_vault("v".into(), "Team".into()).unwrap();
        let pv = "00112233445566778899aabbccddeeff";
        core.create_vault(pv.into(), "Personal".into()).unwrap();
        core.set_personal_vault(pv.into()).unwrap();
        core.save_identity(
            pv.into(),
            Identity {
                identity_id: "ident1".into(),
                label: "L".into(),
                user: "alice".into(),
                key_item_id: Some("k".into()),
                password_item_id: None,
            },
        )
        .unwrap();
        let mk = |id: &str, host: &str, auth: ProfileAuth| ConnectionProfile {
            profile_id: id.into(),
            uid: String::new(),
            label: id.into(),
            host: host.into(),
            port: 22,
            user: "u".into(),
            auth,
            username_template: None,
            jumps: vec![],
            tags: vec!["prod".into()],
        };
        core.save_connection("v".into(), mk("personal-host", "gw", ProfileAuth::Personal))
            .unwrap();
        core.save_connection(
            "v".into(),
            mk(
                "key-host",
                "web",
                ProfileAuth::Key {
                    key_item_id: "kk".into(),
                },
            ),
        )
        .unwrap();
        // Привязываем личную идентичность к Personal-хосту (пин = его назначение).
        let ph = core
            .get_connection("v".into(), "personal-host".into())
            .unwrap();
        let dest = core.personal_destination(
            ph.host.clone(),
            ph.port,
            ph.username_template.clone(),
            ph.jumps.clone(),
        );
        core.set_binding(
            pv.into(),
            IdentityBinding {
                team_vault_id: "v".into(),
                profile_uid: ph.uid.clone(),
                identity_item_id: "ident1".into(),
                destination_pin: dest,
            },
            false,
        )
        .unwrap();
        // Tag fan-out: привязанный Personal-хост включён с разрешёнными user+auth.
        let targets = core
            .select_targets_by_tags("v".into(), vec!["prod".into()], false)
            .unwrap();
        assert_eq!(targets.len(), 2);
        let pt = targets.iter().find(|t| t.host == "gw").unwrap();
        assert_eq!(pt.user, "alice");
        assert!(matches!(
            &pt.auth,
            AuthMethod::Agent { vault_id, key_item_id }
                if vault_id.as_str() == pv && key_item_id == "k"
        ));
        // Group fan-out: dry-run помечает привязанный Personal-хост как Ok.
        core.save_group(
            "v".into(),
            ServerGroup {
                group_id: "g".into(),
                label: "G".into(),
                member_ids: vec!["personal-host".into(), "key-host".into()],
                parent_id: None,
            },
        )
        .unwrap();
        let plans = core.dry_run_group("v".into(), "g".into()).unwrap();
        assert_eq!(
            plans
                .iter()
                .find(|p| p.member_id == "personal-host")
                .unwrap()
                .status,
            ResolveStatus::Ok
        );
    }

    #[test]
    fn retry_backoff_is_linear() {
        assert_eq!(retry_backoff_ms(0, 100), 100);
        assert_eq!(retry_backoff_ms(1, 100), 200);
        assert_eq!(retry_backoff_ms(2, 50), 150);
        assert_eq!(retry_backoff_ms(0, 0), 0);
    }

    #[test]
    fn tags_default_to_empty_for_legacy_profile() {
        // Профиль без поля tags (легаси) читается, tags пустые.
        let legacy = r#"{"label":"L","host":"h","port":22,"user":"u",
                         "key_item_id":"k","jumps":[]}"#;
        let stored: StoredProfile = serde_json::from_str(legacy).unwrap();
        let prof = stored_to_profile("v", "p".to_string(), stored);
        assert!(prof.tags.is_empty());
    }

    #[test]
    fn tag_matching_any_and_all() {
        let host = ["prod".to_string(), "web".to_string(), "eu".to_string()];
        // any: пересечение непусто
        assert!(tags_match(&host, &["prod".to_string()], false));
        assert!(tags_match(
            &host,
            &["x".to_string(), "web".to_string()],
            false
        ));
        assert!(!tags_match(&host, &["x".to_string()], false));
        // all: запрос ⊆ тегов хоста
        assert!(tags_match(
            &host,
            &["prod".to_string(), "web".to_string()],
            true
        ));
        assert!(!tags_match(
            &host,
            &["prod".to_string(), "db".to_string()],
            true
        ));
        // пустой запрос → не выбираем ничего (защита от «exec на всё»)
        assert!(!tags_match(&host, &[], false));
        assert!(!tags_match(&host, &[], true));
    }

    /// Чистый flatten вложенных групп: дедупликация, защита от циклов, лимит
    /// глубины. Граф задаётся map'ами без БД.
    #[test]
    fn flatten_group_members_respects_depth_limit() {
        use std::collections::{HashMap, HashSet};
        // Цепочка g0->g1->...->g40, у каждой следующая группа + терминальный профиль.
        let profiles: HashSet<String> = ["p_end".to_string()].into_iter().collect();
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for i in 0..40 {
            groups.insert(format!("g{i}"), vec![format!("g{}", i + 1)]);
        }
        groups.insert("g40".to_string(), vec!["p_end".to_string()]);
        // не должно переполнить стек; глубже лимита — CycleSkipped, не паника.
        let (members, issues) = flatten_group_members(&groups, &profiles, "g0", GROUP_MAX_DEPTH);
        assert!(issues
            .iter()
            .any(|(_, st)| *st == ResolveStatus::CycleSkipped));
        // профиль за пределами лимита глубины не раскрыт
        assert!(members.is_empty());
    }

    #[test]
    fn flatten_group_members_dedup_cycle_depth() {
        use std::collections::HashMap;
        let profiles: std::collections::HashSet<String> =
            ["p1", "p2", "p3"].iter().map(|s| s.to_string()).collect();
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        // A → [p1, B, p2]; B → [p2, p3, A(цикл)]
        groups.insert("A".to_string(), vec!["p1".into(), "B".into(), "p2".into()]);
        groups.insert("B".to_string(), vec!["p2".into(), "p3".into(), "A".into()]);

        let (members, issues) = flatten_group_members(&groups, &profiles, "A", GROUP_MAX_DEPTH);
        // профили раскрыты по одному разу, в порядке обхода
        assert_eq!(members, vec!["p1", "p2", "p3"]);
        // цикл A→B→A отмечен, но не зациклил
        assert!(issues
            .iter()
            .any(|(_, s)| *s == ResolveStatus::CycleSkipped));

        // висячий член и член-не-группа-не-профиль
        let mut g2: HashMap<String, Vec<String>> = HashMap::new();
        g2.insert("G".to_string(), vec!["p1".into(), "ghost".into()]);
        let (m2, iss2) = flatten_group_members(&g2, &profiles, "G", GROUP_MAX_DEPTH);
        assert_eq!(m2, vec!["p1"]);
        assert!(iss2
            .iter()
            .any(|(id, s)| id == "ghost" && *s == ResolveStatus::Dangling));
    }
}
