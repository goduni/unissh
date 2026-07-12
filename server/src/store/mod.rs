//! Repository layer (sqlx). Dual-dialect: SQLite (self-host default, WAL) and
//! Postgres (scale). A single `Store` facade with `enum Db`; every method is
//! tenant-scoped (spec §12). Opaque blobs — verbatim; open columns mirror the
//! core's record contract.
//!
//! Decision: we use the **runtime** query API of sqlx (`sqlx::query(...).bind(...)`),
//! not the compile-time macros — they are incompatible with dual-dialect + DB-free
//! builds (see README). Coverage — integration tests on both dialects.

use crate::config::DbConfig;
use crate::error::{AppError, AppResult};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
};
use sqlx::{FromRow, Postgres, Sqlite};
use std::str::FromStr;

pub mod accounts_repo;
pub mod admin_repo;
pub mod audit_repo;
pub mod auth_repo;
pub mod enroll_repo;
pub mod identity_repo;
pub mod instance_repo;
pub mod models;
pub mod policy_repo;
pub mod sync_repo;
pub mod tenants;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
}

/// Bind parameter, dialect-agnostic. Lets orchestration logic (push-seq,
/// idempotency, invite-CAS, grants/publish) be written **once**, reducing the
/// dialect-specifics to tiny arms in `exec`/`fetch`.
#[derive(Debug, Clone)]
pub enum Val {
    I(i64),
    B(Vec<u8>),
    T(String),
    OptI(Option<i64>),
    OptB(Option<Vec<u8>>),
    OptT(Option<String>),
}

impl Val {
    pub fn b(v: impl Into<Vec<u8>>) -> Val {
        Val::B(v.into())
    }
    pub fn t(v: impl Into<String>) -> Val {
        Val::T(v.into())
    }
}

/// Converts `?` placeholders into `$1,$2,...` for Postgres. The SQL contains no
/// literal `?` (guaranteed by the code — every `?` is a placeholder).
pub(crate) fn to_pg(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0u32;
    for c in sql.chars() {
        if c == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(c);
        }
    }
    out
}

/// Bind a `Vec<Val>` to `query`/`query_as` (both have `.bind()` → Self).
macro_rules! bind_all {
    ($q:expr, $vals:expr) => {{
        let mut q = $q;
        for v in $vals {
            q = match v {
                Val::I(x) => q.bind(x),
                Val::B(x) => q.bind(x),
                Val::T(x) => q.bind(x),
                Val::OptI(x) => q.bind(x),
                Val::OptB(x) => q.bind(x),
                Val::OptT(x) => q.bind(x),
            };
        }
        q
    }};
}

/// Connection pool for a specific dialect.
#[derive(Clone)]
pub enum Db {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

/// Store facade. Cheap to clone (the pool is an Arc inside).
#[derive(Clone)]
pub struct Store {
    pub db: Db,
}

impl Store {
    pub fn dialect(&self) -> Dialect {
        match &self.db {
            Db::Sqlite(_) => Dialect::Sqlite,
            Db::Postgres(_) => Dialect::Postgres,
        }
    }

    /// Open a pool from the config.
    pub async fn connect(cfg: &DbConfig) -> AppResult<Self> {
        if cfg.backend.eq_ignore_ascii_case("sqlite") {
            Self::connect_sqlite(&cfg.url, cfg.max_connections).await
        } else if cfg.backend.eq_ignore_ascii_case("postgres") {
            Self::connect_postgres(&cfg.url, cfg.max_connections).await
        } else {
            Err(AppError::internal(format!(
                "unknown db backend: {}",
                cfg.backend
            )))
        }
    }

    pub async fn connect_sqlite(url: &str, max_conns: u32) -> AppResult<Self> {
        let in_memory = url == ":memory:" || url.contains(":memory:");
        let mut opts = if in_memory {
            SqliteConnectOptions::from_str("sqlite::memory:")
                .map_err(|e| AppError::internal(format!("sqlite opts: {e}")))?
        } else {
            SqliteConnectOptions::new()
                .filename(url)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(std::time::Duration::from_secs(10))
        };
        opts = opts.foreign_keys(true);
        // In-memory sqlite — per-connection; to let the pool see one dataset, we keep 1 connection.
        let max = if in_memory { 1 } else { max_conns.max(1) };
        let pool = SqlitePoolOptions::new()
            .max_connections(max)
            .connect_with(opts)
            .await
            .map_err(|e| AppError::internal(format!("sqlite connect: {e}")))?;
        Ok(Self {
            db: Db::Sqlite(pool),
        })
    }

    pub async fn connect_postgres(url: &str, max_conns: u32) -> AppResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_conns.max(1))
            .connect(url)
            .await
            .map_err(|e| AppError::internal(format!("postgres connect: {e}")))?;
        Ok(Self {
            db: Db::Postgres(pool),
        })
    }

    /// Apply the dialect's migrations (idempotent, forward-only) from the default dir.
    pub async fn migrate(&self) -> AppResult<()> {
        let dir = match self.dialect() {
            Dialect::Sqlite => "./migrations/sqlite",
            Dialect::Postgres => "./migrations/postgres",
        };
        self.migrate_from(dir).await
    }

    /// Apply migrations from an explicit directory (used by the v2 staging tests).
    pub async fn migrate_from(&self, dir: &str) -> AppResult<()> {
        use sqlx::migrate::Migrator;
        let m = Migrator::new(std::path::Path::new(dir))
            .await
            .map_err(|e| AppError::internal(format!("load migrations {dir}: {e}")))?;
        match &self.db {
            Db::Sqlite(p) => m
                .run(p)
                .await
                .map_err(|e| AppError::internal(format!("sqlite migrate: {e}")))?,
            Db::Postgres(p) => m
                .run(p)
                .await
                .map_err(|e| AppError::internal(format!("postgres migrate: {e}")))?,
        }
        Ok(())
    }

    /// Connection pool stats `(size, idle)` for `/v1/admin/health`. `size` is the
    /// currently open connections, `idle` is the idle ones among them; `in_use = size -
    /// idle`. The ceiling (`max`) is taken from the config by the caller.
    pub fn pool_stats(&self) -> (u32, usize) {
        match &self.db {
            Db::Sqlite(p) => (p.size(), p.num_idle()),
            Db::Postgres(p) => (p.size(), p.num_idle()),
        }
    }

    /// DB availability check (for /readyz).
    pub async fn ping(&self) -> AppResult<()> {
        match &self.db {
            Db::Sqlite(p) => {
                sqlx::query("SELECT 1").execute(p).await?;
            }
            Db::Postgres(p) => {
                sqlx::query("SELECT 1").execute(p).await?;
            }
        }
        Ok(())
    }

    // ---- Dialect-agnostic primitives (auto-commit) ----

    /// Execute a mutation; return the number of affected rows.
    pub async fn exec(&self, sql: &str, vals: Vec<Val>) -> AppResult<u64> {
        Ok(match &self.db {
            Db::Sqlite(p) => bind_all!(sqlx::query(sqlx::AssertSqlSafe(sql)), vals)
                .execute(p)
                .await?
                .rows_affected(),
            Db::Postgres(p) => {
                let pg = to_pg(sql);
                bind_all!(sqlx::query(sqlx::AssertSqlSafe(pg)), vals)
                    .execute(p)
                    .await?
                    .rows_affected()
            }
        })
    }

    /// Fetch 0..1 row into `T: FromRow`.
    pub async fn fetch_optional_as<T>(&self, sql: &str, vals: Vec<Val>) -> AppResult<Option<T>>
    where
        T: for<'r> FromRow<'r, SqliteRow> + for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        Ok(match &self.db {
            Db::Sqlite(p) => {
                bind_all!(sqlx::query_as::<Sqlite, T>(sqlx::AssertSqlSafe(sql)), vals)
                    .fetch_optional(p)
                    .await?
            }
            Db::Postgres(p) => {
                let pg = to_pg(sql);
                bind_all!(sqlx::query_as::<Postgres, T>(sqlx::AssertSqlSafe(pg)), vals)
                    .fetch_optional(p)
                    .await?
            }
        })
    }

    /// Fetch all rows into `T: FromRow`.
    pub async fn fetch_all_as<T>(&self, sql: &str, vals: Vec<Val>) -> AppResult<Vec<T>>
    where
        T: for<'r> FromRow<'r, SqliteRow> + for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        Ok(match &self.db {
            Db::Sqlite(p) => {
                bind_all!(sqlx::query_as::<Sqlite, T>(sqlx::AssertSqlSafe(sql)), vals)
                    .fetch_all(p)
                    .await?
            }
            Db::Postgres(p) => {
                let pg = to_pg(sql);
                bind_all!(sqlx::query_as::<Postgres, T>(sqlx::AssertSqlSafe(pg)), vals)
                    .fetch_all(p)
                    .await?
            }
        })
    }

    /// i64 scalar (e.g. `COUNT(*)`), 0..1 row.
    pub async fn fetch_scalar_i64(&self, sql: &str, vals: Vec<Val>) -> AppResult<Option<i64>> {
        Ok(match &self.db {
            Db::Sqlite(p) => {
                bind_all!(
                    sqlx::query_scalar::<Sqlite, i64>(sqlx::AssertSqlSafe(sql)),
                    vals
                )
                .fetch_optional(p)
                .await?
            }
            Db::Postgres(p) => {
                let pg = to_pg(sql);
                bind_all!(
                    sqlx::query_scalar::<Postgres, i64>(sqlx::AssertSqlSafe(pg)),
                    vals
                )
                .fetch_optional(p)
                .await?
            }
        })
    }

    /// Begin a transaction (dialect-agnostic wrapper).
    pub async fn begin(&self) -> AppResult<Tx<'_>> {
        Ok(match &self.db {
            Db::Sqlite(p) => Tx::Sqlite(p.begin().await?),
            Db::Postgres(p) => Tx::Postgres(p.begin().await?),
        })
    }
}

/// Transaction, dialect-agnostic. The same primitives as `Store`, but within a
/// single DB transaction (atomicity of push/register/grants-publish).
pub enum Tx<'c> {
    Sqlite(sqlx::Transaction<'c, Sqlite>),
    Postgres(sqlx::Transaction<'c, Postgres>),
}

impl Tx<'_> {
    pub fn dialect(&self) -> Dialect {
        match self {
            Tx::Sqlite(_) => Dialect::Sqlite,
            Tx::Postgres(_) => Dialect::Postgres,
        }
    }

    pub async fn exec(&mut self, sql: &str, vals: Vec<Val>) -> AppResult<u64> {
        Ok(match self {
            Tx::Sqlite(t) => bind_all!(sqlx::query(sqlx::AssertSqlSafe(sql)), vals)
                .execute(&mut **t)
                .await?
                .rows_affected(),
            Tx::Postgres(t) => {
                let pg = to_pg(sql);
                bind_all!(sqlx::query(sqlx::AssertSqlSafe(pg)), vals)
                    .execute(&mut **t)
                    .await?
                    .rows_affected()
            }
        })
    }

    pub async fn fetch_optional_as<T>(&mut self, sql: &str, vals: Vec<Val>) -> AppResult<Option<T>>
    where
        T: for<'r> FromRow<'r, SqliteRow> + for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        Ok(match self {
            Tx::Sqlite(t) => {
                bind_all!(sqlx::query_as::<Sqlite, T>(sqlx::AssertSqlSafe(sql)), vals)
                    .fetch_optional(&mut **t)
                    .await?
            }
            Tx::Postgres(t) => {
                let pg = to_pg(sql);
                bind_all!(sqlx::query_as::<Postgres, T>(sqlx::AssertSqlSafe(pg)), vals)
                    .fetch_optional(&mut **t)
                    .await?
            }
        })
    }

    pub async fn fetch_all_as<T>(&mut self, sql: &str, vals: Vec<Val>) -> AppResult<Vec<T>>
    where
        T: for<'r> FromRow<'r, SqliteRow> + for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        Ok(match self {
            Tx::Sqlite(t) => {
                bind_all!(sqlx::query_as::<Sqlite, T>(sqlx::AssertSqlSafe(sql)), vals)
                    .fetch_all(&mut **t)
                    .await?
            }
            Tx::Postgres(t) => {
                let pg = to_pg(sql);
                bind_all!(sqlx::query_as::<Postgres, T>(sqlx::AssertSqlSafe(pg)), vals)
                    .fetch_all(&mut **t)
                    .await?
            }
        })
    }

    pub async fn fetch_scalar_i64(&mut self, sql: &str, vals: Vec<Val>) -> AppResult<Option<i64>> {
        Ok(match self {
            Tx::Sqlite(t) => {
                bind_all!(
                    sqlx::query_scalar::<Sqlite, i64>(sqlx::AssertSqlSafe(sql)),
                    vals
                )
                .fetch_optional(&mut **t)
                .await?
            }
            Tx::Postgres(t) => {
                let pg = to_pg(sql);
                bind_all!(
                    sqlx::query_scalar::<Postgres, i64>(sqlx::AssertSqlSafe(pg)),
                    vals
                )
                .fetch_optional(&mut **t)
                .await?
            }
        })
    }

    pub async fn commit(self) -> AppResult<()> {
        match self {
            Tx::Sqlite(t) => t.commit().await?,
            Tx::Postgres(t) => t.commit().await?,
        }
        Ok(())
    }

    pub async fn rollback(self) -> AppResult<()> {
        match self {
            Tx::Sqlite(t) => t.rollback().await?,
            Tx::Postgres(t) => t.rollback().await?,
        }
        Ok(())
    }
}
