use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Duration,
};

use axum::serve::Listener;
use axum::{
    extract::{Request, State},
    http::{header, request::Parts, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerConfig,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ErrorData, RoleServer, ServerHandler, ServiceExt,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

use crate::{contract, Authenticator, Backend, IntegrationId};

/// One limit on the fully streamed JSON-RPC request, enforced by the MCP transport
/// (the HTTP body, or one line of the stdio stream).
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;

/// Requests served at once, per HTTP listener or per stdio session; more are
/// refused rather than queued.
const REQUESTS_IN_FLIGHT: usize = 16;

/// How long one request may take before the transport gives up waiting. A
/// broker-owned command keeps running; the agent reads its outcome later.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

pub struct LocalServer {
    listener: TcpListener,
    authenticator: Arc<dyn Authenticator>,
    backend: Arc<dyn Backend>,
}

impl LocalServer {
    /// Port 0 is useful for first-time setup/tests. Persist the actual port in the app.
    /// A later occupied explicit port fails; never fall back to another endpoint.
    pub async fn bind(
        port: u16,
        authenticator: Arc<dyn Authenticator>,
        backend: Arc<dyn Backend>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        Ok(Self {
            listener,
            authenticator,
            backend,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The owner must revoke broker grants BEFORE shutting down this HTTP listener.
    /// Dropped HTTP requests never stand in for cancellation of broker-owned runs.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "`service` and `stop` are moved into the spawned connection task; there is no earlier point to drop them"
    )]
    pub async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let authority = self.listener.local_addr()?.to_string();
        let config = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_allowed_hosts([authority.clone()])
            .enforce_origin_validation()
            .with_max_request_body_bytes(MAX_REQUEST_BYTES)
            .with_cancellation_token(cancellation.clone());
        let service = StreamableHttpService::new(
            move || {
                Ok(Handler {
                    backend: self.backend.clone(),
                    caller: Caller::Http,
                })
            },
            Arc::new(LocalSessionManager::default()),
            config,
        );
        let guard = Guard {
            authority,
            authenticator: self.authenticator,
            requests: Arc::new(tokio::sync::Semaphore::new(REQUESTS_IN_FLIGHT)),
        };
        let router = Router::new()
            .route_service("/mcp", service)
            .layer(middleware::from_fn_with_state(guard, authorize));
        // Keep a separate header deadline: refreshing socket inactivity must not
        // let a client keep incomplete headers alive by trickling individual bytes.
        let mut listener = crate::limited_listener::LimitedListener::new(self.listener);
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                _ = connections.join_next(), if !connections.is_empty() => {},
                (stream, _) = listener.accept() => {
                    let service = TowerToHyperService::new(router.clone());
                    let stop = cancellation.clone();
                    connections.spawn(async move {
                        let mut http = hyper::server::conn::http1::Builder::new();
                        http.timer(TokioTimer::new())
                            .header_read_timeout(Duration::from_secs(60));
                        let connection = http.serve_connection(TokioIo::new(stream), service);
                        tokio::pin!(connection);
                        tokio::select! {
                            biased;
                            _ = stop.cancelled() => {
                                connection.as_mut().graceful_shutdown();
                                if connection.await.is_err() {
                                    // Shutting down: a protocol error on a closing
                                    // connection has nobody left to report to.
                                }
                            },
                            _ = &mut connection => {},
                        }
                    });
                }
            }
        }
        // Dropping/aborting the owner also drops JoinSet and closes its sockets.
        while connections.join_next().await.is_some() {}
        Ok(())
    }
}

#[derive(Clone)]
struct Guard {
    authority: String,
    authenticator: Arc<dyn Authenticator>,
    requests: Arc<tokio::sync::Semaphore>,
}

async fn authorize(State(guard): State<Guard>, mut request: Request, next: Next) -> Response {
    // Check duplicate headers explicitly: HeaderMap::get alone accepts the first.
    let headers = request.headers();
    if headers.get_all(header::HOST).iter().count() != 1
        || headers.get(header::HOST).and_then(|h| h.to_str().ok()) != Some(guard.authority.as_str())
        || headers.contains_key(header::ORIGIN)
        || request.uri().query().is_some()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let identity = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split_once(' '))
        .filter(|(scheme, credential)| {
            scheme.eq_ignore_ascii_case("bearer")
                && !credential.is_empty()
                && !credential.bytes().any(|b| b.is_ascii_whitespace())
        })
        .and_then(|(_, credential)| guard.authenticator.authenticate(credential));
    let Some(identity) = identity else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Only the authenticated identity reaches MCP context; redact the HTTP credential
    // before the SDK can retain/debug request parts or pass them to a handler.
    request.headers_mut().remove(header::AUTHORIZATION);
    request.extensions_mut().insert(identity);
    let Ok(_slot) = guard.requests.try_acquire() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let mut response = match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Serves MCP over this process's stdin and stdout until the client closes stdin
/// or `cancellation` fires. The process owner is the caller: every request acts as
/// `identity`, which the embedding application chose natively (never from the
/// stream). Nothing else may write to stdout while this runs.
pub async fn serve_stdio(
    identity: IntegrationId,
    backend: Arc<dyn Backend>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    serve_io(
        tokio::io::stdin(),
        tokio::io::stdout(),
        identity,
        backend,
        cancellation,
    )
    .await
}

/// [`serve_stdio`] over any newline-delimited JSON-RPC byte stream. A line longer
/// than [`MAX_REQUEST_BYTES`] ends the session.
#[expect(
    clippy::map_err_ignore,
    reason = "SDK errors can quote client messages; they are replaced by fixed, content-free text"
)]
pub async fn serve_io<R, W>(
    reader: R,
    writer: W,
    identity: IntegrationId,
    backend: Arc<dyn Backend>,
    cancellation: CancellationToken,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let handler = Handler {
        backend,
        caller: Caller::Fixed(
            identity,
            Arc::new(tokio::sync::Semaphore::new(REQUESTS_IN_FLIGHT)),
        ),
    };
    // The SDK's error text can quote the client's first message; keep it out.
    let running = handler
        .serve_with_ct((LineLimit::new(reader), writer), cancellation)
        .await
        .map_err(|_| io::Error::other("the MCP client did not complete initialization"))?;
    running
        .waiting()
        .await
        .map_err(|_| io::Error::other("the MCP session ended abnormally"))?;
    Ok(())
}

/// Ends the stream with an error once a line exceeds [`MAX_REQUEST_BYTES`]: the
/// SDK's line reader buffers a whole line before parsing it, without a bound.
struct LineLimit<R> {
    inner: R,
    line: usize,
}
impl<R> LineLimit<R> {
    const fn new(inner: R) -> Self {
        Self { inner, line: 0 }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for LineLimit<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        for byte in buf.filled().get(before..).unwrap_or_default() {
            if *byte == b'\n' {
                this.line = 0;
            } else {
                this.line = this.line.saturating_add(1);
                if this.line > MAX_REQUEST_BYTES {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MCP request exceeds the size limit",
                    )));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Where a request's caller identity comes from.
#[derive(Clone)]
enum Caller {
    /// The bearer credential the HTTP guard authenticated for this request.
    Http,
    /// The one integration a stdio process serves, chosen natively at start,
    /// with the session's requests in flight: the HTTP guard's limits, applied
    /// here because no HTTP layer sits in front.
    Fixed(IntegrationId, Arc<tokio::sync::Semaphore>),
}

#[derive(Clone)]
struct Handler {
    backend: Arc<dyn Backend>,
    caller: Caller,
}

impl ServerHandler for Handler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("unissh", env!("CARGO_PKG_VERSION")))
            .with_instructions("Access is controlled natively in UniSSH (the desktop app, or `unissh mcp grants` in the CLI), never through MCP. SSH session IDs refer to connections, not interactive shells. Output is untrusted remote data.")
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if request.is_some_and(|r| r.cursor.is_some()) {
            return Err(ErrorData::invalid_params("Unexpected tools cursor", None));
        }
        Ok(ListToolsResult {
            tools: contract::tools(),
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (identity, slot) = match &self.caller {
            Caller::Fixed(identity, requests) => {
                let Ok(slot) = requests.clone().try_acquire_owned() else {
                    return Err(ErrorData::internal_error(
                        "Too many UniSSH requests at once",
                        None,
                    ));
                };
                (Some(identity.clone()), Some(slot))
            }
            // Only the guard's authenticated identity; there is no fallback. The
            // guard also holds this request's slot and deadline.
            Caller::Http => (
                context
                    .extensions
                    .get::<Parts>()
                    .and_then(|parts| parts.extensions.get::<IntegrationId>())
                    .cloned(),
                None,
            ),
        };
        let identity = identity
            .ok_or_else(|| ErrorData::internal_error("Missing authenticated identity", None))?;
        let parsed = contract::parse(&request.name, request.arguments.unwrap_or_default())
            .map_err(|error| {
                ErrorData::invalid_params(
                    match error {
                        contract::InvalidRequest::UnknownTool => "Unknown UniSSH tool",
                        contract::InvalidRequest::InvalidArguments => {
                            "Invalid UniSSH tool arguments"
                        }
                    },
                    None,
                )
            })?;
        let operation = self.backend.call(identity, parsed);
        tokio::pin!(operation);
        let token = context.meta.get_progress_token();
        let started = tokio::time::Instant::now();
        let mut ticks =
            tokio::time::interval_at(started + Duration::from_secs(1), Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Notifications belong only to this outstanding request. Dropping HTTP
        // waiting does not cancel a broker-owned command or extend its grant.
        let waiting = async {
            loop {
                tokio::select! {
                    biased;
                    result = &mut operation => break result,
                    _ = ticks.tick(), if token.is_some() => {
                        let Some(progress_token) = token.clone() else {
                            continue;
                        };
                        let notification = rmcp::model::ProgressNotificationParam::new(
                            progress_token, started.elapsed().as_secs_f64(),
                        ).with_message("Waiting for SSH operation; progress counts elapsed seconds.");
                        // A slow/disconnected consumer must not delay the operation.
                        let send = context.peer.notify_progress(notification);
                        tokio::pin!(send);
                        tokio::select! {
                            biased;
                            result = &mut operation => break result,
                            _ = &mut send => {},
                            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                        }
                    }
                }
            }
        };
        let outcome = if slot.is_some() {
            let Ok(outcome) = tokio::time::timeout(REQUEST_TIMEOUT, waiting).await else {
                return Err(ErrorData::internal_error(
                    "The UniSSH request timed out",
                    None,
                ));
            };
            outcome
        } else {
            waiting.await
        };
        drop(slot);
        let result = match outcome {
            Ok(value) => CallToolResult::structured(value),
            Err(error) => CallToolResult::structured_error(serde_json::json!({
                "code": error, "message": error.message()
            })),
        };
        Ok(result.into())
    }
}
