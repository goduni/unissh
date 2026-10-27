//! Port forwarding: `-L`, `-R` and `-D` through a host, as with `ssh -N`,
//! until Ctrl-C.
//!
//! Each forward is the core's (`Core::open_local_forward` and its siblings),
//! one connection per forward, as in the app. The address rules are the
//! core's too: a SOCKS forward listens only on loopback, and nothing here
//! widens what the core allows. A forward that names no address listens on
//! `127.0.0.1`.

use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;

use unissh_ffi::{Core, SshTunnel};

use crate::connect::{connecting, with_password};
use crate::failure::{Failure, Res, EXIT_BROKEN_PIPE};
use crate::hosts::Target;
use crate::signals;
use crate::tty::one_line;

/// Where a forward listens when the spec names no address.
const LOOPBACK: &str = "127.0.0.1";

/// One forward, as `-L`, `-R` or `-D` gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forward {
    /// `-L`: listen here on `bind:port`, connect to `to_host:to_port` from the host.
    Local {
        /// Address to listen on, here.
        bind: String,
        /// Port to listen on (0: any free one).
        port: u16,
        /// Where the host connects to.
        to_host: String,
        /// Its port.
        to_port: u16,
    },
    /// `-R`: the host listens on `bind:port`, connections come to `to_host:to_port` here.
    Remote {
        /// Address the host listens on.
        bind: String,
        /// Port it listens on (0: the host picks one).
        port: u16,
        /// Where this machine connects to.
        to_host: String,
        /// Its port.
        to_port: u16,
    },
    /// `-D`: a SOCKS5 proxy here on `bind:port`, connecting from the host.
    Dynamic {
        /// Address to listen on, here (loopback only; the core enforces it).
        bind: String,
        /// Port to listen on (0: any free one).
        port: u16,
    },
}

/// The forward as it would be typed, for messages about it.
impl fmt::Display for Forward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local {
                bind,
                port,
                to_host,
                to_port,
            } => write!(f, "-L {}:{}", shown(bind, *port), shown(to_host, *to_port)),
            Self::Remote {
                bind,
                port,
                to_host,
                to_port,
            } => write!(f, "-R {}:{}", shown(bind, *port), shown(to_host, *to_port)),
            Self::Dynamic { bind, port } => write!(f, "-D {}", shown(bind, *port)),
        }
    }
}

/// `host:port`, with an IPv6 address in brackets.
fn socket(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// [`socket`] for the terminal: a typed address shown without control
/// characters.
fn shown(host: &str, port: u16) -> String {
    socket(&one_line(host), port)
}

/// The `:`-separated fields of a spec; `[...]` keeps an IPv6 address whole
/// (and drops the brackets).
fn fields(spec: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut rest = spec;
    loop {
        let (field, after) = if let Some(inner) = rest.strip_prefix('[') {
            let (address, tail) = inner
                .split_once(']')
                .ok_or_else(|| "an address in [ ] is not closed".to_owned())?;
            match tail.strip_prefix(':') {
                Some(tail) => (address, Some(tail)),
                None if tail.is_empty() => (address, None),
                None => return Err(format!("expected `:` after [{address}]")),
            }
        } else {
            match rest.split_once(':') {
                Some((field, tail)) => (field, Some(tail)),
                None => (rest, None),
            }
        };
        out.push(field.to_owned());
        match after {
            Some(tail) => rest = tail,
            None => return Ok(out),
        }
    }
}

/// A port; 0 only where `any` allows "any free one".
fn port(text: &str, any: bool) -> Result<u16, String> {
    match text.parse::<u16>() {
        Ok(0) if !any => Err("port 0 cannot be connected to".to_owned()),
        Ok(port) => Ok(port),
        Err(_) => Err(format!("\"{}\" is not a port", one_line(text))),
    }
}

/// The address to listen on: loopback unless named. An empty address or `*`
/// ("every interface" to OpenSSH) has to be spelled out, so that exposing a
/// port to the network is never a typo.
fn bind(text: Option<&String>) -> Result<String, String> {
    match text.map(String::as_str) {
        None => Ok(LOOPBACK.to_owned()),
        Some("" | "*") => Err(
            "name the address to listen on (0.0.0.0 for every interface, where allowed)".to_owned(),
        ),
        Some(address) => Ok(address.to_owned()),
    }
}

fn host(text: &str) -> Result<String, String> {
    if text.is_empty() {
        Err("the host to connect to is empty".to_owned())
    } else {
        Ok(text.to_owned())
    }
}

/// `[bind:]port:host:hostport` → its parts.
fn four(spec: &str) -> Result<(String, u16, String, u16), String> {
    let all = fields(spec)?;
    let (address, listen, to_host, to_port) = match all.as_slice() {
        [listen, to_host, to_port] => (None, listen, to_host, to_port),
        [address, listen, to_host, to_port] => (Some(address), listen, to_host, to_port),
        _ => return Err("expected [BIND:]PORT:HOST:HOSTPORT".to_owned()),
    };
    Ok((
        bind(address)?,
        port(listen, true)?,
        host(to_host)?,
        port(to_port, false)?,
    ))
}

/// Parses a `-L` value: `[bind:]port:host:hostport`.
pub fn local(spec: &str) -> Result<Forward, String> {
    let (bind, port, to_host, to_port) = four(spec)?;
    Ok(Forward::Local {
        bind,
        port,
        to_host,
        to_port,
    })
}

/// Parses a `-R` value: `[bind:]port:host:hostport` (bind is on the host).
pub fn remote(spec: &str) -> Result<Forward, String> {
    let (bind, port, to_host, to_port) = four(spec)?;
    Ok(Forward::Remote {
        bind,
        port,
        to_host,
        to_port,
    })
}

/// Parses a `-D` value: `[bind:]port`.
pub fn dynamic(spec: &str) -> Result<Forward, String> {
    let all = fields(spec)?;
    let (address, listen) = match all.as_slice() {
        [listen] => (None, listen),
        [address, listen] => (Some(address), listen),
        _ => return Err("expected [BIND:]PORT".to_owned()),
    };
    Ok(Forward::Dynamic {
        bind: bind(address)?,
        port: port(listen, true)?,
    })
}

/// The line printed once `forward` listens on `bound` (the core's
/// `bind_address`: the real port, also when 0 was asked for). `label` is
/// already one line.
fn listening(forward: &Forward, bound: &str, label: &str) -> String {
    match forward {
        Forward::Local {
            to_host, to_port, ..
        } => format!(
            "{} -> {} (via {label})",
            one_line(bound),
            shown(to_host, *to_port)
        ),
        Forward::Remote {
            bind,
            to_host,
            to_port,
            ..
        } => {
            // The core gives `bind:port` without brackets; show it as typed.
            let on = bound
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .map_or_else(|| one_line(bound), |p| shown(bind, p));
            format!("{on} on {label} -> {}", shown(to_host, *to_port))
        }
        Forward::Dynamic { .. } => format!("{} SOCKS5 (via {label})", one_line(bound)),
    }
}

/// Opens one forward over its own connection.
fn open_one(core: &Core, t: &Target, forward: &Forward) -> Res<Arc<SshTunnel>> {
    let tunnel = match forward {
        Forward::Local {
            bind,
            port,
            to_host,
            to_port,
        } => core.open_local_forward(
            t.host.clone(),
            t.port,
            t.user.clone(),
            t.auth.clone(),
            t.jumps.clone(),
            t.proxy.clone(),
            socket(bind, *port),
            to_host.clone(),
            *to_port,
        )?,
        Forward::Remote {
            bind,
            port,
            to_host,
            to_port,
        } => core.open_remote_forward(
            t.host.clone(),
            t.port,
            t.user.clone(),
            t.auth.clone(),
            t.jumps.clone(),
            t.proxy.clone(),
            bind.clone(),
            *port,
            to_host.clone(),
            *to_port,
        )?,
        Forward::Dynamic { bind, port } => core.open_dynamic_forward(
            t.host.clone(),
            t.port,
            t.user.clone(),
            t.auth.clone(),
            t.jumps.clone(),
            t.proxy.clone(),
            socket(bind, *port),
        )?,
    };
    Ok(tunnel)
}

fn close_all(tunnels: &[Arc<SshTunnel>]) {
    for tunnel in tunnels {
        tunnel.close();
    }
}

/// How opening the forwards ended, short of a failure.
#[derive(Debug, PartialEq, Eq)]
enum Opened<T> {
    /// Every forward listens.
    All(Vec<T>),
    /// Stdout is a pipe nobody reads any more (`| head -n1` has the port it
    /// wanted); every forward was closed again.
    ReaderGone,
}

/// Opens the forwards in order with `open`, which gives each tunnel and the
/// address it listens on, and writes a line to `out` for each one as it
/// listens. A forward that fails to open, or a line that cannot be written,
/// closes with `close` the ones already open.
fn open_each<T>(
    forwards: &[Forward],
    label: &str,
    out: &mut impl Write,
    mut open: impl FnMut(&Forward) -> Res<(T, String)>,
    close: impl Fn(&[T]),
) -> Res<Opened<T>> {
    let mut opened = Vec::with_capacity(forwards.len());
    for forward in forwards {
        let (tunnel, bound) = match open(forward) {
            Ok(it) => it,
            Err(mut failure) => {
                close(&opened);
                failure.message = format!("{forward}: {}", failure.message);
                return Err(failure);
            }
        };
        opened.push(tunnel);
        let line = listening(forward, &bound, label);
        if let Err(e) = writeln!(out, "{line}").and_then(|()| out.flush()) {
            close(&opened);
            // Rust ignores SIGPIPE, so leaving when the reader has gone is
            // ours to do, with the status `ssh` would die with.
            return if e.kind() == io::ErrorKind::BrokenPipe {
                Ok(Opened::ReaderGone)
            } else {
                Err(Failure::msg(format!("cannot write to stdout: {e}")))
            };
        }
    }
    Ok(Opened::All(opened))
}

/// Opens every forward through `target` (the host labelled `label`), prints
/// a line for each as it listens, and keeps them until Ctrl-C or SIGTERM,
/// then closes them; returns the exit code. A forward that fails to open
/// fails the command with its reason, after closing the ones already open.
///
/// A hang-up is not caught: it ends the process as it would any other, and
/// under `nohup` the tunnels stay up.
pub fn run(core: &Core, mut target: Target, label: &str, forwards: &[Forward]) -> Res<u8> {
    let label = one_line(label);
    // A password asked at every connection is asked once for all of them.
    let opened = with_password(&mut target, |target| {
        open_each(
            forwards,
            &label,
            &mut io::stdout(),
            |forward| {
                let tunnel = connecting(core, target, || open_one(core, target, forward))?;
                let bound = tunnel.bind_address();
                Ok((tunnel, bound))
            },
            close_all,
        )
    })?;
    let Opened::All(open) = opened else {
        return Ok(EXIT_BROKEN_PIPE);
    };
    let waited = wait_for_stop();
    close_all(&open);
    waited
        .map(|()| 0)
        .map_err(|e| Failure::msg(format!("cannot wait for Ctrl-C: {e}")))
}

/// Blocks until Ctrl-C or SIGTERM (Ctrl-C elsewhere). From then on, another
/// one ends the process at once (status 130 after Ctrl-C), so that a close
/// that hangs on a dead connection never holds the terminal.
fn wait_for_stop() -> io::Result<()> {
    let mut stop = signals::Caught::install(signals::STOP)?;
    eprintln!("unissh: forwarding; Ctrl-C closes the tunnels");
    stop.wait();
    eprintln!("unissh: closing the tunnels (Ctrl-C again to quit at once)");
    stop.quit_on_next();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_fw(bind: &str, port: u16, to_host: &str, to_port: u16) -> Forward {
        Forward::Local {
            bind: bind.to_owned(),
            port,
            to_host: to_host.to_owned(),
            to_port,
        }
    }

    #[test]
    fn a_forward_listens_on_loopback_unless_an_address_is_named() {
        assert_eq!(
            local("8080:db:5432"),
            Ok(local_fw("127.0.0.1", 8080, "db", 5432))
        );
        assert_eq!(
            local("0.0.0.0:8080:db:5432"),
            Ok(local_fw("0.0.0.0", 8080, "db", 5432))
        );
        assert_eq!(
            dynamic("1080"),
            Ok(Forward::Dynamic {
                bind: "127.0.0.1".to_owned(),
                port: 1080
            })
        );
    }

    #[test]
    fn ipv6_addresses_in_brackets_stay_whole() {
        let forward = local("[::1]:8080:[fd00::5]:22");
        assert_eq!(forward, Ok(local_fw("::1", 8080, "fd00::5", 22)));
        assert_eq!(
            forward.map(|f| f.to_string()),
            Ok("-L [::1]:8080:[fd00::5]:22".to_owned())
        );
        assert!(local("[::1:8080:db:22").is_err(), "an unclosed bracket");
    }

    #[test]
    fn every_interface_has_to_be_spelled_out() {
        assert!(local(":8080:db:5432").is_err());
        assert!(remote("*:8080:localhost:3000").is_err());
    }

    #[test]
    fn only_the_listening_port_may_be_zero() {
        assert!(local("0:db:5432").is_ok(), "any free port here");
        assert!(remote("0:localhost:3000").is_ok(), "the host picks one");
        assert!(local("8080:db:0").is_err(), "nothing listens on port 0");
    }

    #[test]
    fn a_port_is_a_number_up_to_65535() {
        assert!(local("8080:db:http").is_err(), "a service name");
        assert!(dynamic("70000").is_err(), "out of range");
    }

    #[test]
    fn a_spec_with_the_wrong_number_of_fields_is_refused() {
        assert!(local("8080:db").is_err());
        assert!(remote("a:1:b:2:3").is_err());
        assert!(dynamic("127.0.0.1:1080:x").is_err());
    }

    #[test]
    fn each_forward_says_where_it_listens_and_where_it_goes() {
        let l = local_fw("127.0.0.1", 0, "db", 5432);
        assert_eq!(
            listening(&l, "127.0.0.1:40123", "web"),
            "127.0.0.1:40123 -> db:5432 (via web)"
        );
        let r = remote("[::1]:0:localhost:3000").unwrap();
        assert_eq!(
            listening(&r, "::1:9000", "web"),
            "[::1]:9000 on web -> localhost:3000"
        );
        let d = dynamic("1080").unwrap();
        assert_eq!(
            listening(&d, "127.0.0.1:1080", "web"),
            "127.0.0.1:1080 SOCKS5 (via web)"
        );
    }

    #[test]
    fn typed_addresses_reach_the_terminal_without_control_characters() {
        let l = local("local\u{1b}host:8080:d\u{7}b:5432").unwrap();
        assert_eq!(l.to_string(), "-L localhost:8080:db:5432");
        assert_eq!(
            listening(&l, "127.0.0.1:8080", "web"),
            "127.0.0.1:8080 -> db:5432 (via web)"
        );
    }

    /// A stdout whose reader has gone.
    struct Gone;

    impl Write for Gone {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    fn three() -> Vec<Forward> {
        vec![
            local("8080:db:5432").unwrap(),
            remote("9000:localhost:3000").unwrap(),
            dynamic("1080").unwrap(),
        ]
    }

    #[test]
    fn a_forward_that_fails_closes_the_ones_already_open() {
        let closed = std::cell::RefCell::new(Vec::new());
        let mut out = Vec::new();
        let mut next = 0;
        let result = open_each(
            &three(),
            "web",
            &mut out,
            |_| {
                next += 1;
                if next == 3 {
                    Err(Failure::msg("refused"))
                } else {
                    Ok((next, "127.0.0.1:1".to_owned()))
                }
            },
            |open: &[i32]| closed.borrow_mut().extend_from_slice(open),
        );
        let Err(failure) = result else {
            panic!("the third forward failed");
        };
        assert_eq!(failure.message, "-D 127.0.0.1:1080: refused");
        assert_eq!(*closed.borrow(), [1, 2]);
    }

    #[test]
    fn a_reader_that_has_gone_closes_every_forward() {
        let closed = std::cell::RefCell::new(Vec::new());
        let mut opened = 0;
        let result = open_each(
            &three(),
            "web",
            &mut Gone,
            |_| {
                opened += 1;
                Ok((opened, "127.0.0.1:1".to_owned()))
            },
            |open: &[i32]| closed.borrow_mut().extend_from_slice(open),
        );
        assert_eq!(result.map_err(|f| f.message), Ok(Opened::ReaderGone));
        assert_eq!(opened, 1, "nothing more opens once nobody reads");
        assert_eq!(*closed.borrow(), [1]);
    }
}
