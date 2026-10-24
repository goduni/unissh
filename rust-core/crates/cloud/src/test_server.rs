//! A scripted HTTP server for the tests of this crate.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// The server's answer to an expired access token.
pub const UNAUTH: (&str, &str) = (
    "401 Unauthorized",
    r#"{"error":{"code":"unauthenticated","message":"access token expired"}}"#,
);

/// A throwaway HTTP server that answers each connection from a canned script
/// and records the Authorization header it was given.
///
/// `replies` are (status line, JSON body) — the Content-Length is COMPUTED.
/// It was hand-written first, was wrong by two bytes, and reqwest then failed
/// to read the body: three tests failed asserting on the error code because
/// the envelope never parsed. A fixture that can lie about its own length is
/// a fixture that tests the fixture.
pub fn serve(replies: Vec<(&'static str, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    std::thread::spawn(move || {
        for (status, body) in replies {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(&stream);
            let mut auth = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("authorization:") {
                    auth = v.trim().to_owned();
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            seen2.lock().unwrap().push(auth);
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let mut w = &stream;
            w.write_all(reply.as_bytes())
                .expect("the test client reads the reply");
            w.flush().expect("the test client reads the reply");
        }
    });
    (format!("http://127.0.0.1:{port}"), seen)
}
