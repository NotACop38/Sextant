//! A minimal HTTP/1.1 server bound to 127.0.0.1 for provider tests.
//!
//! It serves a scripted list of replies, one connection each, records every
//! request it receives, and never touches the network beyond loopback. Replies
//! can also misbehave on purpose (trickle a body or stay silent) so deadline
//! handling can be tested.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// One request as the server received it.
#[derive(Debug, Clone)]
pub(crate) struct Captured {
    /// The request path, for example `/v1/messages`.
    pub(crate) path: String,
    /// Header names (lowercased) and values, in arrival order.
    pub(crate) headers: Vec<(String, String)>,
    /// The request body.
    pub(crate) body: Vec<u8>,
}

impl Captured {
    /// The value of a header, matched case-insensitively.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body parsed as JSON.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("the request body is JSON")
    }
}

/// What the server does with one connection.
pub(crate) enum Reply {
    /// Answer with a status, extra headers, and a JSON body.
    Json {
        /// The HTTP status code.
        status: u16,
        /// Extra response headers.
        headers: Vec<(&'static str, String)>,
        /// The response body.
        body: String,
    },
    /// Send headers promising a large body, then one byte per `interval`
    /// until `total` has passed or the client hangs up.
    Drip {
        /// Delay between body bytes.
        interval: Duration,
        /// How long to keep dripping before closing.
        total: Duration,
    },
    /// Read the request and then say nothing for `hold`.
    Silent {
        /// How long to hold the connection open.
        hold: Duration,
    },
}

impl Reply {
    /// A JSON reply with no extra headers.
    pub(crate) fn json(status: u16, body: &str) -> Self {
        Self::Json {
            status,
            headers: Vec::new(),
            body: body.to_owned(),
        }
    }
}

/// A running fake server.
pub(crate) struct FakeServer {
    /// The server's base URL, for example `http://127.0.0.1:40000`.
    pub(crate) base_url: String,
    requests: mpsc::Receiver<Captured>,
}

impl FakeServer {
    /// Start serving `replies` in order, one connection per reply.
    pub(crate) fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let base_url = format!("http://{}", listener.local_addr().expect("local address"));
        let (sender, requests) = mpsc::channel();
        std::thread::spawn(move || {
            for reply in replies {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                // A client that hangs up mid-reply is expected in the
                // deadline tests, so write errors are ignored.
                let _ = serve(stream, reply, &sender);
            }
        });
        Self { base_url, requests }
    }

    /// The next request the server received, waiting up to ten seconds.
    pub(crate) fn next_request(&self) -> Captured {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the provider sent a request")
    }

    /// How many further requests arrive within `wait`.
    pub(crate) fn count_more(&self, wait: Duration) -> usize {
        let deadline = Instant::now() + wait;
        let mut count = 0;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            if self.requests.recv_timeout(left).is_err() {
                break;
            }
            count += 1;
        }
        count
    }
}

/// Read one request from `stream`, record it, and act out `reply`.
fn serve(stream: TcpStream, reply: Reply, sender: &mpsc::Sender<Captured>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let _ = sender.send(Captured {
        path,
        headers,
        body,
    });

    let mut stream = stream;
    match reply {
        Reply::Json {
            status,
            headers,
            body,
        } => {
            let mut head = format!(
                "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            stream.write_all(head.as_bytes())?;
            stream.write_all(body.as_bytes())?;
            stream.flush()
        }
        Reply::Drip { interval, total } => {
            stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000000\r\nconnection: close\r\n\r\n",
            )?;
            let started = Instant::now();
            while started.elapsed() < total {
                stream.write_all(b" ")?;
                stream.flush()?;
                std::thread::sleep(interval);
            }
            Ok(())
        }
        Reply::Silent { hold } => {
            std::thread::sleep(hold);
            Ok(())
        }
    }
}
