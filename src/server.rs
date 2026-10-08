//! Connection handling shared by the local `demo` and `directory` servers.

use anyhow::{Context, Result, bail};
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

/// Connections served at once; further connections are closed immediately.
const MAX_ACTIVE_CONNECTIONS: usize = 64;

/// Wall-clock limit for receiving one request, however slowly the client trickles bytes.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// Longest single wait for more bytes from the client.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Accepts connections and handles each on its own thread, so one slow or idle client
/// cannot stall the others. With `max_connections`, stops accepting after that many and
/// waits for in-flight handlers before returning.
pub(crate) fn serve<F>(listener: TcpListener, max_connections: Option<usize>, handler: F)
where
    F: Fn(TcpStream) + Sync,
{
    let active = AtomicUsize::new(0);
    thread::scope(|scope| {
        for (accepted, connection) in listener.incoming().enumerate() {
            match connection {
                Ok(stream) => {
                    if active.fetch_add(1, Ordering::SeqCst) >= MAX_ACTIVE_CONNECTIONS {
                        active.fetch_sub(1, Ordering::SeqCst);
                        drop(stream);
                    } else {
                        let (active, handler) = (&active, &handler);
                        scope.spawn(move || {
                            handler(stream);
                            active.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                }
                Err(error) => eprintln!("botgate: accepting connection: {error}"),
            }
            if max_connections.is_some_and(|limit| accepted + 1 >= limit) {
                break;
            }
        }
    });
}

/// Tracks the request deadline for one connection.
pub(crate) struct RequestReader {
    started: Instant,
}

impl RequestReader {
    pub(crate) fn new(stream: &TcpStream) -> Result<Self> {
        stream.set_write_timeout(Some(READ_TIMEOUT))?;
        Ok(Self {
            started: Instant::now(),
        })
    }

    /// Reads once, failing when the overall request deadline has passed.
    pub(crate) fn read(&self, stream: &mut TcpStream, buffer: &mut [u8]) -> Result<usize> {
        let remaining = REQUEST_DEADLINE
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero());
        let Some(remaining) = remaining else {
            bail!(
                "request not received within {}s",
                REQUEST_DEADLINE.as_secs()
            );
        };
        stream.set_read_timeout(Some(remaining.min(READ_TIMEOUT)))?;
        stream.read(buffer).context("reading request")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn idle_connection_does_not_block_other_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            serve(listener, Some(2), |mut stream| {
                let reader = RequestReader::new(&stream).unwrap();
                let mut buffer = [0_u8; 64];
                if reader
                    .read(&mut stream, &mut buffer)
                    .is_ok_and(|size| size > 0)
                {
                    let _ = stream.write_all(b"ok");
                }
            });
        });

        // The first client connects and sends nothing.
        let idle = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(100));

        let started = Instant::now();
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"ping").unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert_eq!(response, "ok");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );

        drop(idle);
        server.join().unwrap();
    }
}
