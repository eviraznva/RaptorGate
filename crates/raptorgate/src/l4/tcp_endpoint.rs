use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

use crate::conntrack::tuple::Direction;
use crate::l4::stage::L4Emit;

const CHANNEL_CAPACITY: usize = 1024;

pub struct L4TcpEndpoint {
    pub reader: L4TcpReadHalf,
    pub writer: L4TcpWriteHalf,
}

#[derive(Clone)]
pub struct L4TcpEndpointHandle {
    inbound_tx: mpsc::Sender<Vec<u8>>,
    emitted_rx: Arc<Mutex<mpsc::UnboundedReceiver<L4Emit>>>,
}

pub struct L4TcpReadHalf {
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
}

pub struct L4TcpWriteHalf {
    dir: Direction,
    emitted_tx: mpsc::UnboundedSender<L4Emit>,
}

impl L4TcpEndpoint {
    pub fn new() -> (Self, L4TcpEndpointHandle) {
        Self::with_writer_direction(Direction::Reply)
    }

    pub fn with_writer_direction(dir: Direction) -> (Self, L4TcpEndpointHandle) {
        let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (emitted_tx, emitted_rx) = mpsc::unbounded_channel();
        (
            Self {
                reader: L4TcpReadHalf {
                    inbound_rx,
                    current: Vec::new(),
                    offset: 0,
                },
                writer: L4TcpWriteHalf { dir, emitted_tx },
            },
            L4TcpEndpointHandle {
                inbound_tx,
                emitted_rx: Arc::new(Mutex::new(emitted_rx)),
            },
        )
    }
}

impl L4TcpEndpointHandle {
    pub async fn admit(&self, _dir: Direction, payload: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.inbound_tx.send(payload).await
    }

    pub async fn next_emitted(&mut self) -> Option<L4Emit> {
        self.emitted_rx.lock().await.recv().await
    }

    pub fn try_next_emitted(&self) -> Option<L4Emit> {
        self.emitted_rx.try_lock().ok()?.try_recv().ok()
    }
}

impl AsyncRead for L4TcpEndpoint {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for L4TcpEndpoint {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl AsyncRead for L4TcpReadHalf {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.offset < self.current.len() {
                let available = &self.current[self.offset..];
                let take = available.len().min(buf.remaining());
                buf.put_slice(&available[..take]);
                self.offset += take;
                if self.offset == self.current.len() {
                    self.current.clear();
                    self.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.inbound_rx).poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for L4TcpWriteHalf {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let item = L4Emit {
            dir: self.dir,
            payload: data.to_vec(),
        };
        match self.emitted_tx.send(item) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "L4 TCP endpoint closed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn endpoint_reads_admitted_encrypted_bytes() {
        let (endpoint, handle) = L4TcpEndpoint::new();

        handle.admit(Direction::Original, b"client tls".to_vec()).await.unwrap();
        drop(handle);

        let mut reader = endpoint.reader;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"client tls");
    }

    #[tokio::test]
    async fn endpoint_write_returns_generated_ciphertext() {
        let (endpoint, mut handle) = L4TcpEndpoint::new();

        let mut writer = endpoint.writer;
        writer.write_all(b"server tls").await.unwrap();
        writer.flush().await.unwrap();

        let emitted = handle.next_emitted().await.unwrap();
        assert_eq!(emitted.dir, Direction::Reply);
        assert_eq!(emitted.payload, b"server tls");
    }
}
