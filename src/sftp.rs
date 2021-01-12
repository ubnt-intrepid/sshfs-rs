//! A pure-Rust implementation of SFTP client independent to transport layer.

// Refs:
// * https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
// * https://tools.ietf.org/html/rfc4251
// * https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sftp-server.c?rev=1.120&content-type=text/x-cvsweb-markup

#![allow(dead_code)]

use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use futures::{
    future::Future,
    ready,
    task::{self, Poll},
};
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    io,
    mem::{self, MaybeUninit},
    os::unix::prelude::*,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Weak,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, oneshot},
};

const SFTP_PROTOCOL_VERSION: u32 = 3;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-3
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;
const SSH_FXP_EXTENDED: u8 = 200;
const SSH_FXP_EXTENDED_REPLY: u8 = 201;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;
const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.3
const SSH_FXF_READ: u32 = 0x00000001;
const SSH_FXF_WRITE: u32 = 0x00000002;
const SSH_FXF_APPEND: u32 = 0x00000004;
const SSH_FXF_CREAT: u32 = 0x00000008;
const SSH_FXF_TRUNC: u32 = 0x00000010;
const SSH_FXF_EXCL: u32 = 0x00000020;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-7
pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_BAD_MESSAGE: u32 = 5;
pub const SSH_FX_NO_CONNECTION: u32 = 6;
pub const SSH_FX_CONNECTION_LOST: u32 = 7;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("errored in underlying transport I/O")]
    Transport(
        #[from]
        #[source]
        io::Error,
    ),

    #[error("protocol error")]
    Protocol { msg: Cow<'static, str> },

    #[error("from remote: {}", _0)]
    Remote(#[source] RemoteError),

    #[error("session has already been closed")]
    SessionClosed,
}

#[derive(Debug, thiserror::Error)]
#[error("from remote server")]
pub struct RemoteError(RemoteStatus);

impl RemoteError {
    pub fn code(&self) -> u32 {
        self.0.code
    }

    pub fn message(&self) -> &OsStr {
        &self.0.message
    }

    pub fn language_tag(&self) -> &OsStr {
        &self.0.language_tag
    }
}

// described in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct FileAttr {
    pub size: Option<u64>,
    pub uid_gid: Option<(u32, u32)>,
    pub permissions: Option<u32>,
    pub ac_mod_time: Option<(u32, u32)>,
    pub extended: Vec<(OsString, OsString)>,
}

impl FileAttr {
    pub fn uid(&self) -> Option<u32> {
        self.uid_gid.map(|(uid, _)| uid)
    }

    pub fn gid(&self) -> Option<u32> {
        self.uid_gid.map(|(_, gid)| gid)
    }

    pub fn atime(&self) -> Option<u32> {
        self.ac_mod_time.map(|(atime, _)| atime)
    }

    pub fn mtime(&self) -> Option<u32> {
        self.ac_mod_time.map(|(_, mtime)| mtime)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct DirEntry {
    pub filename: OsString,
    pub longname: OsString,
    pub attrs: FileAttr,
}

#[derive(Debug, Clone)]
pub struct FileHandle(Arc<OsStr>);

/// The handle for communicating with associated SFTP session.
#[derive(Debug, Clone)]
pub struct Session {
    inner: Weak<Inner>,
}

impl Session {
    async fn request<F>(&self, packet_type: u8, f: F) -> Result<Response, Error>
    where
        F: FnOnce(&Inner, &mut Vec<u8>),
    {
        let inner = self.inner.upgrade().ok_or(Error::SessionClosed)?;
        inner.send_request(packet_type, f).await
    }

    /// Request to open a file.
    pub async fn open(
        &self,
        filename: impl AsRef<OsStr>,
        pflags: OpenFlag,
        attrs: &FileAttr,
    ) -> Result<FileHandle, Error> {
        let filename = filename.as_ref();

        let response = self
            .request(SSH_FXP_OPEN, |_, buf| {
                put_string(&mut *buf, filename.as_bytes());
                buf.put_u32(pflags.bits());
                put_attrs(&mut *buf, attrs);
            })
            .await?;

        match response {
            Response::Handle(handle) => Ok(handle),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to close a file corresponding to the specified handle.
    pub async fn close(&self, handle: &FileHandle) -> Result<(), Error> {
        let response = self
            .request(SSH_FXP_CLOSE, |_, buf| {
                put_string(&mut *buf, handle.0.as_bytes());
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to read a range of data from an opened file corresponding to the specified handle.
    pub async fn read(&self, handle: &FileHandle, offset: u64, len: u32) -> Result<Vec<u8>, Error> {
        let response = self
            .request(SSH_FXP_READ, |_, buf| {
                put_string(&mut *buf, handle.0.as_bytes());
                buf.put_u64(offset);
                buf.put_u32(len);
            })
            .await?;

        match response {
            Response::Data(data) => Ok(data),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to write a range of data to an opened file corresponding to the specified handle.
    pub async fn write(&self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<(), Error> {
        let response = self
            .request(SSH_FXP_WRITE, |_, buf| {
                put_string(&mut *buf, handle.0.as_bytes());
                buf.put_u64(offset);
                buf.put(&*data);
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file, without following symbolic links.
    #[inline]
    pub async fn lstat(&self, path: impl AsRef<OsStr>) -> Result<FileAttr, Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_LSTAT, |_, buf| {
                put_string(&mut *buf, path.as_bytes());
            })
            .await?;

        match response {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub async fn fstat(&self, handle: &FileHandle) -> Result<FileAttr, Error> {
        let response = self
            .request(SSH_FXP_FSTAT, |_, buf| {
                put_string(&mut *buf, handle.0.as_bytes());
            })
            .await?;

        match response {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn setstat(&self, path: impl AsRef<OsStr>, attrs: &FileAttr) -> Result<(), Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_SETSTAT, |_, buf| {
                put_string(&mut *buf, path.as_bytes());
                put_attrs(&mut *buf, attrs);
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn fsetstat(&self, handle: &FileHandle, attrs: &FileAttr) -> Result<(), Error> {
        let response = self
            .request(SSH_FXP_FSETSTAT, |_, buf| {
                put_string(&mut *buf, handle.0.as_bytes());
                put_attrs(&mut *buf, attrs);
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a directory for reading.
    pub async fn opendir(&self, path: impl AsRef<OsStr>) -> Result<FileHandle, Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_OPENDIR, |_, buf| {
                put_string(buf, path.as_bytes());
            })
            .await?;

        match response {
            Response::Handle(handle) => Ok(handle),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to list files and directories contained in an opened directory.
    pub async fn readdir(&self, handle: &FileHandle) -> Result<Vec<DirEntry>, Error> {
        let response = self
            .request(SSH_FXP_READDIR, |_, buf| {
                put_string(buf, handle.0.as_bytes());
            })
            .await?;

        match response {
            Response::Name(entries) => Ok(entries),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn remove(&self, filename: impl AsRef<OsStr>) -> Result<(), Error> {
        let filename = filename.as_ref();

        let response = self
            .request(SSH_FXP_REMOVE, |_, buf| {
                put_string(&mut *buf, filename.as_bytes());
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn mkdir(&self, path: impl AsRef<OsStr>, attrs: &FileAttr) -> Result<(), Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_MKDIR, |_, buf| {
                put_string(&mut *buf, path.as_bytes());
                put_attrs(&mut *buf, attrs);
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn rmdir(&self, path: impl AsRef<OsStr>) -> Result<(), Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_RMDIR, |_, buf| {
                put_string(&mut *buf, path.as_bytes());
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn realpath(&self, path: impl AsRef<OsStr>) -> Result<OsString, Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_REALPATH, |_, buf| {
                put_string(&mut *buf, path.as_bytes());
            })
            .await?;

        match response {
            Response::Name(mut entries) => Ok(entries.remove(0).filename),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[inline]
    pub async fn stat(&self, path: impl AsRef<OsStr>) -> Result<FileAttr, Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_STAT, |_, buf| {
                put_string(buf, path.as_bytes());
            })
            .await?;

        match response {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn rename(
        &self,
        oldpath: impl AsRef<OsStr>,
        newpath: impl AsRef<OsStr>,
    ) -> Result<(), Error> {
        let oldpath = oldpath.as_ref();
        let newpath = newpath.as_ref();

        let response = self
            .request(SSH_FXP_RENAME, |_, buf| {
                put_string(&mut *buf, oldpath.as_bytes());
                put_string(&mut *buf, newpath.as_bytes());
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn readlink(&self, path: impl AsRef<OsStr>) -> Result<OsString, Error> {
        let path = path.as_ref();

        let response = self
            .request(SSH_FXP_READLINK, |_, buf| {
                put_string(&mut *buf, path.as_bytes());
            })
            .await?;

        match response {
            Response::Name(mut entries) => Ok(entries.remove(0).filename),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn symlink(
        &self,
        linkpath: impl AsRef<OsStr>,
        targetpath: impl AsRef<OsStr>,
    ) -> Result<(), Error> {
        let linkpath = linkpath.as_ref();
        let targetpath = targetpath.as_ref();

        let response = self
            .request(SSH_FXP_SYMLINK, |inner, buf| {
                if inner.reverse_symlink_arguments {
                    put_string(&mut *buf, targetpath.as_bytes());
                    put_string(&mut *buf, linkpath.as_bytes());
                } else {
                    put_string(&mut *buf, linkpath.as_bytes());
                    put_string(&mut *buf, targetpath.as_bytes());
                }
            })
            .await?;

        match response {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    pub async fn extended(
        &self,
        request: impl AsRef<OsStr>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let request = request.as_ref();

        let response = self
            .request(SSH_FXP_EXTENDED, |_, buf| {
                put_string(&mut *buf, request.as_bytes());
                buf.put(data);
            })
            .await?;

        match response {
            Response::Extended(data) => Ok(data.to_vec()),
            Response::Status(st) if st.code != SSH_FX_OK => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }
}

bitflags::bitflags! {
    /// Open file flags.
    #[repr(transparent)]
    pub struct OpenFlag: u32 {
        /// Open the file for reading.
        const READ = SSH_FXF_READ;

        /// Open the file for writing.
        const WRITE = SSH_FXF_WRITE;

        /// Force all writes to append data at the end of the file.
        const APPEND = SSH_FXF_APPEND;

        /// A new file will be created if one does not already exist.
        ///
        /// When [`TRUNC`](Self::TRUNC) is specified at the same time
        /// as this flag, the new file will be truncated to zero length
        /// if it previously exists.
        const CREAT = SSH_FXF_CREAT;

        /// Forces an existing file with the same name to be truncated
        /// to zero length when creating a file.
        ///
        /// This flag MUST be specified with [`CREAT`](Self::CREAT) if
        /// it is used.
        const TRUNC = SSH_FXF_TRUNC;

        /// Causes the request to fail if the named file already exists.
        ///
        /// This flag MUST be specified with [`CREAT`](Self::CREAT) if
        /// it is used.
        const EXCL = SSH_FXF_EXCL;
    }
}

// ==== session drivers ====

#[derive(Debug)]
struct Inner {
    extensions: Vec<(OsString, OsString)>,
    reverse_symlink_arguments: bool,
    incoming_requests: mpsc::UnboundedSender<Vec<u8>>,
    pending_requests: DashMap<u32, oneshot::Sender<Response>>,
    next_request_id: AtomicU32,
}

impl Inner {
    async fn send_request<F>(&self, packet_type: u8, f: F) -> Result<Response, Error>
    where
        F: FnOnce(&Inner, &mut Vec<u8>),
    {
        // FIXME: choose appropriate atomic ordering.
        let id = self.next_request_id.fetch_add(1, Ordering::SeqCst);

        let mut buf = vec![];
        buf.put_u8(packet_type);
        buf.put_u32(id);
        f(self, &mut buf);

        self.incoming_requests.send(buf).map_err(|_| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "session is not available")
        })?;

        let (tx, rx) = oneshot::channel();
        self.pending_requests.insert(id, tx);

        rx.await.map_err(|_| Error::SessionClosed)
    }
}

#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Connection<T> {
    stream: T,
    inner: Arc<Inner>,
    incoming_requests: mpsc::UnboundedReceiver<Vec<u8>>,
    send: SendRequest,
    recv: RecvResponse,
}

#[derive(Debug)]
enum SendRequest {
    Waiting,
    Writing {
        packet: bytes::buf::Chain<io::Cursor<[u8; 4]>, io::Cursor<Vec<u8>>>,
    },
    Closed,
}

#[derive(Debug)]
enum RecvResponse {
    ReadLength {
        buf: [u8; 4],
        filled: usize,
    },
    ReadPacket {
        buf: BytesMut,
        inited: usize,
        filled: usize,
    },
}

impl<T> Future for Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        let me = self.get_mut();

        // FIXME: gracefully shutdown
        let send = me.poll_send(cx)?;
        let recv = me.poll_recv(cx)?;

        if send.is_ready() && recv.is_ready() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl<T> Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_send(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        let mut w = Pin::new(&mut self.stream);

        loop {
            match &mut self.send {
                SendRequest::Waiting => match ready!(self.incoming_requests.poll_recv(cx)) {
                    Some(packet) => {
                        let length = packet.len() as u32;
                        self.send = SendRequest::Writing {
                            packet: Buf::chain(
                                io::Cursor::new(length.to_be_bytes()),
                                io::Cursor::new(packet),
                            ),
                        };
                    }
                    None => {
                        self.send = SendRequest::Closed;
                        return Poll::Ready(Ok(()));
                    }
                },

                SendRequest::Writing { packet } => {
                    while packet.remaining() > 0 {
                        let written = ready!(w.as_mut().poll_write(cx, packet.chunk()))?;
                        packet.advance(written);
                    }
                    ready!(w.as_mut().poll_flush(cx))?;
                    self.send = SendRequest::Waiting;
                }

                SendRequest::Closed => return Poll::Ready(Ok(())),
            }
        }
    }

    fn poll_recv(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        let mut r = Pin::new(&mut self.stream);

        loop {
            match &mut self.recv {
                RecvResponse::ReadLength { buf, filled } => {
                    let mut read_buf = ReadBuf::new(buf);
                    read_buf.set_filled(*filled);
                    while read_buf.remaining() > 0 {
                        let res = r.as_mut().poll_read(cx, &mut read_buf);
                        *filled = read_buf.filled().len();
                        ready!(res)?;
                    }

                    let length = u32::from_be_bytes(*buf);
                    let buf = BytesMut::with_capacity(length as usize);
                    self.recv = RecvResponse::ReadPacket {
                        buf,
                        inited: 0,
                        filled: 0,
                    };
                }

                RecvResponse::ReadPacket {
                    buf,
                    inited,
                    filled,
                } => {
                    let mut read_buf = unsafe {
                        let mut b = ReadBuf::uninit(std::slice::from_raw_parts_mut(
                            buf.as_mut_ptr() as *mut MaybeUninit<u8>,
                            buf.capacity(),
                        ));
                        b.assume_init(*inited);
                        b.set_filled(*filled);
                        b
                    };

                    while read_buf.remaining() > 0 {
                        let res = r.as_mut().poll_read(cx, &mut read_buf);
                        *inited = read_buf.initialized().len();
                        *filled = read_buf.filled().len();
                        ready!(res)?;
                    }

                    unsafe {
                        buf.set_len(buf.capacity());
                    }

                    match std::mem::replace(
                        &mut self.recv,
                        RecvResponse::ReadLength {
                            buf: [0u8; 4],
                            filled: 0,
                        },
                    ) {
                        RecvResponse::ReadPacket { buf, .. } => {
                            let mut packet = buf.freeze();

                            let typ = read_u8(&mut packet)?;
                            let id = read_u32(&mut packet)?;

                            let response = match typ {
                                SSH_FXP_STATUS => {
                                    let code = read_u32(&mut packet)?;
                                    let message = read_string(&mut packet)?;
                                    let language_tag = read_string(&mut packet)?;
                                    Response::Status(RemoteStatus {
                                        code,
                                        message,
                                        language_tag,
                                    })
                                }

                                SSH_FXP_HANDLE => {
                                    let handle = read_string(&mut packet)?;
                                    Response::Handle(FileHandle(handle.into_boxed_os_str().into()))
                                }

                                SSH_FXP_DATA => {
                                    let data = read_string(&mut packet)?;
                                    Response::Data(data.into_vec())
                                }

                                SSH_FXP_ATTRS => {
                                    let attrs = read_file_attr(&mut packet)?;
                                    Response::Attrs(attrs)
                                }

                                SSH_FXP_NAME => {
                                    let count = read_u32(&mut packet)?;
                                    let mut entries = Vec::with_capacity(count as usize);
                                    for _ in 0..count {
                                        let filename = read_string(&mut packet)?;
                                        let longname = read_string(&mut packet)?;
                                        let attrs = read_file_attr(&mut packet)?;
                                        entries.push(DirEntry {
                                            filename,
                                            longname,
                                            attrs,
                                        });
                                    }
                                    Response::Name(entries)
                                }

                                SSH_FXP_EXTENDED_REPLY => {
                                    let data = packet.split_to(packet.len());
                                    Response::Extended(data)
                                }

                                typ => {
                                    let data = packet.split_to(packet.len());
                                    Response::Unknown { typ, data }
                                }
                            };

                            debug_assert!(packet.is_empty());

                            if let Some((_id, tx)) = self.inner.pending_requests.remove(&id) {
                                let _ = tx.send(response);
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
}

/// The kind of response values received from the server.
#[derive(Debug)]
enum Response {
    /// The operation is failed.
    Status(RemoteStatus),

    /// An opened file handle.
    Handle(FileHandle),

    /// Received data.
    Data(Vec<u8>),

    /// Retrieved attribute values.
    Attrs(FileAttr),

    /// Directory entries.
    Name(Vec<DirEntry>),

    /// Reply from an vendor-specific extended request.
    Extended(Bytes),

    /// The response type is unknown or currently not supported.
    Unknown { typ: u8, data: Bytes },
}

#[derive(Debug)]
struct RemoteStatus {
    code: u32,
    message: OsString,
    language_tag: OsString,
}

/// Start a SFTP session on the provided transport I/O.
///
/// This is a shortcut to `InitSession::default().init(r, w)`.
pub async fn init<T>(stream: T) -> Result<(Session, Connection<T>), Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    InitSession::default().init(stream).await
}

#[derive(Debug)]
pub struct InitSession {
    reverse_symlink_arguments: bool,
    extensions: Vec<(OsString, OsString)>,
}

impl Default for InitSession {
    fn default() -> Self {
        Self {
            reverse_symlink_arguments: true,
            extensions: vec![],
        }
    }
}

impl InitSession {
    /// Reverse the order of arguments in symlink request.
    ///
    /// For historical reason, the SFTP server implementation provied by OpenSSH
    /// (`sftp-server`) requiers that the order of arguments in the `SSH_FXP_SYMLINK`
    /// requests be the opposite of what is defined in RFC draft.
    ///
    /// This flag is enabled by default, as most SFTP servers are expected to
    /// use OpenSSH's implementation.
    pub fn reverse_symlink_arguments(&mut self, enabled: bool) -> &mut Self {
        self.reverse_symlink_arguments = enabled;
        self
    }

    pub fn extension(&mut self, name: OsString, data: OsString) -> &mut Self {
        self.extensions.push((name, data));
        self
    }

    /// Start a SFTP session on the provided transport I/O.
    ///
    /// This function first exchanges some packets with the server and negotiates
    /// the settings of SFTP protocol to use.  When the initialization process is
    /// successed, it returns a handle to send subsequent SFTP requests from the
    /// client and objects to drive the underlying communication with the server.
    pub async fn init<T>(&self, stream: T) -> Result<(Session, Connection<T>), Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut stream = stream;

        // send SSH_FXP_INIT packet.
        let packet = {
            let mut buf = vec![];
            buf.put_u8(SSH_FXP_INIT);
            buf.put_u32(SFTP_PROTOCOL_VERSION);
            for (name, data) in &self.extensions {
                put_string(&mut buf, name.as_bytes());
                put_string(&mut buf, data.as_bytes());
            }
            buf
        };
        let length = packet.len() as u32;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&packet[..]).await?;
        stream.flush().await?;

        // receive SSH_FXP_VERSION packet.
        let length = {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf[..]).await?;
            u32::from_be_bytes(buf)
        };

        let packet = {
            let mut buf = vec![0u8; length as usize];
            stream.read_exact(&mut buf[..]).await?;
            buf
        };
        let mut packet = &packet[..];

        let typ = read_u8(&mut packet)?;
        if typ != SSH_FXP_VERSION {
            return Err(Error::Protocol {
                msg: "incorrect message type during initialization".into(),
            });
        }

        let version = read_u32(&mut packet)?;
        if version < SFTP_PROTOCOL_VERSION {
            return Err(Error::Protocol {
                msg: "server supports older SFTP protocol".into(),
            });
        }

        let mut extensions = vec![];
        while !packet.is_empty() {
            let name = read_string(&mut packet)?;
            let data = read_string(&mut packet)?;
            extensions.push((name, data));
        }

        let (tx, rx) = mpsc::unbounded_channel();

        let inner = Arc::new(Inner {
            extensions,
            reverse_symlink_arguments: self.reverse_symlink_arguments,
            incoming_requests: tx,
            pending_requests: DashMap::new(),
            next_request_id: AtomicU32::new(0),
        });

        let session = Session {
            inner: Arc::downgrade(&inner),
        };

        let conn = Connection {
            stream,
            inner,
            incoming_requests: rx,
            send: SendRequest::Waiting,
            recv: RecvResponse::ReadLength {
                buf: [0u8; 4],
                filled: 0,
            },
        };

        Ok((session, conn))
    }
}

// ==== misc ====

#[inline]
fn put_string<B>(mut b: B, s: &[u8])
where
    B: BufMut,
{
    b.put_u32(s.len() as u32);
    b.put(s);
}

fn put_attrs<B>(mut b: B, attrs: &FileAttr)
where
    B: BufMut,
{
    #[inline(always)]
    fn flag(b: bool, flag: u32) -> u32 {
        if b {
            flag
        } else {
            0
        }
    }

    let flags = flag(attrs.size.is_some(), SSH_FILEXFER_ATTR_SIZE)
        | flag(attrs.uid_gid.is_some(), SSH_FILEXFER_ATTR_UIDGID)
        | flag(attrs.permissions.is_some(), SSH_FILEXFER_ATTR_PERMISSIONS)
        | flag(attrs.ac_mod_time.is_some(), SSH_FILEXFER_ATTR_ACMODTIME)
        | flag(!attrs.extended.is_empty(), SSH_FILEXFER_ATTR_EXTENDED);

    b.put_u32(flags);
    if let Some(size) = attrs.size {
        b.put_u64(size);
    }
    if let Some((uid, gid)) = attrs.uid_gid {
        b.put_u32(uid);
        b.put_u32(gid);
    }
    if let Some(perm) = attrs.permissions {
        b.put_u32(perm);
    }
    if let Some((atime, mtime)) = attrs.ac_mod_time {
        b.put_u32(atime);
        b.put_u32(mtime);
    }
    if !attrs.extended.is_empty() {
        b.put_u32(attrs.extended.len() as u32);
        for (typ, data) in &attrs.extended {
            put_string(&mut b, typ.as_bytes());
            put_string(&mut b, data.as_bytes());
        }
    }
}

#[inline]
fn ensure_buf_remaining(b: &impl Buf, n: usize) -> Result<(), Error> {
    if b.remaining() >= n {
        Ok(())
    } else {
        Err(Error::Protocol {
            msg: "too short data".into(),
        })
    }
}

fn read_u8<B>(mut b: B) -> Result<u8, Error>
where
    B: Buf,
{
    ensure_buf_remaining(&b, mem::size_of::<u8>())?;
    let ret = b.chunk()[0];
    b.advance(1);
    Ok(ret)
}

fn read_u32<B>(mut b: B) -> Result<u32, Error>
where
    B: Buf,
{
    ensure_buf_remaining(&b, mem::size_of::<u32>())?;
    let mut buf = [0u8; mem::size_of::<u32>()];
    b.copy_to_slice(&mut buf[..]);
    Ok(u32::from_be_bytes(buf))
}

fn read_u64<B>(mut b: B) -> Result<u64, Error>
where
    B: Buf,
{
    ensure_buf_remaining(&b, mem::size_of::<u64>())?;
    let mut buf = [0u8; mem::size_of::<u64>()];
    b.copy_to_slice(&mut buf[..]);
    Ok(u64::from_be_bytes(buf))
}

fn read_string<B>(mut b: B) -> Result<OsString, Error>
where
    B: Buf,
{
    let len = read_u32(&mut b)?;
    ensure_buf_remaining(&b, len as usize)?;

    let mut buf = vec![0u8; len as usize];
    b.copy_to_slice(&mut buf[..]);

    Ok(OsString::from_vec(buf))
}

fn read_file_attr<B>(mut b: B) -> Result<FileAttr, Error>
where
    B: Buf,
{
    let flags = read_u32(&mut b)?;

    let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
        let size = read_u64(&mut b)?;
        Some(size)
    } else {
        None
    };

    let uid_gid = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        let uid = read_u32(&mut b)?;
        let gid = read_u32(&mut b)?;
        Some((uid, gid))
    } else {
        None
    };

    let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        let perm = read_u32(&mut b)?;
        Some(perm)
    } else {
        None
    };

    let ac_mod_time = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let atime = read_u32(&mut b)?;
        let mtime = read_u32(&mut b)?;
        Some((atime, mtime))
    } else {
        None
    };

    let mut extended = vec![];

    if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count = read_u32(&mut b)?;
        for _ in 0..count {
            let ex_type = read_string(&mut b)?;
            let ex_data = read_string(&mut b)?;
            extended.push((ex_type, ex_data));
        }
    }

    Ok(FileAttr {
        size,
        uid_gid,
        permissions,
        ac_mod_time,
        extended,
    })
}
