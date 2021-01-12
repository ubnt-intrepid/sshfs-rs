mod sftp;

use anyhow::{ensure, Context as _, Result};
use futures::{
    future::poll_fn,
    ready,
    task::{self, Poll},
};
use polyfuse::{
    op,
    reply::{AttrOut, EntryOut, FileAttr, OpenOut, ReaddirOut, WriteOut},
    Data, KernelConfig, Operation, Request,
};
use slab::Slab;
use std::{
    collections::HashMap,
    ffi::OsString,
    io::{self, prelude::*},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{unix::AsyncFd, AsyncRead, AsyncWrite, Interest, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
};
use tracing::Instrument as _;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::from_env().context("Failed to parse command line arguments")?;
    dbg!(&args);

    ensure!(args.mountpoint.is_dir(), "mountpoint must be a directory");

    let (mut child, stream) = establish_connection(&args.host, &args.username)
        .context("failed to establish SSH connection")?;

    let (sftp, conn) = crate::sftp::init(stream)
        .await
        .context("failed to initialize SFTP session")?;
    tokio::spawn(conn.instrument(tracing::debug_span!("sftp_connection")));

    // let stat = sftp
    //     .lstat(&args.base_dir)
    //     .await
    //     .context("failed to get target attribute")?;
    // ensure!(stat.is_dir(), "the target path is not directory");

    let fuse = AsyncSession::mount(args.mountpoint, {
        let mut config = KernelConfig::default();
        config.mount_option("fsname=sshfs");
        config.mount_option("default_permissions");
        config
    })
    .await
    .context("failed to start FUSE session")?;

    let mut sshfs = SSHFS {
        sftp,
        base_dir: args.base_dir,
        path_table: PathTable::new(),
        dir_handles: Slab::new(),
        file_handles: Slab::new(),
    };

    while let Some(req) = fuse
        .next_request()
        .await
        .context("failed to receive FUSE request")?
    {
        sshfs
            .handle_request(&req)
            .await
            .context("failed to send FUSE reply")?;
    }

    child.kill().await.context("failed to send kill")?;
    child.wait().await?;

    Ok(())
}

#[derive(Debug)]
struct Args {
    mountpoint: PathBuf,
    host: SocketAddr,
    username: String,
    base_dir: PathBuf,
}

impl Args {
    fn from_env() -> Result<Self> {
        let mut args = pico_args::Arguments::from_env();

        let host = args
            .opt_value_from_str(["-h", "--host"])?
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 22)));

        let username = args
            .opt_value_from_str(["-u", "--user"])?
            .unwrap_or_else(whoami::username);

        let directory = args
            .opt_value_from_str(["-d", "--directory"])?
            .unwrap_or_else(|| PathBuf::from("."));

        let mountpoint: PathBuf = args.free_from_str()?.context("missing mountpoint")?;

        Ok(Self {
            mountpoint,
            host,
            username,
            base_dir: directory,
        })
    }
}

// ==== PathTable ====

/// Data structure that holds the correspondence between inode number and path.
struct PathTable {
    inodes: HashMap<u64, INode>,
    path_to_ino: HashMap<PathBuf, u64>,
    next_ino: u64,
}

struct INode {
    ino: u64,
    path: PathBuf,
    refcount: u64,
}

impl PathTable {
    fn new() -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(
            1,
            INode {
                ino: 1,
                path: PathBuf::new(),
                refcount: u64::MAX / 2,
            },
        );

        let mut path_to_ino = HashMap::new();
        path_to_ino.insert(PathBuf::new(), 1);

        Self {
            inodes,
            path_to_ino,
            next_ino: 2,
        }
    }

    fn get(&self, ino: u64) -> Option<&Path> {
        self.inodes.get(&ino).map(|inode| &*inode.path)
    }

    fn recognize(&mut self, path: &Path) -> &mut INode {
        match self.path_to_ino.get(path) {
            Some(&ino) => self.inodes.get_mut(&ino).expect("inode is missing"),

            None => {
                let ino = self.next_ino;
                debug_assert!(!self.inodes.contains_key(&ino));

                let inode = self.inodes.entry(ino).or_insert_with(|| INode {
                    ino,
                    path: path.to_owned(),
                    refcount: 0,
                });

                self.path_to_ino.insert(path.to_owned(), ino);
                self.next_ino = self.next_ino.wrapping_add(1);

                inode
            }
        }
    }

    fn forget(&mut self, ino: u64, nlookup: u64) {
        use std::collections::hash_map::Entry;
        if let Entry::Occupied(mut entry) = self.inodes.entry(ino) {
            let refcount = {
                let inode = entry.get_mut();
                inode.refcount = inode.refcount.saturating_sub(nlookup);
                inode.refcount
            };
            if refcount == 0 {
                drop(entry.remove());
            }
        }
    }
}

// ==== SSHFS ====

struct SSHFS {
    sftp: sftp::Session,
    base_dir: PathBuf,
    path_table: PathTable,
    dir_handles: Slab<DirHandle>,
    file_handles: Slab<sftp::FileHandle>,
}

impl SSHFS {
    async fn handle_request(&mut self, req: &Request) -> Result<()> {
        let span = tracing::debug_span!("handle_request", unique = req.unique());
        let _enter = span.enter();

        match req.operation()? {
            Operation::Lookup(op) => self.do_lookup(req, op).await?,
            Operation::Forget(forgets) => self.do_forget(forgets.as_ref()),

            Operation::Getattr(op) => self.do_getattr(req, op).await?,
            Operation::Readlink(op) => self.do_readlink(req, op).await?,

            Operation::Opendir(op) => self.do_opendir(req, op).await?,
            Operation::Readdir(op) => self.do_readdir(req, op)?,
            Operation::Releasedir(op) => self.do_releasedir(req, op)?,

            Operation::Open(op) => self.do_open(req, op).await?,
            Operation::Read(op) => self.do_read(req, op).await?,
            Operation::Write(op, data) => self.do_write(req, op, data).await?,
            Operation::Release(op) => self.do_release(req, op).await?,

            _ => req.reply_error(libc::ENOSYS)?,
        }

        Ok(())
    }

    async fn do_lookup(&mut self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("lookup", parent = op.parent(), name = ?op.name());
        let _enter = span.enter();

        let path = match self.path_table.get(op.parent()) {
            Some(parent) => parent.join(op.name()),
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(&path);
        tracing::debug!(?full_path);

        let stat = match self.sftp.lstat(&full_path).await {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        let inode = self.path_table.recognize(&path);
        inode.refcount += 1;

        let mut out = EntryOut::default();
        fill_attr(out.attr(), &stat);
        out.ttl_attr(Duration::from_secs(60));
        out.ttl_entry(Duration::from_secs(60));
        out.ino(inode.ino);
        out.attr().ino(inode.ino);

        req.reply(out)
    }

    fn do_forget(&mut self, forgets: &[op::Forget]) {
        let span = tracing::debug_span!("forget", forgets = ?forgets);
        let _enter = span.enter();

        for forget in forgets {
            tracing::debug!(ino = forget.ino(), nlookup = forget.nlookup());
            self.path_table.forget(forget.ino(), forget.nlookup());
        }
    }

    async fn do_getattr(&mut self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("getattr", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let stat = match self.sftp.lstat(&full_path).await {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        let mut out = AttrOut::default();
        fill_attr(out.attr(), &stat);
        out.attr().ino(op.ino());
        out.ttl(Duration::from_secs(60));

        req.reply(out)
    }

    async fn do_readlink(&mut self, req: &Request, op: op::Readlink<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("readlink", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let link = match self.sftp.readlink(&full_path).await {
            Ok(link) => link,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        req.reply(link)
    }

    async fn do_opendir(&mut self, req: &Request, op: op::Opendir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("opendir", ino = op.ino());
        let _enter = span.enter();

        let dirname = match self.path_table.get(op.ino()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let full_dirname = self.base_dir.join(&dirname);
        tracing::debug!(?full_dirname);

        let dir = match self.sftp.opendir(&full_dirname).await {
            Ok(dir) => dir,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        let entries: Vec<DirEntry> = match self.sftp.readdir(&dir).await {
            Ok(entries) => {
                let mut dst = vec![];
                for entry in entries {
                    if entry.filename == "." || entry.filename == ".." {
                        continue;
                    }

                    let ino = self
                        .path_table
                        .recognize(&dirname.join(&entry.filename))
                        .ino;

                    dst.push(DirEntry {
                        name: entry.filename,
                        ino,
                        typ: libc::DT_UNKNOWN as u32,
                    });
                }
                dst
            }

            Err(sftp::Error::Remote(err)) if err.code() == sftp::SSH_FX_EOF => {
                vec![]
            }

            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };
        tracing::debug!(?entries);

        match self.sftp.close(&dir).await {
            Ok(()) => (),
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        }

        let fh = self.dir_handles.insert(DirHandle { entries, offset: 0 }) as u64;

        let mut out = OpenOut::default();
        out.fh(fh);
        out.direct_io(true);

        req.reply(out)
    }

    fn do_readdir(&mut self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("readdir", ino = op.ino());
        let _enter = span.enter();

        if op.mode() == op::ReaddirMode::Plus {
            return req.reply_error(libc::ENOSYS);
        }

        let handle = match self.dir_handles.get_mut(op.fh() as usize) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        let mut out = ReaddirOut::new(op.size() as usize);
        for entry in handle.entries.iter().skip(op.offset() as usize) {
            if out.entry(&entry.name, entry.ino, entry.typ, handle.offset + 1) {
                break;
            }
            handle.offset += 1;
        }
        req.reply(out)
    }

    fn do_releasedir(&mut self, req: &Request, op: op::Releasedir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("releasedir", ino = op.ino());
        let _enter = span.enter();

        drop(self.dir_handles.remove(op.fh() as usize));
        req.reply(())
    }

    async fn do_open(&mut self, req: &Request, op: op::Open<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("open", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let pflags = match op.flags() as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => sftp::OpenFlag::READ,
            libc::O_WRONLY => sftp::OpenFlag::WRITE,
            libc::O_RDWR => sftp::OpenFlag::READ | sftp::OpenFlag::WRITE,
            _ => sftp::OpenFlag::empty(),
        };

        let handle = match self
            .sftp
            .open(&full_path, pflags, &Default::default())
            .await
        {
            Ok(file) => file,
            Err(err) => {
                tracing::error!("reply_err({:?})", err);
                return req.reply_error(sftp_error_to_errno(&err));
            }
        };

        let fh = self.file_handles.insert(handle) as u64;

        let mut out = OpenOut::default();
        out.fh(fh);

        req.reply(out)
    }

    async fn do_read(&mut self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("read", ino = op.ino(), fh = op.fh());
        let _enter = span.enter();

        let handle = match self.file_handles.get(op.fh() as usize) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        match self.sftp.read(&handle, op.offset(), op.size()).await {
            Ok(data) => req.reply(data),
            Err(err) => req.reply_error(sftp_error_to_errno(&err)),
        }
    }

    async fn do_write(
        &mut self,
        req: &Request,
        op: op::Write<'_>,
        mut data: Data<'_>,
    ) -> io::Result<()> {
        let span = tracing::debug_span!("write", ino = op.ino(), fh = op.fh());
        let _enter = span.enter();

        let handle = match self.file_handles.get(op.fh() as usize) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        let mut content = vec![];
        data.by_ref()
            .take(op.size() as u64)
            .read_to_end(&mut content)?;

        match self.sftp.write(&handle, op.offset(), &content[..]).await {
            Ok(()) => {
                let mut out = WriteOut::default();
                out.size(op.size());
                req.reply(out)
            }
            Err(err) => req.reply_error(sftp_error_to_errno(&err)),
        }
    }

    async fn do_release(&mut self, req: &Request, op: op::Release<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("release", ino = op.ino());
        let _enter = span.enter();

        let handle = self.file_handles.remove(op.fh() as usize);

        match self.sftp.close(&handle).await {
            Ok(()) => req.reply(()),
            Err(err) => req.reply_error(sftp_error_to_errno(&err)),
        }
    }
}

struct DirHandle {
    entries: Vec<DirEntry>,
    offset: u64,
}

#[derive(Debug)]
struct DirEntry {
    name: OsString,
    typ: u32,
    ino: u64,
}

fn fill_attr(attr: &mut FileAttr, st: &sftp::FileAttr) {
    attr.size(st.size.unwrap_or(0));
    attr.mode(st.permissions.unwrap_or(0));
    attr.uid(st.uid().unwrap_or(0));
    attr.gid(st.gid().unwrap_or(0));
    attr.atime(Duration::from_secs(st.atime().unwrap_or(0).into()));
    attr.mtime(Duration::from_secs(st.mtime().unwrap_or(0).into()));

    attr.nlink(1);
}

fn sftp_error_to_errno(err: &sftp::Error) -> i32 {
    match err {
        sftp::Error::Remote(err) => match err.code() {
            sftp::SSH_FX_OK => 0,
            sftp::SSH_FX_NO_SUCH_FILE => libc::ENOENT,
            sftp::SSH_FX_PERMISSION_DENIED => libc::EPERM,
            sftp::SSH_FX_OP_UNSUPPORTED => libc::ENOTSUP,
            _ => libc::EIO,
        },
        _ => libc::EIO,
    }
}

// ==== AsyncSession ====

struct AsyncSession {
    inner: AsyncFd<polyfuse::Session>,
}

impl AsyncSession {
    async fn mount(mountpoint: PathBuf, config: KernelConfig) -> io::Result<Self> {
        tokio::task::spawn_blocking(move || {
            let session = polyfuse::Session::mount(mountpoint, config)?;
            Ok(Self {
                inner: AsyncFd::with_interest(session, Interest::READABLE)?,
            })
        })
        .await
        .expect("join error")
    }

    async fn next_request(&self) -> io::Result<Option<Request>> {
        poll_fn(|cx| {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().next_request()) {
                Err(_would_block) => Poll::Pending,
                Ok(res) => Poll::Ready(res),
            }
        })
        .await
    }
}

// ==== SSH connection ====

struct Stream {
    reader: ChildStdout,
    writer: ChildStdin,
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

fn establish_connection(addr: &SocketAddr, username: &str) -> Result<(Child, Stream)> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-p")
        .arg(addr.port().to_string())
        .arg(format!("{}@{}", username, addr.ip().to_string()))
        .args(&["-s", "sftp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    tracing::debug!("spawn {:?}", cmd);
    let mut child = cmd.spawn().context("failed to spawn ssh")?;

    let stream = Stream {
        reader: child.stdout.take().expect("missing stdout pipe"),
        writer: child.stdin.take().expect("missing stdin pipe"),
    };

    Ok((child, stream))
}
