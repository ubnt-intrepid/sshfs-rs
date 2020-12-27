use anyhow::{ensure, Context as _, Result};
use polyfuse::{
    op,
    reply::{AttrOut, EntryOut, FileAttr, OpenOut, ReaddirOut},
    KernelConfig, Operation, Request,
};
use slab::Slab;
use std::{
    collections::HashMap,
    ffi::OsString,
    io::{self, prelude::*},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::from_env().context("Failed to parse command line arguments")?;
    dbg!(&args);

    ensure!(args.mountpoint.is_dir(), "mountpoint must be a directory");

    let stream = TcpStream::connect(&args.host).context("failed to establish TCP connection")?;

    let mut ssh2 = ssh2::Session::new().context("ssh2 is not available")?;
    ssh2.set_tcp_stream(stream);
    ssh2.handshake()
        .context("errored during performing SSH handshake")?;

    let mut agent = ssh2.agent().context("failed to init SSH agent handle")?;
    agent.connect().context("failed to connect SSH agent")?;
    agent
        .list_identities()
        .context("failed to fetch identities from agent")?;
    let identities = agent
        .identities()
        .context("failed to get identities from SSH agent")?;
    ensure!(!identities.is_empty(), "public keys is empty");
    for identity in identities {
        if let Err(..) = agent.userauth(&args.username, &identity) {
            continue;
        }
    }
    drop(agent);
    ensure!(ssh2.authenticated(), "session is not authenticated");

    let sftp = ssh2.sftp().context("failed to open SFTP subsystem")?;

    let stat = sftp
        .lstat(&args.base_dir)
        .context("failed to get target attribute")?;
    ensure!(stat.is_dir(), "the target path is not directory");

    let fuse = polyfuse::Session::mount(args.mountpoint, {
        let mut config = KernelConfig::default();
        config.mount_option("fsname=sshfs");
        config.mount_option("default_permissions");
        config
    })
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
        .context("failed to receive FUSE request")?
    {
        sshfs
            .handle_request(&req)
            .context("failed to send FUSE reply")?;
    }

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
    sftp: ssh2::Sftp,
    base_dir: PathBuf,
    path_table: PathTable,
    dir_handles: Slab<DirHandle>,
    file_handles: Slab<FileHandle>,
}

impl SSHFS {
    fn handle_request(&mut self, req: &Request) -> Result<()> {
        let span = tracing::debug_span!("handle_request", unique = req.unique());
        let _enter = span.enter();

        match req.operation()? {
            Operation::Lookup(op) => self.do_lookup(req, op)?,
            Operation::Forget(forgets) => self.do_forget(forgets.as_ref()),

            Operation::Getattr(op) => self.do_getattr(req, op)?,
            Operation::Readlink(op) => self.do_readlink(req, op)?,

            Operation::Opendir(op) => self.do_opendir(req, op)?,
            Operation::Readdir(op) => self.do_readdir(req, op)?,
            Operation::Releasedir(op) => self.do_releasedir(req, op)?,

            Operation::Open(op) => self.do_open(req, op)?,
            Operation::Read(op) => self.do_read(req, op)?,
            Operation::Release(op) => self.do_release(req, op)?,

            _ => req.reply_error(libc::ENOSYS)?,
        }

        Ok(())
    }

    fn do_lookup(&mut self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("lookup", parent = op.parent(), name = ?op.name());
        let _enter = span.enter();

        let path = match self.path_table.get(op.parent()) {
            Some(parent) => parent.join(op.name()),
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(&path);
        tracing::debug!(?full_path);

        let stat = match self.sftp.lstat(&full_path) {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(ssh2_error_code(&err)),
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

    fn do_getattr(&mut self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("getattr", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let stat = match self.sftp.lstat(&full_path) {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(ssh2_error_code(&err)),
        };

        let mut out = AttrOut::default();
        fill_attr(out.attr(), &stat);
        out.attr().ino(op.ino());
        out.ttl(Duration::from_secs(60));

        req.reply(out)
    }

    fn do_readlink(&mut self, req: &Request, op: op::Readlink<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("readlink", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let link = match self.sftp.readlink(&full_path) {
            Ok(link) => link,
            Err(err) => return req.reply_error(ssh2_error_code(&err)),
        };

        req.reply(link.into_os_string())
    }

    fn do_opendir(&mut self, req: &Request, op: op::Opendir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("opendir", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let entries: Vec<DirEntry> = match self.sftp.readdir(&full_path) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(path, stat)| {
                    let name = path.file_name()?;
                    let inode = self.path_table.recognize(&path.join(name));
                    let typ = match stat.file_type() {
                        ft if ft.is_dir() => libc::DT_DIR as u32,
                        ft if ft.is_file() => libc::DT_REG as u32,
                        ft if ft.is_symlink() => libc::DT_LNK as u32,
                        _ => libc::DT_UNKNOWN as u32,
                    };
                    Some(DirEntry {
                        name: name.to_owned(),
                        typ,
                        ino: inode.ino,
                    })
                })
                .collect(),
            Err(err) => return req.reply_error(ssh2_error_code(&err)),
        };
        tracing::debug!(?entries);

        let fh = self.dir_handles.insert(DirHandle { entries, offset: 0 }) as u64;

        let mut out = OpenOut::default();
        out.fh(fh);

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

    fn do_open(&mut self, req: &Request, op: op::Open<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("open", ino = op.ino());
        let _enter = span.enter();

        if op.flags() as i32 & libc::O_ACCMODE != libc::O_RDONLY {
            return req.reply_error(libc::EACCES);
        }

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let mut file =
            match self
                .sftp
                .open_mode(&full_path, ssh2::OpenFlags::READ, 0, ssh2::OpenType::File)
            {
                Ok(file) => file,
                Err(err) => return req.reply_error(ssh2_error_code(&err)),
            };

        // Receive the whole content at here for simplify read operation.
        let mut content = vec![];
        if let Err(err) = file.read_to_end(&mut content) {
            return req.reply_error(err.raw_os_error().unwrap_or(libc::EIO));
        }

        let fh = self.file_handles.insert(FileHandle { content }) as u64;

        let mut out = OpenOut::default();
        out.fh(fh);

        req.reply(out)
    }

    fn do_read(&mut self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("open", ino = op.ino());
        let _enter = span.enter();

        let offset = op.offset() as usize;
        let size = op.size() as usize;

        let handle = match self.file_handles.get_mut(op.fh() as usize) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        let content = handle.content.get(offset..).unwrap_or(&[]);
        let content = &content[..std::cmp::min(content.len(), size)];

        req.reply(content)
    }

    fn do_release(&mut self, req: &Request, op: op::Release<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("release", ino = op.ino());
        let _enter = span.enter();

        drop(self.file_handles.remove(op.fh() as usize));
        req.reply(())
    }
}

fn fill_attr(attr: &mut FileAttr, st: &ssh2::FileStat) {
    attr.size(st.size.unwrap_or(0));
    attr.mode(st.perm.unwrap_or(0));
    attr.uid(st.uid.unwrap_or(0));
    attr.gid(st.gid.unwrap_or(0));
    attr.atime(Duration::from_secs(st.atime.unwrap_or(0)));
    attr.mtime(Duration::from_secs(st.mtime.unwrap_or(0)));

    attr.nlink(1);
}

fn ssh2_error_code(err: &ssh2::Error) -> i32 {
    use libssh2_sys as raw;
    use ssh2::ErrorCode;

    match err.code() {
        ErrorCode::SFTP(raw::LIBSSH2_FX_NO_SUCH_FILE) => libc::ENOENT,
        ErrorCode::SFTP(raw::LIBSSH2_FX_PERMISSION_DENIED) => libc::EPERM,
        ErrorCode::SFTP(raw::LIBSSH2_FX_OP_UNSUPPORTED) => libc::ENOTSUP,
        ErrorCode::SFTP(raw::LIBSSH2_FX_NO_SUCH_PATH) => libc::ENOENT,
        ErrorCode::SFTP(raw::LIBSSH2_FX_FILE_ALREADY_EXISTS) => libc::EEXIST,
        ErrorCode::SFTP(raw::LIBSSH2_FX_DIR_NOT_EMPTY) => libc::ENOTEMPTY,
        ErrorCode::SFTP(raw::LIBSSH2_FX_NOT_A_DIRECTORY) => libc::ENOTDIR,
        ErrorCode::SFTP(raw::LIBSSH2_FX_INVALID_FILENAME) => libc::EINVAL,
        _ => libc::EIO,
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

struct FileHandle {
    content: Vec<u8>,
}
