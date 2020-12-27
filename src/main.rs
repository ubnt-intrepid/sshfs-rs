use anyhow::{ensure, Context as _, Result};
use std::{
    io::prelude::*,
    net::{SocketAddr, TcpStream},
    path::PathBuf,
};

fn main() -> Result<()> {
    let args = Args::from_env().context("Failed to parse command line arguments")?;
    dbg!(&args);

    ensure!(args.mountpoint.is_dir(), "mountpoint must be a directory");

    let stream = TcpStream::connect(&args.host).context("failed to establish TCP connection")?;

    let mut ssh2 = ssh2::Session::new().context("ssh2 is not available")?;
    ssh2.set_tcp_stream(stream);
    ssh2.handshake()
        .context("errored during performing SSH handshake")?;

    ssh2.userauth_agent(&args.username)
        .context("failed to authenticate SSH connection")?;

    let mut channel = ssh2
        .channel_session()
        .context("failed to open channel on SSH connection")?;

    println!("$ ls");
    channel.exec("ls").context("failed to exec SSH command")?;

    let mut s = String::new();
    channel
        .read_to_string(&mut s)
        .context("failed to read SSH stdout")?;
    println!("{}", s);

    channel
        .wait_close()
        .context("failed to close SSH connection")?;

    Ok(())
}

#[derive(Debug)]
struct Args {
    mountpoint: PathBuf,
    host: SocketAddr,
    username: String,
}

impl Args {
    fn from_env() -> Result<Self> {
        let mut args = pico_args::Arguments::from_env();

        let host = args
            .opt_value_from_str(["-h", "--host"])?
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 22)));

        let username = args
            .opt_value_from_str(["-u", "--user"])?
            .unwrap_or_else(|| whoami::username());

        let mountpoint: PathBuf = args.free_from_str()?.context("missing mountpoint")?;

        Ok(Self {
            mountpoint,
            host,
            username,
        })
    }
}
