//! Regression test (Amperstrand fork): full sunset client↔server session
//! over a real async transport (tokio duplex), exercising the negotiated
//! KEX — including mlkem768x25519-sha256 when default features are on.
//!
//! Reproduces the conwrt #112 spike finding: an in-memory hello-exec
//! session failed with `BadKex` server-side when mlkem was negotiated.
//! This copy uses tokio's duplex (a known-good transport) so any failure
//! here indicts the async SSH layer itself, not a hand-rolled transport.

use sunset::*;
use sunset_async::embedded_io_async::{Read, Write};
use sunset_async::{ChanInOut, ProgressHolder, SSHClient, SSHServer};

type Res<T> = std::result::Result<T, sunset::Error>;

enum CliAct {
    None,
    Open,
    Launch,
}

enum ServAct {
    None,
    Exec,
    Done,
}

/// Client side: trust hostkey, auth spike/pw, exec "hello", read payload.
async fn client_session(cli: &SSHClient<'_>) -> Res<bool> {
    let (io_tx, mut io_rx) = tokio::sync::mpsc::channel::<ChanInOut<'_>>(1);
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);

    let ev_loop = async {
        let mut io_ready: Option<ChanInOut<'_>> = None;
        loop {
            let act = {
                let mut ph = ProgressHolder::new();
                let ev = cli.progress(&mut ph).await?;
                match ev {
                    CliEvent::Hostkey(h) => {
                        h.accept()?;
                        CliAct::None
                    }
                    CliEvent::Username(u) => {
                        u.username("spike")?;
                        CliAct::None
                    }
                    CliEvent::Password(p) => {
                        p.password("pw")?;
                        CliAct::None
                    }
                    CliEvent::Pubkey(p) => {
                        p.skip()?;
                        CliAct::None
                    }
                    CliEvent::AgentSign(k) => {
                        k.skip()?;
                        CliAct::None
                    }
                    CliEvent::Authenticated => CliAct::Open,
                    CliEvent::SessionOpened(mut opener) => {
                        opener.exec("hello")?;
                        CliAct::Launch
                    }
                    CliEvent::SessionExit(_) => CliAct::None,
                    CliEvent::Defunct => break,
                    _ => CliAct::None,
                }
            };
            match act {
                CliAct::Open => {
                    let (io, _stderr) = cli.open_session_nopty().await?;
                    io_ready = Some(io);
                }
                CliAct::Launch => {
                    if let Some(io) = io_ready.take() {
                        io_tx.send(io).await.unwrap();
                    }
                }
                CliAct::None => (),
            }
        }
        Ok::<_, sunset::Error>(())
    };

    let pump = async {
        let mut io = io_rx.recv().await.unwrap();
        let mut collected = Vec::new();
        let mut buf = [0u8; 32];
        loop {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    collected.extend_from_slice(&buf[..n]);
                    if collected == b"hello\n" {
                        break;
                    }
                }
            }
        }
        let _ = done_tx.send(collected).await;
    };

    // Race: the pump finishing (exact payload match) completes the client
    // session; the event loop is dropped mid-progress. A server-first
    // result here means the server errored (e.g. the BadKex repro).
    let collected = tokio::select! {
        r = ev_loop => {
            r?;
            done_rx.try_recv().unwrap_or_default()
        }
        _ = pump => done_rx.try_recv().unwrap_or_default(),
    };
    Ok(collected == b"hello\n")
}

/// Server side: ed25519 hostkey, password auth, exec "hello" → "hello\n".
async fn server_session(serv: &SSHServer<'_>) -> Res<()> {
    let hostkey = SignKey::generate(KeyType::Ed25519, None)?;
    let mut chan: Option<ChanHandle> = None;

    loop {
        let act = {
            let mut ph = ProgressHolder::new();
            let ev = serv.progress(&mut ph).await?;
            match ev {
                ServEvent::Hostkeys(h) => {
                    h.hostkeys(&[&hostkey])?;
                    ServAct::None
                }
                ServEvent::FirstAuth(mut a) => {
                    a.enable_password_auth(true)?;
                    ServAct::None
                }
                ServEvent::PasswordAuth(a) => {
                    if a.username()? == "spike" && a.password()? == "pw" {
                        a.allow()?;
                    }
                    ServAct::None
                }
                ServEvent::Authenticated => ServAct::None,
                ServEvent::OpenSession(a) => {
                    chan = Some(a.accept()?);
                    ServAct::None
                }
                ServEvent::SessionExec(a) => {
                    if a.command()? == "hello" {
                        a.succeed()?;
                        ServAct::Exec
                    } else {
                        a.fail()?;
                        ServAct::None
                    }
                }
                ServEvent::Defunct => ServAct::Done,
                _ => ServAct::None,
            }
        };
        match act {
            ServAct::Exec => {
                if let Some(ch) = chan.take() {
                    let mut io = serv.stdio(ch).await?;
                    io.write_all(b"hello\n").await?;
                }
                // keep polling: sunset flushes the channel close from
                // inside progress() only
            }
            ServAct::Done => break,
            ServAct::None => (),
        }
    }
    Ok(())
}

#[tokio::test]
async fn hello_exec_duplex() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();
    // Fail fast instead of hanging on any regression.
    tokio::time::timeout(std::time::Duration::from_secs(30), hello_exec_duplex_inner())
        .await
        .expect("session timed out (regression?)");
}

async fn hello_exec_duplex_inner() {
    // 8 KiB duplex (SSH max packet headroom)
    let (a, b) = tokio::io::duplex(8 * 1024);

    let (mut ard, mut awr) = tokio::io::split(a);
    let (mut brd, mut bwr) = tokio::io::split(b);

    let mut cli_rxbuf = [0u8; 2000];
    let mut cli_txbuf = [0u8; 2000];
    let cli = SSHClient::new(&mut cli_rxbuf, &mut cli_txbuf);

    let mut serv_rxbuf = [0u8; 2000];
    let mut serv_txbuf = [0u8; 2000];
    let serv = SSHServer::new(&mut serv_rxbuf, &mut serv_txbuf);

    let cli_run = cli.run_tokio(&mut ard, &mut awr);
    let serv_run = serv.run_tokio(&mut brd, &mut bwr);

    let cli_sess = client_session(&cli);
    let serv_sess = server_session(&serv);

    // Transports MUST be polled concurrently with the sessions (the
    // session futures only pump SSH state through them).
    let transports = async { tokio::join!(cli_run, serv_run) };
    tokio::pin!(transports);

    // Race the sessions (conwrt-harness semantics): a server-first result
    // means the server errored — surface it immediately.
    let (cli_res, serv_res): (Res<bool>, Res<()>) = tokio::select! {
        r = cli_sess => {
            eprintln!("CLIENT finished first: {r:?}");
            (r, Ok(()))
        }
        r = serv_sess => {
            eprintln!("SERVER finished first: {r:?}");
            (Ok(false), r)
        }
        _ = &mut transports => {
            panic!("transports ended before the sessions (link break)");
        }
    };
    eprintln!("client session: {cli_res:?}");
    eprintln!("server session: {serv_res:?}");
    assert!(serv_res.is_ok(), "server session failed: {serv_res:?}");
    assert!(cli_res.unwrap(), "client did not receive hello payload");
}
