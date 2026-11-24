use anyhow::{Result, ensure};
use lp2ln_core_v2::{
    PeerId,
    db::P2PDatabase,
    flow::Flow,
    node::{NodeBuilder, NodeOptions, NodeRuntime},
    storage::hash_bytes,
    transport::quic::{QuicTransport, QuicTransportOptions},
};
use lp2ln_rtc::{Capture, FRAME, PROTOCOL, Playout, Signal, exchange};
use std::path::Path;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

async fn node(path: &Path) -> Result<NodeRuntime> {
    let mut options = NodeOptions::empty()
        .allow_unsigned_packets(false)
        .with_listen("quic", "127.0.0.1:0".parse()?);
    options.enable_topology_maintenance = false;
    options.experimental.content = true;
    options.database_dir = Some(path.into());
    options.lan_discovery.enabled = false;
    let mut n = NodeBuilder::new()
        .db(Arc::new(P2PDatabase::new(path.to_str().unwrap())?))
        .add_transport(Arc::new(QuicTransport::new_listener(
            None,
            QuicTransportOptions {
                enable_realtime_flows: true,
                ..Default::default()
            },
        )))
        .build(options)?;
    n.start().await?;
    Ok(n)
}

async fn signal(a: &Flow, b: &Flow, x: Signal, y: Signal) -> Result<()> {
    let (ca, cb) = (a.control(), b.control());
    let (ra, rb) = tokio::try_join!(exchange(&ca, a.id(), x), exchange(&cb, b.id(), y))?;
    ensure!(ra == y && rb == x, "incorrect authenticated control");
    Ok(())
}

async fn audio(rx: &mut Flow, hz: f32) -> Result<u64> {
    let mut capture = Capture::new()?;
    let mut play = Playout::new()?;
    let tx = rx.sender();
    let mut timer = tokio::time::interval(Duration::from_millis(20));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut output = [0; FRAME];
    let mut frames = 0;
    let mut audible = 0;
    while frames < 150 {
        tokio::select! {
            biased;
            _=timer.tick()=>{
                let pcm=std::array::from_fn(|i| ((i+frames*FRAME) as f32*hz*std::f32::consts::TAU/48000.).sin());
                capture.offer(&tx,&pcm.map(|s|(s*9000.) as i16),Instant::now())?;
                play.render(Instant::now(),&mut output)?;
                audible+=usize::from(output.iter().any(|s|s.unsigned_abs()>1000));
                frames+=1;
            }
            packet=rx.recv_with_deadline()=>{let (packet, deadline)=packet?;play.push(&packet,Instant::now(),deadline)?;}
        }
    }
    ensure!(audible > 125, "audible frames {audible}");
    Ok(play.stats().played)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn two_way_opus_with_durable_file_and_epoch_change() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(40), async {
        let root = tempfile::tempdir()?;
        let a = node(&root.path().join("a")).await?;
        let b = node(&root.path().join("b")).await?;
        let addr = loop {
            if let Some(addr) = b.bound_transport_addr("quic") {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let peer = PeerId::from(b.peer_id());
        b.authorize_realtime_peer(&PeerId::from(a.peer_id()), PROTOCOL)?;
        let (mut x, mut y) = tokio::try_join!(
            a.open_realtime_flow(&peer, addr, PROTOCOL),
            b.accept_realtime_flow()
        )?;
        signal(&x, &y, Signal::Invite, Signal::Ringing).await?;
        signal(&x, &y, Signal::Invite, Signal::Accept).await?;
        signal(&x, &y, Signal::Active, Signal::Accept).await?;
        let ctrl = x.control();
        a.connect("quic", addr).await?;
        let transfer = async {
            while a.active_peer_count() == 0 || b.active_peer_count() == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let source = a.block_transfer_service().unwrap();
            let destination = b.block_transfer_service().unwrap();
            let source_path = root.path().join("source.bin");
            let result_path = root.path().join("download.bin");
            let data: Vec<u8> = (0..4 * 1024 * 1024usize)
                .map(|i| (i ^ (i >> 16)) as u8)
                .collect();
            std::fs::write(&source_path, &data)?;
            let mut downloaded = std::fs::File::create(&result_path)?;
            for block in std::fs::read(&source_path)?.chunks(64 * 1024) {
                let id = source.store.put(block)?;
                let result = destination.fetch_from(a.peer_id(), id).await?;
                ensure!(destination.store.put(&result)? == id);
                std::io::Write::write_all(&mut downloaded, &result)?;
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            downloaded.sync_all()?;
            ensure!(hash_bytes(&data) == hash_bytes(&std::fs::read(result_path)?));
            Ok::<(), anyhow::Error>(())
        };
        let rotate = async {
            tokio::time::sleep(Duration::from_millis(900)).await;
            ctrl.rotate_keys().await
        };
        let (ax, ay, (), ()) =
            tokio::try_join!(audio(&mut x, 440.), audio(&mut y, 660.), transfer, rotate)?;
        signal(&x, &y, Signal::Hangup, Signal::Active).await?;
        eprintln!("Opus played {ax}/{ay} frames; 4194304 file bytes verified");
        drop((x, y));
        a.stop().await?;
        b.stop().await?;
        Ok(())
    })
    .await?
}
