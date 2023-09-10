use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let wintun = wintun::load_from_path("wintun/bin/amd64/wintun.dll")?;

    let version = wintun::get_running_driver_version(&wintun);
    log::info!("Using wintun version: {:?}", version);

    let adapter = match wintun::Adapter::open(&wintun, "Demo") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, "Demo", "Example", None)?,
    };

    let version = wintun::get_running_driver_version(&wintun)?;
    log::info!("Using wintun version: {:?}", version);

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

    let reader_session = session.clone();
    let reader = std::thread::spawn(move || {
        while RUNNING.load(Ordering::Relaxed) {
            let packet = reader_session.receive_blocking();
            if let Err(err) = packet {
                log::info!("Error reading packet: {:?}", err);
                break;
            }
            let packet = packet?;
            let bytes = packet.bytes();
            let len = bytes.len();
            let data = &bytes[0..(20.min(bytes.len()))];
            println!("Read packet size {} bytes. Header data: {:?}", len, data);
        }
        Ok::<(), wintun::Error>(())
    });
    println!("Press enter to stop session");

    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    println!("Shutting down session");

    RUNNING.store(false, Ordering::Relaxed);
    session.shutdown();
    let _ = reader
        .join()
        .map_err(|err| wintun::Error::from(format!("{:?}", err)))?;

    println!("Shutdown complete");
    Ok(())
}
