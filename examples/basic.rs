use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() {
    //Load the wintun dll file so that we can call the underlying C functions
    let wintun = wintun::load_from_path("examples/wintun/bin/amd64/wintun.dll")
        .expect("Failed to load wintun dll");
    //Try to load an adapter from the given pool with the name "Demo"
    let adapter = match wintun::Adapter::open(&wintun, "Example", "Demo") {
        Ok(a) => a,
        Err(_) =>
        //If loading failed (most likely it didn't exist), create a new one
        {
            wintun::Adapter::create(&wintun, "Example", "Demo", None)
                .expect("Failed to create wintun adapter!")
                .adapter
        }
    };
    //Specify the size of the ring buffer the wintun driver should use.
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());

    let reader_session = session.clone();
    let reader = std::thread::spawn(move || {
        while RUNNING.load(Ordering::Relaxed) {
            match reader_session.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.as_ref();
                    println!(
                        "Read packet size {} bytes. Header data: {:?}",
                        bytes.len(),
                        &bytes[0..20.min(bytes.len())]
                    );
                }
                Err(_) => println!("Got error while reading packet"),
            }
        }
    });
    println!("Press enter to stop session");

    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    println!("Shutting down session");

    RUNNING.store(false, Ordering::Relaxed);
    session.shutdown();
    let _ = reader.join();

    println!("Shutdown complete");
}
