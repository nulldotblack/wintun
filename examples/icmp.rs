/// Semi port of WinTun's c example: https://git.zx2c4.com/wintun/tree/example/example.c
use wintun;

use log::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() {
    env_logger::init();

    let wintun = wintun::load_from_path("examples/wintun/bin/amd64/wintun.dll")
        .expect("Failed to load wintun dll");

    let adapter = match wintun::Adapter::open(&wintun, "Example", "Demo") {
        Ok(a) => {
            info!("Opened adapter successfully");
            a
        },
        Err(_) => {
            match wintun::Adapter::create(&wintun, "Example", "Demo", None) {
                Ok(a) => {
                    info!("Created adapter successfully! Should reboot: {}", a.reboot_required);
                    a.adapter
                },
                Err(err) => panic!("Failed to open adapter and failed to create adapter. Is process running as admin? Error: {}", err),
            }
        }
    };
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .expect("Failed to create session"),
    );

    let reader = std::thread::spawn(move || {
        info!("Starting reader");
        while RUNNING.load(Ordering::Relaxed) {
            match session.receive_blocking() {
                Ok(packet) => {}
                Err(err) => {
                    error!("Got error while reading");
                }
            }
        }
    });
    let writer = std::thread::spawn(move || {
        info!("Starting writer");


        while RUNNING.load(Ordering::Relaxed) {

        }
    });


    reader.join().unwrap();
    writer.join().unwrap();

    info!("Crated session successfully!");
}
