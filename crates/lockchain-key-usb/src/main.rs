#[cfg(target_os = "linux")]
mod linux;

#[cfg(any(test, target_os = "linux"))]
mod mounts;

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("lockchain-key-usb is only supported on Linux hosts.");
    std::process::exit(1);
}
