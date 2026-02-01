use utun::Utun;
use utun::engine::Dispatcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let mut utun = Utun::new()?;
    utun.configure("10.0.0.1", "10.0.0.2")?;

    let mut dispatcher = Dispatcher::default();
    let mut buf = [0u8; 2048];
    loop {
        let n = utun.read_packet(&mut buf)?;
        if let Some(reply) = dispatcher.handle_packet(&buf[..n]) {
            utun.write_packet(&reply)?;
        }
    }
}
