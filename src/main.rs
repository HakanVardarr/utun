use tracing::info;
use utun::Utun;
use utun::engine::Dispatcher;

use utun::services::UdpKvService;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let mut utun = Utun::new()?;
    utun.configure("10.0.0.1", "10.0.0.2")?;

    let mut kv = UdpKvService::default();
    let mut dispatcher = Dispatcher::default();
    dispatcher.udp_bind(9000, move |ip, udp| kv.handle(ip, udp));

    let mut buf = [0u8; 2048];
    loop {
        let n = utun.read_packet(&mut buf)?;
        if let Some(reply) = dispatcher.handle_packet(&buf[..n]) {
            info!("{:?}", reply);
            utun.write_packet(&reply)?;
        }
    }
}
