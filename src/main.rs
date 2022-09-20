#![feature(seek_stream_len)]

fn main() {
    let result = mcping("mc.hypixel.net");
    dbg!(&result);
}

fn convert_i32_to_varint(mut n: i32) -> Vec<u8> {
    let mut varint = Vec::with_capacity(5);

    for i in 0.. {
        assert!(i < 5);

        if (n as u32) & 0xFFFFFF80 == 0 {
            varint.push(n as u8);
            break;
        }

        varint.push((n & 0x7F | 0x80) as u8);
        n >>= 7;
    }

    varint
}

fn convert_varint_to_i32(r: &mut impl std::io::Read) -> i32 {
    let mut i32 = 0;

    for i in 0.. {
        assert!(i < 5);

        let mut arr = [0; 1];
        r.read_exact(&mut arr).unwrap();
        let [f] = arr;

        if f & 0x80 == 0 {
            i32 |= (f as i32) << (i * 7);
            break;
        }

        i32 |= ((f & 0x7F) as i32) << (i * 7);
    }

    i32
}

fn resolve_domain(host: &str) -> std::net::IpAddr {
    #[rustfmt::skip]
    // want to use https://adguard-dns.io/en/public-dns.html (DoQ) but gave up
    // see https://github.com/bluejekyll/trust-dns/issues/1687
    //
    // let ns_configs = [
    //     "94.140.14.14",
    //     "94.140.15.15",
    //     "2a10:50c0::ad1:ff",
    //     "2a10:50c0::ad2:ff",
    // ]
    // .into_iter()
    // .map(core::str::FromStr::from_str)
    // .map(Result::unwrap)
    // .map(
    //     |addr: std::net::IpAddr| trust_dns_resolver::config::NameServerConfig {
    //         socket_addr: (addr, 784).into(),
    //         protocol: trust_dns_resolver::config::Protocol::Quic,
    //         tls_dns_name: Some("dns.adguard-dns.com".to_string()),
    //         trust_nx_responses: true,
    //         tls_config: None,
    //         bind_addr: None,
    //     },
    // )
    // .collect::<Vec<_>>();
    // let config =
    //     trust_dns_resolver::config::ResolverConfig::from_parts(None, Vec::new(), ns_configs);

    let config = trust_dns_resolver::config::ResolverConfig::cloudflare_tls();
    let mut options = trust_dns_resolver::config::ResolverOpts::default();
    options.validate = true;

    let resolver = trust_dns_resolver::Resolver::new(config, options).unwrap();
    resolver.lookup_ip(host).unwrap().iter().next().unwrap()
}

fn resolve_address(str: &str) -> std::net::SocketAddr {
    let (host, port) = if let Some((before, after)) = str.split_once(':') {
        (before, after.parse().unwrap())
    } else {
        (str, 25565)
    };

    let ip = if let Ok(ip) = host.parse() {
        ip
    } else {
        resolve_domain(str)
    };

    (ip, port).into()
}

fn mcping(target: &str) -> Result<Response, Error> {
    let addr = resolve_address(target);
    let mut stream = std::net::TcpStream::connect(addr).unwrap();

    use std::io::{Read, Seek, Write};

    // make buffer
    let mut pending = std::io::Cursor::new(Vec::new());

    // write as VarInt for "Packet ID"
    let data = convert_i32_to_varint(0x00);
    pending.write_all(&data).unwrap();

    // write VarInt for "Protocol Version"
    let data = convert_i32_to_varint(760);
    pending.write_all(&data).unwrap();

    // write as VarInt for "Server Address"'s String length
    let data = convert_i32_to_varint(14);
    pending.write_all(&data).unwrap();

    // write as String for "Server Address"
    let data = "mc.hypixel.net".as_bytes();
    pending.write_all(data).unwrap();

    // write as Unsigned Short for "Server Port"
    let data = u16::to_be_bytes(25565);
    pending.write_all(&data).unwrap();

    // write "1" as VarInt for "Next state"
    let data = convert_i32_to_varint(1);
    pending.write_all(&data).unwrap();

    // send
    let len = pending.stream_len().unwrap();
    let len = convert_i32_to_varint(len as i32);
    stream.write_all(&len).unwrap();
    stream.write_all(pending.get_ref()).unwrap();
    stream.flush().unwrap();

    // make buffer
    let mut pending = std::io::Cursor::new(Vec::new());

    // write VarInt for "Packet ID"
    let data = convert_i32_to_varint(0x00);
    pending.write_all(&data).unwrap();

    // send
    let len = pending.stream_len().unwrap();
    let len = convert_i32_to_varint(len as i32);
    stream.write_all(&len).unwrap();
    stream.write_all(pending.get_ref()).unwrap();
    stream.flush().unwrap();

    // read as VarInt for "Length"
    let data = convert_varint_to_i32(&mut stream);
    eprintln!("receiving {data} bytes...");

    // read "0x00" as VarInt for "Packet ID"
    let data = convert_varint_to_i32(&mut stream);
    assert_eq!(data, 0b0000_0000);

    // read as VarInt for "JSON Response"'s String length
    let len = convert_varint_to_i32(&mut stream);

    // read as String for "JSON Response"
    let mut data = Vec::new();
    data.resize(len as usize, 0);
    stream.read_exact(&mut data).unwrap();
    let data = core::str::from_utf8(&data).unwrap();

    eprintln!("received: {data}");

    let data = serde_json::from_str::<'_, Response>(data).unwrap();

    stream.shutdown(std::net::Shutdown::Both).unwrap();

    Ok(data)
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    version: Version,
    players: Players,
    description: Chat,
    favicon: Option<String>, // FIXME: replace `String` to `Favicon`
    previews_chat: Option<bool>,
    enforces_secure_chat: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Version {
    name: String,
    protocol: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct Players {
    max: u32,
    online: u32,
    sample: Option<Vec<User>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    name: String,
    id: uuid::Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Chat {
    String(String),
}

#[derive(Debug)]
struct Favicon {
    mime: mime::Mime,
    image: Vec<u8>,
}

#[derive(Debug)]
enum Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "{:?}", self) }
}

impl std::error::Error for Error {}
