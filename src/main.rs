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

fn resolve_address(str: &str) -> std::net::SocketAddr {
    let (host, port) = if let Some((before, after)) = str.split_once(':') {
        (before, after.parse().unwrap())
    } else {
        (str, 25565)
    };

    let ip = if let Ok(ip) = host.parse() {
        ip
    } else {
        let config = trust_dns_resolver::config::ResolverConfig::cloudflare_tls();
        let options = trust_dns_resolver::config::ResolverOpts::default();

        let resolver = trust_dns_resolver::Resolver::new(config, options).unwrap();
        resolver.lookup_ip(str).unwrap().iter().next().unwrap()
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

    // print "JSON Response"
    println!("{data}");

    stream.shutdown(std::net::Shutdown::Both).unwrap();

    unimplemented!();
}

#[derive(Debug)]
struct Response {}

#[derive(Debug)]
enum Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "{:?}", self) }
}

impl std::error::Error for Error {}
