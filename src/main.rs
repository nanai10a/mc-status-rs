#![feature(iter_intersperse)]

fn main() {
    let args = Args::parse();

    let res = process(&args.target).unwrap();

    println!("{res}");
}

use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    target: String,
}

fn convert_i32_to_varint(n: i32) -> Vec<u8> {
    let mut n = n as u32;
    let mut varint = Vec::with_capacity(5);

    for i in 0.. {
        assert!(i < 5);

        if n & 0xFFFFFF80 == 0 {
            varint.push(n as u8);
            break;
        }

        varint.push((n & 0x7F | 0x80) as u8);
        n >>= 7;
    }

    varint
}

#[test]
#[rustfmt::skip]
fn test_i32_to_varint() {
    // cases from https://wiki.vg/Protocol#VarInt_and_VarLong

    assert_eq!(convert_i32_to_varint( 0         ), vec![0x00                        ]);
    assert_eq!(convert_i32_to_varint( 1         ), vec![0x01                        ]);
    assert_eq!(convert_i32_to_varint( 2         ), vec![0x02                        ]);
    assert_eq!(convert_i32_to_varint( 127       ), vec![0x7F                        ]);
    assert_eq!(convert_i32_to_varint( 128       ), vec![0x80, 0x01                  ]);
    assert_eq!(convert_i32_to_varint( 255       ), vec![0xFF, 0x01                  ]);
    assert_eq!(convert_i32_to_varint( 25565     ), vec![0xDD, 0xC7, 0x01            ]);
    assert_eq!(convert_i32_to_varint( 2097151   ), vec![0xFF, 0xFF, 0x7F            ]);
    assert_eq!(convert_i32_to_varint( 2147483647), vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07]);
    assert_eq!(convert_i32_to_varint(-1         ), vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
    assert_eq!(convert_i32_to_varint(-2147483648), vec![0x80, 0x80, 0x80, 0x80, 0x08]);
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

#[test]
#[rustfmt::skip]
fn test_varint_to_i32() {
    // cases from https://wiki.vg/Protocol#VarInt_and_VarLong

    use std::io::Cursor;

    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0x00                        ])),  0         );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0x01                        ])),  1         );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0x02                        ])),  2         );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0x7F                        ])),  127       );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0x80, 0x01                  ])),  128       );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0xFF, 0x01                  ])),  255       );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0xDD, 0xC7, 0x01            ])),  25565     );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0xFF, 0xFF, 0x7F            ])),  2097151   );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07])),  2147483647);
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F])), -1         );
    assert_eq!(convert_varint_to_i32(&mut Cursor::new(vec![0x80, 0x80, 0x80, 0x80, 0x08])), -2147483648);
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

fn process(target: &str) -> Result<Response, Error> {
    let addr = resolve_address(target);
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();

    use std::io::{Read, Seek, Write};

    // make buffer
    let mut pending = std::io::Cursor::new(Vec::new());

    // write as VarInt for "Packet ID"
    let data = convert_i32_to_varint(0x00);
    pending.write_all(&data).unwrap();

    // write VarInt for "Protocol Version"
    let data = convert_i32_to_varint(-1);
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
    let len = pending.get_ref().len();
    let len = convert_i32_to_varint(len as i32);
    stream.write_all(&len).unwrap();
    stream.write_all(pending.get_ref()).unwrap();

    // make buffer
    let mut pending = std::io::Cursor::new(Vec::new());

    // write VarInt for "Packet ID"
    let data = convert_i32_to_varint(0x00);
    pending.write_all(&data).unwrap();

    // send
    let len = pending.get_ref().len();
    let len = convert_i32_to_varint(len as i32);
    stream.write_all(&len).unwrap();
    stream.write_all(pending.get_ref()).unwrap();

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

    let res = serde_json::from_str::<'_, Response>(data).unwrap();

    // make buffer
    let mut pending = std::io::Cursor::new(Vec::new());

    // write VarInt for "Packet ID"
    let data = convert_i32_to_varint(0x01);
    pending.write_all(&data).unwrap();

    // write Long for "Payload"
    let payload = 771;
    let data = i64::to_be_bytes(payload);
    pending.write_all(&data).unwrap();

    // send
    let len = pending.get_ref().len();
    let len = convert_i32_to_varint(len as i32);
    stream.write_all(&len).unwrap();
    stream.write_all(pending.get_ref()).unwrap();
    let sent_time = std::time::Instant::now();

    // read as VarInt for "Length"
    let data = convert_varint_to_i32(&mut stream);
    eprintln!("receiving {data} bytes...");

    // read "0x01" as VarInt for "Packet ID"
    let data = convert_varint_to_i32(&mut stream);
    assert_eq!(data, 0b0000_0001);

    // read as Long for "Payload"
    let mut data = [0; 8];
    stream.read_exact(&mut data).unwrap();
    let data = i64::from_be_bytes(data);
    assert_eq!(data, payload);
    eprintln!("pong ({} ms)", sent_time.elapsed().as_millis());

    stream.shutdown(std::net::Shutdown::Both).unwrap();

    Ok(res)
}

impl core::fmt::Display for Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use colored::Colorize;

        writeln!(f, "{}", self.description)?;
        writeln!(f)?;

        writeln!(
            f,
            "{} (protocol ver. {})",
            self.version.name.cyan(),
            self.version.protocol.to_string().magenta()
        )?;

        let players =
            if self.players.sample.is_none() || self.players.sample.as_ref().unwrap().is_empty() {
                "*nothing to show*".dimmed().to_string()
            } else if self.players.sample.as_ref().unwrap().len() <= 3 {
                self.players
                    .sample
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|s| s.name.as_str())
                    .intersperse(", ")
                    .collect::<String>()
            } else {
                let mut ps = self
                    .players
                    .sample
                    .as_ref()
                    .unwrap()
                    .iter()
                    .take(3)
                    .map(|s| s.name.as_str())
                    .intersperse(", ")
                    .collect::<String>();
                ps.push_str(", etc");

                ps
            };

        writeln!(
            f,
            "{players} are participating now ({} / {} players)",
            self.players.online, self.players.max
        )?;

        writeln!(f)?;

        let fv = match self.favicon {
            Some(_) => "found".green(),
            None => "none".dimmed(),
        };

        let cp = match self.previews_chat {
            Some(true) => "available".green(),
            Some(false) => "unavailable".red(),
            None => "unsupported".dimmed(),
        };

        let esc = match self.enforces_secure_chat {
            Some(true) => "yes".green().to_string(),
            Some(false) => "no".red().to_string(),
            None => "unsupported".dimmed().to_string(),
        };

        writeln!(f, "  favicon             - {fv}")?;
        writeln!(f, "  chat preview        - {cp}")?;
        writeln!(f, "  enforce secure chat - {esc}")?;

        writeln!(f)?;

        write!(f, "  modding - ")?;
        if let Some(mi) = &self.mod_info {
            writeln!(f, "found")?;
            writeln!(f, "  type    - {}", mi.ty)?;
            writeln!(f, "  mods    - {} installed", mi.mod_list.len())
        } else {
            writeln!(f, "none")
        }
    }
}

impl core::fmt::Display for Chat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Old(s) =>
                if let Some((before, after)) = s.split_once('\n') {
                    let (ord, delta) = {
                        let esc = regex::Regex::new("§.").unwrap();

                        let before = esc.replace_all(before, "");
                        let after = esc.replace_all(after, "");

                        let ord = before.len().cmp(&after.len());
                        let delta = (before.len() as isize - after.len() as isize).abs() as usize;

                        (ord, delta)
                    };

                    let pad = " ".repeat(delta / 2);

                    use core::cmp::Ordering::*;
                    match ord {
                        Less => {
                            writeln!(f, "{}", format_old_text(before.to_string()))?;
                            write!(f, "{pad}{}{pad}", format_old_text(after.to_string()))
                        },

                        Equal => {
                            writeln!(f, "{}", format_old_text(before.to_string()))?;
                            write!(f, "{}", format_old_text(after.to_string()))
                        },
                        Greater => {
                            writeln!(f, "{pad}{}{pad}", format_old_text(before.to_string()))?;
                            write!(f, "{}", format_old_text(after.to_string()))
                        },
                    }
                } else {
                    write!(f, "{}", format_old_text(s.to_string()))
                },
            Self::New { extra, text } => {
                if extra.is_none() && text.find('§').is_some() {
                    return Self::Old(text.to_string()).fmt(f);
                }

                todo!()
            },
        }
    }
}

fn format_old_text(mut s: String) -> String {
    let mut buf = termcolor::Buffer::ansi();

    use std::io::Write;

    use termcolor::{ColorSpec, WriteColor};

    macro_rules! color {
        (color $fg:expr) => {{
            let mut c = ColorSpec::new();
            c.set_fg(Some($fg.parse().unwrap()));
            c
        }};
        (style $style:ident) => {{
            let mut c = ColorSpec::new();
            c.$style(true);
            c
        }};
    }

    loop {
        if let Some((before, after)) = s.split_once('§') {
            buf.write_all(before.as_bytes()).unwrap();

            let code = after.chars().next().unwrap();
            let color = match code {
                '0' => color!(color "0x00,0x00,0x00"),
                '1' => color!(color "0x00,0x00,0xaa"),
                '2' => color!(color "0x00,0xaa,0x00"),
                '3' => color!(color "0x00,0xaa,0xaa"),
                '4' => color!(color "0xaa,0x00,0x00"),
                '5' => color!(color "0xaa,0x00,0xaa"),
                '6' => color!(color "0xff,0xaa,0x00"),
                '7' => color!(color "0xaa,0xaa,0xaa"),
                '8' => color!(color "0x55,0x55,0x55"),
                '9' => color!(color "0x55,0x55,0xff"),
                'a' => color!(color "0x55,0xff,0x55"),
                'b' => color!(color "0x55,0xff,0xff"),
                'c' => color!(color "0xff,0x55,0x55"),
                'd' => color!(color "0xff,0x55,0xff"),
                'e' => color!(color "0xff,0xff,0x55"),
                'f' => color!(color "0xff,0xff,0xff"),

                'k' => unimplemented!("unable support this style"),
                'l' => color!(style set_bold),
                'm' => {
                    use colored::Colorize;
                    s = after[1..].strikethrough().to_string();
                    continue;
                },
                'n' => color!(style set_underline),
                'o' => color!(style set_italic),
                'r' => color!(style set_reset),

                c => unreachable!("invalid charactor '{c}'"),
            };

            buf.set_color(&color).unwrap();

            s = after[1..].to_string();
        } else {
            buf.write_all(s.as_bytes()).unwrap();
            break;
        }
    }

    buf.set_color(&color!(style set_reset)).unwrap();

    core::str::from_utf8(buf.as_slice()).unwrap().to_string()
}

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Response {
    version: Version,
    players: Players,
    description: Chat,
    favicon: Option<Favicon>,
    #[serde(rename = "previewsChat")]
    previews_chat: Option<bool>,
    #[serde(rename = "enforcesSercureChat")]
    enforces_secure_chat: Option<bool>,
    #[serde(rename = "modinfo")]
    mod_info: Option<ModInfo>,
}

#[derive(Debug, Deserialize)]
struct Version {
    name: String,
    protocol: u16,
}

#[derive(Debug, Deserialize)]
struct Players {
    max: u32,
    online: u32,
    sample: Vec<User>,
}

#[derive(Debug, Deserialize)]
struct User {
    name: String,
    id: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Chat {
    Old(String),
    New {
        extra: Option<Vec<Wtf>>,
        text: String,
    },
}

#[derive(Debug, Deserialize)]
struct Wtf {
    color: Option<String>,
    text: String,
}

#[derive(Debug, Deserialize)]
struct ModInfo {
    #[serde(rename = "type")]
    ty: String,
    #[serde(rename = "modList")]
    mod_list: Vec<String>, // FIXME: unknown element
}

#[derive(Debug)]
struct Favicon(Vec<u8>);

use serde::de::Visitor;
use serde::Deserializer;

impl<'de> Deserialize<'de> for Favicon {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_string(FaviconVisitor)
    }
}

struct FaviconVisitor;

impl<'de> Visitor<'de> for FaviconVisitor {
    type Value = Favicon;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("favicon must be a string (data url)")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where E: std::error::Error {
        let url = url::Url::parse(v).unwrap();

        assert_eq!(url.scheme(), "data");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);

        let path = url.path();
        let (before, after) = path.rsplit_once(',').unwrap();
        let (before_before, before_after) = before.rsplit_once(';').unwrap();
        assert_eq!(before_after, "base64");

        let mime = before_before.parse::<mime::Mime>().unwrap();
        assert_eq!(mime, mime::IMAGE_PNG);

        let image = base64::decode(after).unwrap();

        Ok(Favicon(image))
    }
}

#[derive(Debug)]
enum Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "{:?}", self) }
}

impl std::error::Error for Error {}
