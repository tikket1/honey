//! Parsing of address literals: `"127.0.0.1"`, `"::1"`, `"aa:bb:cc:dd:ee:ff"`.
//! Used by the type checker (to validate) and codegen (to get the bytes).

/// `"a.b.c.d"` → the address as a host-order u32 (what `pkt.u32` yields).
pub fn parse_ipv4(s: &str) -> Option<u32> {
    let mut out: u32 = 0;
    let mut n = 0;
    for part in s.split('.') {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        out = (out << 8) | v;
        n += 1;
    }
    (n == 4).then_some(out)
}

/// `"aa:bb:cc:dd:ee:ff"` → 6 bytes.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        if n == 6 || part.len() != 2 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

/// RFC 4291 text form → 16 bytes: up to eight 16-bit hex groups, one `::`
/// standing for the run of zero groups. No embedded IPv4, no zone ids.
pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    fn groups(part: &str) -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        part.split(':').map(|g| if g.is_empty() || g.len() > 4 { None } else { u16::from_str_radix(g, 16).ok() }).collect()
    }
    let all: Vec<u16> = match s.split_once("::") {
        Some((l, r)) => {
            if r.contains("::") {
                return None;
            }
            let (l, r) = (groups(l)?, groups(r)?);
            if l.len() + r.len() > 7 {
                return None;
            }
            let mut v = l;
            v.extend(std::iter::repeat_n(0u16, 8 - v.len() - r.len()));
            v.extend(r);
            v
        }
        None => {
            let g = groups(s)?;
            if g.len() != 8 {
                return None;
            }
            g
        }
    };
    let mut out = [0u8; 16];
    for (i, g) in all.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
    }
    Some(out)
}

/// `"10.0.0.0/8"` → (network in host order, prefix length). A bare address
/// is a /32.
pub fn parse_cidr4(s: &str) -> Option<(u32, u8)> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, l.parse::<u8>().ok().filter(|l| *l <= 32)?),
        None => (s, 32),
    };
    Some((parse_ipv4(addr)?, len))
}

/// `"fe80::/10"` → (network bytes, prefix length). A bare address is a /128.
pub fn parse_cidr6(s: &str) -> Option<([u8; 16], u8)> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, l.parse::<u8>().ok().filter(|l| *l <= 128)?),
        None => (s, 128),
    };
    Some((parse_ipv6(addr)?, len))
}

/// The netmask for a prefix length, as a host-order u32.
pub fn mask4(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len as u32) }
}

/// The netmask for a prefix length, as 16 wire-order bytes.
pub fn mask6(len: u8) -> [u8; 16] {
    let mut m = [0u8; 16];
    let mut left = len as u32;
    for b in m.iter_mut() {
        if left >= 8 {
            *b = 0xff;
            left -= 8;
        } else if left > 0 {
            *b = (0xffu16 << (8 - left)) as u8;
            left = 0;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        assert_eq!(parse_cidr4("10.0.0.0/8"), Some((0x0a00_0000, 8)));
        assert_eq!(parse_cidr4("127.0.0.1"), Some((0x7f00_0001, 32)));
        assert_eq!(parse_cidr4("10.0.0.0/33"), None);
        assert_eq!(mask4(8), 0xff00_0000);
        assert_eq!(mask4(0), 0);
        assert_eq!(mask4(32), u32::MAX);
        let (net, len) = parse_cidr6("fe80::/10").unwrap();
        assert_eq!((net[0], net[1], len), (0xfe, 0x80, 10));
        assert_eq!(mask6(10)[..2], [0xff, 0xc0]);
        assert_eq!(mask6(10)[2], 0);
        assert_eq!(mask6(128), [0xff; 16]);
        assert_eq!(parse_cidr6("::1/129"), None);
    }

    #[test]
    fn ipv4() {
        assert_eq!(parse_ipv4("127.0.0.1"), Some(0x7f00_0001));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(u32::MAX));
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.256"), None);
        assert_eq!(parse_ipv4("a.b.c.d"), None);
    }

    #[test]
    fn mac() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("00:00:00:00:00:00"), Some([0; 6]));
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:f"), None);
    }

    #[test]
    fn ipv6() {
        let mut one = [0u8; 16];
        one[15] = 1;
        assert_eq!(parse_ipv6("::1"), Some(one));
        assert_eq!(parse_ipv6("::"), Some([0; 16]));
        let mut fe80 = [0u8; 16];
        fe80[0] = 0xfe;
        fe80[1] = 0x80;
        fe80[15] = 0x01;
        assert_eq!(parse_ipv6("fe80::1"), Some(fe80));
        assert_eq!(parse_ipv6("2001:db8:0:0:0:0:0:1"), parse_ipv6("2001:db8::1"));
        assert_eq!(parse_ipv6("1:2:3:4:5:6:7"), None); // too few without ::
        assert_eq!(parse_ipv6("1::2::3"), None);
        assert_eq!(parse_ipv6("12345::"), None);
    }
}
