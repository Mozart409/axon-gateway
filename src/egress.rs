//! Egress policy for user-supplied (personal) MCP backend URLs.
//!
//! A personal backend URL is typed in by a user, so without a guard it is a
//! server-side request forgery primitive: the gateway would connect to
//! whatever the URL names, including the gateway host's own loopback
//! services, the LAN behind it and the cloud metadata endpoint. The policy
//! refuses every loopback, private, link-local, CGNAT, multicast and reserved
//! address by default; an operator opens exceptions with allow rules and
//! closes more with deny rules.
//!
//! Checking the URL is not enough on its own: a hostile DNS server can answer
//! the check with a public address and the connection with `127.0.0.1`
//! (DNS rebinding). [`EgressPolicy::check_url`] therefore resolves the host
//! once, checks every address it got and returns a [`PinnedTarget`]; the
//! client built from it connects only to that address, so nothing is resolved
//! again. Redirects are off for the same reason: a redirect target would
//! bypass the check.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use reqwest::Url;

/// Address ranges refused unless an allow rule names them.
const DEFAULT_DENY: &[&str] = &[
    // "This network" (0.0.0.0 reaches the local host on Linux).
    "0.0.0.0/8",
    // RFC 1918 private.
    "10.0.0.0/8",
    // CGNAT, also the Tailscale range.
    "100.64.0.0/10",
    // Loopback.
    "127.0.0.0/8",
    // Link-local, including the cloud metadata endpoint 169.254.169.254.
    "169.254.0.0/16",
    // RFC 1918 private.
    "172.16.0.0/12",
    // IETF protocol assignments.
    "192.0.0.0/24",
    // RFC 1918 private.
    "192.168.0.0/16",
    // Benchmarking.
    "198.18.0.0/15",
    // Multicast.
    "224.0.0.0/4",
    // Reserved, including the limited broadcast 255.255.255.255.
    "240.0.0.0/4",
    // IPv6 unspecified.
    "::/128",
    // IPv6 loopback.
    "::1/128",
    // Unique local addresses, including the AWS IPv6 metadata fd00:ec2::254.
    "fc00::/7",
    // IPv6 link-local.
    "fe80::/10",
    // IPv6 multicast.
    "ff00::/8",
    // 64:ff9b::/96 (NAT64) is deliberately absent: it maps public addresses.
    // `allows` checks the IPv4 address embedded in it (and in 6to4 and Teredo).
];

/// One allow or deny entry
#[derive(Debug, Clone)]
enum Rule {
    /// A CIDR or a bare IP
    Net(IpNet),
    /// An exact host, lower case
    Host(String),
    /// `*.example.com`: the suffix with its leading dot (`.example.com`),
    /// lower case. Matches subdomains only, never the apex.
    Wildcard(String),
}

impl Rule {
    fn parse(entry: &str) -> Result<Self, EgressError> {
        let bad = |why: &str| EgressError::Rule(format!("{entry:?}: {why}"));
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(bad("empty entry"));
        }
        if entry.contains('/') {
            return entry
                .parse::<IpNet>()
                .map(Self::Net)
                .map_err(|_| bad("not a valid CIDR"));
        }
        if let Ok(ip) = entry.parse::<IpAddr>() {
            return Ok(Self::Net(IpNet::from(ip)));
        }
        let host = entry.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host);
        let (wildcard, name) = match host.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, host),
        };
        let valid = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid {
            return Err(bad("not a CIDR, IP address or host name"));
        }
        Ok(if wildcard {
            Self::Wildcard(format!(".{name}"))
        } else {
            Self::Host(name.to_owned())
        })
    }

    /// `host` is lower case without a trailing dot, `ip` is normalised.
    fn matches(&self, host: &str, ip: IpAddr) -> bool {
        match self {
            Self::Net(net) => net.contains(&ip),
            Self::Host(name) => host == name,
            Self::Wildcard(suffix) => host.len() > suffix.len() && host.ends_with(suffix.as_str()),
        }
    }
}

/// What a personal backend URL may connect to
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    default_deny: Vec<IpNet>,
}

/// A checked URL with the one address the connection is pinned to
#[derive(Debug, Clone)]
pub struct PinnedTarget {
    pub host: String,
    pub addr: SocketAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// A malformed allow or deny entry in the configuration
    #[error("invalid egress rule {0}")]
    Rule(String),
    #[error("invalid url: {0}")]
    Url(String),
    #[error("only http and https urls are allowed")]
    Scheme,
    #[error("urls with credentials are not allowed")]
    Credentials,
    #[error("cannot resolve host: {0}")]
    Resolve(String),
    #[error("egress to {host} ({ip}) is not allowed")]
    Denied { host: String, ip: IpAddr },
    #[error("cannot build http client: {0}")]
    Client(String),
}

impl EgressPolicy {
    /// Entries are a CIDR (`10.0.0.0/8`, `fd00::/8`), a bare IP, an exact host
    /// (`mcp.example.com`) or a wildcard host (`*.example.com`, subdomains
    /// only). Hosts are case-insensitive.
    ///
    /// # Errors
    ///
    /// [`EgressError::Rule`] for an entry that is none of those.
    pub fn new(allow: &[String], deny: &[String]) -> Result<Self, EgressError> {
        let parse = |entries: &[String]| -> Result<Vec<Rule>, EgressError> {
            entries.iter().map(|e| Rule::parse(e)).collect()
        };
        let default_deny = DEFAULT_DENY
            .iter()
            .map(|net| {
                net.parse::<IpNet>()
                    .map_err(|_| EgressError::Rule(format!("{net:?}: built-in range")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            allow: parse(allow)?,
            deny: parse(deny)?,
            default_deny,
        })
    }

    /// Parses the URL (http and https only, no userinfo), resolves the host
    /// (IP literals skip DNS), checks every resolved address and returns the
    /// first one to pin.
    ///
    /// # Errors
    ///
    /// [`EgressError::Url`], [`EgressError::Scheme`] or
    /// [`EgressError::Credentials`] for a URL that is not acceptable,
    /// [`EgressError::Resolve`] when the host does not resolve, and
    /// [`EgressError::Denied`] when any resolved address is refused.
    pub async fn check_url(&self, url: &str) -> Result<PinnedTarget, EgressError> {
        let url = Url::parse(url).map_err(|e| EgressError::Url(e.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(EgressError::Scheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::Credentials);
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| EgressError::Url("no port".to_owned()))?;
        let raw = url
            .host_str()
            .ok_or_else(|| EgressError::Url("no host".to_owned()))?;
        // `host_str` keeps the brackets of an IPv6 literal.
        let literal = raw.trim_start_matches('[').trim_end_matches(']');
        let (host, addrs) = if let Ok(ip) = literal.parse::<IpAddr>() {
            (ip.to_string(), vec![SocketAddr::new(ip, port)])
        } else {
            let host = raw.to_ascii_lowercase();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| EgressError::Resolve(format!("{host}: {e}")))?
                .collect();
            (host, addrs)
        };
        let Some(first) = addrs.first().copied() else {
            return Err(EgressError::Resolve(format!("{host}: no addresses")));
        };
        // One refused address refuses the URL: the client may pick any of them.
        if let Some(denied) = addrs.iter().find(|a| !self.allows(&host, a.ip())) {
            return Err(EgressError::Denied {
                host,
                ip: denied.ip(),
            });
        }
        Ok(PinnedTarget { host, addr: first })
    }

    /// The decision for one host and one of its addresses: a deny rule
    /// matching either refuses, then an allow rule matching either allows,
    /// then the built-in default-deny ranges refuse, otherwise allowed.
    /// IPv4-mapped IPv6 addresses are matched as the IPv4 address, and an
    /// IPv4 address embedded in a NAT64, 6to4 or Teredo address is checked as
    /// well as the IPv6 address itself: every one of them must be allowed.
    ///
    /// A host rule (exact or wildcard) relaxes only the host name test: an
    /// address that is loopback, unspecified or link-local (cloud metadata
    /// included) stays refused unless a CIDR or IP rule covers that address.
    #[must_use]
    pub fn allows(&self, host: &str, ip: IpAddr) -> bool {
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host);
        let ip = normalise(ip);
        self.allows_one(host, ip) && embedded_ipv4(ip).is_none_or(|v4| self.allows_one(host, v4))
    }

    fn allows_one(&self, host: &str, ip: IpAddr) -> bool {
        if self.deny.iter().any(|r| r.matches(host, ip)) {
            return false;
        }
        if self.allow.iter().any(|r| match r {
            Rule::Net(net) => net.contains(&ip),
            Rule::Host(_) | Rule::Wildcard(_) => !always_refused(ip) && r.matches(host, ip),
        }) {
            return true;
        }
        !self.default_deny.iter().any(|net| net.contains(&ip))
    }
}

/// Loopback, unspecified and link-local addresses: a host rule never opens them.
fn always_refused(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.to_bits() >> 24 == 0,
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.to_bits() >> 118 == 0xfe80 >> 6
        }
    }
}

/// `::ffff:a.b.c.d` becomes `a.b.c.d`, so a mapped loopback is a loopback.
fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// The IPv4 address a transition-mechanism IPv6 address carries: NAT64
/// `64:ff9b::/96` (last 32 bits), 6to4 `2002::/16` (bits 16 to 48) and Teredo
/// `2001:0::/32` (the client address, last 32 bits inverted).
fn embedded_ipv4(ip: IpAddr) -> Option<IpAddr> {
    let IpAddr::V6(v6) = ip else {
        return None;
    };
    let bits = v6.to_bits();
    // The low 32 bits, or the 32 bits after the first 16.
    let low = u32::try_from(bits & 0xffff_ffff).ok()?;
    let mid = u32::try_from((bits >> 80) & 0xffff_ffff).ok()?;
    let v4 = if bits >> 32 == 0x64_ff9b_0000_0000_0000_0000 {
        Ipv4Addr::from_bits(low)
    } else if bits >> 112 == 0x2002 {
        Ipv4Addr::from_bits(mid)
    } else if bits >> 96 == 0x2001_0000 {
        Ipv4Addr::from_bits(!low)
    } else {
        return None;
    };
    Some(IpAddr::V4(v4))
}

impl PinnedTarget {
    /// A client that connects only to `addr` for `host`, follows no redirects
    /// and gives up after `timeout`. It ignores proxy environment variables:
    /// a proxy would resolve and connect on its own, past the pin.
    ///
    /// # Errors
    ///
    /// [`EgressError::Client`] when reqwest cannot build the client.
    pub fn client(&self, timeout: Duration) -> Result<reqwest::Client, EgressError> {
        reqwest::Client::builder()
            .resolve(&self.host, self.addr)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|e| EgressError::Client(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow: &[&str], deny: &[&str]) -> EgressPolicy {
        let own = |s: &[&str]| s.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>();
        EgressPolicy::new(&own(allow), &own(deny)).expect("valid rules")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip literal")
    }

    #[test]
    fn default_denies_loopback_metadata_and_private_ranges() {
        let p = policy(&[], &[]);
        for denied in [
            "127.0.0.1",
            "127.255.0.9",
            "::1",
            "169.254.169.254",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "255.255.255.255",
            "fd00::1",
            "fd00:ec2::254",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!p.allows("example.com", ip(denied)), "{denied} allowed");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        let p = policy(&[], &[]);
        for allowed in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
            "::ffff:8.8.8.8",
        ] {
            assert!(p.allows("example.com", ip(allowed)), "{allowed} denied");
        }
    }

    #[test]
    fn allow_cidr_opens_a_private_range() {
        let p = policy(&["10.0.0.0/8", "fd00::/8"], &[]);
        assert!(p.allows("mcp.internal", ip("10.4.5.6")));
        assert!(p.allows("mcp.internal", ip("fd12::1")));
        assert!(p.allows("mcp.internal", ip("::ffff:10.4.5.6")));
        assert!(!p.allows("mcp.internal", ip("192.168.0.1")));
        assert!(!p.allows("mcp.internal", ip("127.0.0.1")));
    }

    #[test]
    fn allow_bare_ip_and_host() {
        let p = policy(&["192.168.1.5", "mcp.example.com"], &[]);
        assert!(p.allows("x.test", ip("192.168.1.5")));
        assert!(!p.allows("x.test", ip("192.168.1.6")));
        // An allowed host opens its addresses too, even private ones.
        assert!(p.allows("MCP.Example.com.", ip("10.0.0.1")));
        assert!(!p.allows("other.example.com", ip("10.0.0.1")));
    }

    #[test]
    fn embedded_ipv4_is_checked() {
        let p = policy(&[], &[]);
        // NAT64 of 10.0.0.1, 6to4 of 192.168.1.1, Teredo client 127.0.0.1.
        assert!(!p.allows("example.com", ip("64:ff9b::a00:1")));
        assert!(p.allows("example.com", ip("64:ff9b::808:808")));
        assert!(!p.allows("example.com", ip("2002:c0a8:101::1")));
        assert!(!p.allows("example.com", ip("2001:0:4136:e378:8000:63bf:80ff:fffe")));
        assert!(p.allows("example.com", ip("2002:808:808::1")));
    }

    #[test]
    fn host_rule_never_opens_loopback_unspecified_or_link_local() {
        let p = policy(&["mcp.example.com", "*.homelab.internal"], &[]);
        for denied in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "169.254.169.254",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!p.allows("mcp.example.com", ip(denied)), "{denied} allowed");
            assert!(
                !p.allows("a.homelab.internal", ip(denied)),
                "{denied} allowed"
            );
        }
        assert!(p.allows("mcp.example.com", ip("10.1.2.3")));
        assert!(p.allows("a.homelab.internal", ip("fd00::1")));
        assert!(p.allows("a.homelab.internal", ip("100.64.0.1")));
    }

    #[test]
    fn cidr_rule_opens_loopback_for_a_host_rule() {
        let p = policy(&["127.0.0.1/32", "mcp.example.com"], &[]);
        assert!(p.allows("mcp.example.com", ip("127.0.0.1")));
        assert!(!p.allows("mcp.example.com", ip("127.0.0.2")));
    }

    #[test]
    fn deny_beats_allow() {
        let p = policy(
            &["*.example.com", "10.0.0.0/8"],
            &["bad.example.com", "10.9.0.0/16"],
        );
        assert!(p.allows("good.example.com", ip("1.1.1.1")));
        assert!(!p.allows("bad.example.com", ip("1.1.1.1")));
        assert!(!p.allows("good.example.com", ip("10.9.1.1")));
        assert!(p.allows("good.example.com", ip("10.8.1.1")));
    }

    #[test]
    fn deny_rule_refuses_a_public_address() {
        let p = policy(&[], &["1.1.1.0/24", "evil.test"]);
        assert!(!p.allows("example.com", ip("1.1.1.1")));
        assert!(!p.allows("evil.test", ip("8.8.8.8")));
        assert!(p.allows("example.com", ip("8.8.8.8")));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let p = policy(&["*.Example.com"], &[]);
        assert!(p.allows("a.example.com", ip("10.0.0.1")));
        assert!(p.allows("A.B.EXAMPLE.COM", ip("10.0.0.1")));
        assert!(!p.allows("example.com", ip("10.0.0.1")));
        assert!(!p.allows("notexample.com", ip("10.0.0.1")));
        assert!(!p.allows("example.com.evil.test", ip("10.0.0.1")));
    }

    #[test]
    fn new_rejects_garbage() {
        for bad in [
            "",
            "  ",
            "10.0.0.0/33",
            "10.0.0.0/",
            "not a host",
            "*.",
            "*",
            "a..b",
            "-a.com",
            "http://example.com",
            "ex*mple.com",
        ] {
            let err = EgressPolicy::new(&[bad.to_owned()], &[]).expect_err(bad);
            assert!(matches!(err, EgressError::Rule(_)), "{bad}: {err}");
            let err = EgressPolicy::new(&[], &[bad.to_owned()]).expect_err(bad);
            assert!(matches!(err, EgressError::Rule(_)), "{bad}: {err}");
        }
    }

    #[tokio::test]
    async fn check_url_denies_ip_literals() {
        let p = policy(&[], &[]);
        let err = p.check_url("http://127.0.0.1:8080/mcp").await.unwrap_err();
        assert!(matches!(err, EgressError::Denied { ip, .. } if ip == self::ip("127.0.0.1")));
        let err = p.check_url("http://[::1]/").await.unwrap_err();
        assert!(matches!(err, EgressError::Denied { .. }));
        let err = p
            .check_url("http://169.254.169.254/latest")
            .await
            .unwrap_err();
        assert!(matches!(err, EgressError::Denied { .. }));
        // Decimal and hex forms are normalised by the URL parser.
        let err = p.check_url("http://2130706433/").await.unwrap_err();
        assert!(matches!(err, EgressError::Denied { .. }));
        let err = p.check_url("http://[::ffff:127.0.0.1]/").await.unwrap_err();
        assert!(matches!(err, EgressError::Denied { .. }));
    }

    #[tokio::test]
    async fn check_url_rejects_bad_urls() {
        let p = policy(&[], &[]);
        let err = p.check_url("https://user:pw@1.1.1.1/").await.unwrap_err();
        assert!(matches!(err, EgressError::Credentials));
        let err = p.check_url("https://user@1.1.1.1/").await.unwrap_err();
        assert!(matches!(err, EgressError::Credentials));
        let err = p.check_url("ftp://1.1.1.1/").await.unwrap_err();
        assert!(matches!(err, EgressError::Scheme));
        let err = p.check_url("not a url").await.unwrap_err();
        assert!(matches!(err, EgressError::Url(_)));
    }

    #[tokio::test]
    async fn check_url_pins_a_public_literal() {
        let p = policy(&[], &[]);
        let target = p.check_url("https://1.1.1.1/mcp").await.unwrap();
        assert_eq!(target.addr, "1.1.1.1:443".parse().unwrap());
        assert_eq!(target.host, "1.1.1.1");
        target.client(Duration::from_secs(5)).unwrap();
    }

    #[tokio::test]
    async fn check_url_allow_rule_opens_a_private_literal() {
        let p = policy(&["10.0.0.0/8"], &[]);
        let target = p.check_url("http://10.1.2.3:9000/mcp").await.unwrap();
        assert_eq!(target.addr, "10.1.2.3:9000".parse().unwrap());
    }

    #[tokio::test]
    async fn localhost_resolves_to_loopback_and_is_denied() {
        let p = policy(&[], &[]);
        let err = p.check_url("http://localhost:8080/").await.unwrap_err();
        assert!(matches!(err, EgressError::Denied { ref host, .. } if host == "localhost"));
    }
}
