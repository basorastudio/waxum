//! SSRF guard for any code path that fetches or connects to a
//! caller-supplied URL: "send media by URL" (`handlers::messages`), webhook
//! registration + delivery (`handlers::webhooks`, `state.rs`), and the call
//! audio-URL playback path (`handlers::calls`).
//!
//! Two layers, because a single up-front string check is not enough — the
//! attacker doesn't need a URL that already points at 169.254.169.254, they
//! just need one whose DNS answer changes between our check and the actual
//! connection (a "DNS rebind"):
//!
//! - [`validate_public_url`]: cheap fail-fast check (scheme + one DNS
//!   resolution) for validating input eagerly, e.g. at webhook registration
//!   time so a bad URL is rejected immediately instead of silently never
//!   firing.
//! - [`SsrfSafeResolver`]: a `reqwest::dns::Resolve` implementation that
//!   performs the same address check on *every* DNS resolution reqwest
//!   actually makes for a request, including redirect hops (each hop
//!   re-resolves its target host). Wired into [`safe_http_client`], this is
//!   what actually closes the DNS-rebind and redirect-to-internal-host
//!   bypasses — `validate_public_url` alone cannot, since the resolution it
//!   saw is not necessarily the one the HTTP client will use moments later.
//!
//! Both reject: non-`http(s)` schemes, and any resolved address in a
//! loopback, link-local (this also covers the `169.254.169.254` cloud
//! metadata endpoint), private (RFC1918), unique-local (RFC4193), CGNAT
//! (RFC6598), multicast, broadcast, "this network" (0.0.0.0/8), or
//! unspecified range.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use once_cell::sync::Lazy;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Validates `raw_url`'s scheme and resolves its host, rejecting anything
/// that isn't a publicly-routable `http`/`https` target. Intended for
/// eager validation (e.g. at webhook registration); does not by itself
/// protect a later fetch from DNS rebinding — pair with [`safe_http_client`]
/// for that.
pub async fn validate_public_url(raw_url: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(raw_url).map_err(|e| format!("invalid URL: {e}"))?;

    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "unsupported URL scheme '{other}', only http/https are allowed"
            ))
        }
    }

    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| format!("failed to resolve host '{host}': {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("host '{host}' did not resolve to any address"));
    }

    for addr in &addrs {
        if !is_globally_routable(addr.ip()) {
            return Err(format!(
                "'{host}' resolves to a non-public address ({}), refusing",
                addr.ip()
            ));
        }
    }

    Ok(url)
}

/// A `reqwest::dns::Resolve` that rejects any resolution landing on a
/// non-public address. Reqwest calls this for the initial request and again
/// for every redirect hop, so wiring it into a client (see
/// [`safe_http_client`]) closes both the "URL looked fine at registration,
/// then someone repointed the DNS record" and "the server 302'd us to
/// 169.254.169.254" bypasses that a one-time string check cannot.
#[derive(Debug, Default, Clone, Copy)]
pub struct SsrfSafeResolver;

impl Resolve for SsrfSafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            if addrs.is_empty() {
                return Err(resolve_error(format!(
                    "host '{host}' did not resolve to any address"
                )));
            }

            for addr in &addrs {
                if !is_globally_routable(addr.ip()) {
                    return Err(resolve_error(format!(
                        "refusing to connect: '{host}' resolves to non-public address {}",
                        addr.ip()
                    )));
                }
            }

            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn resolve_error(msg: String) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(msg))
}

/// Shared `reqwest::Client` for fetching caller-supplied URLs (media-by-URL,
/// webhook delivery): SSRF-safe DNS resolution on every hop plus a bounded
/// timeout so a slow/hanging remote can't tie up a request indefinitely.
pub fn safe_http_client() -> &'static reqwest::Client {
    static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
        reqwest::Client::builder()
            .dns_resolver(std::sync::Arc::new(SsrfSafeResolver))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build SSRF-safe HTTP client")
    });
    &CLIENT
}

fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_globally_routable_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => is_globally_routable_v4(mapped),
            None => is_globally_routable_v6(v6),
        },
    }
}

/// Beyond std's `Ipv4Addr::is_private`/`is_loopback`/etc: also rejects the
/// rest of 0.0.0.0/8 ("this network", `is_unspecified` only covers the
/// single all-zero address) and 100.64.0.0/10 (RFC 6598 carrier-grade NAT,
/// used internally by many cloud/container networks but not covered by
/// `is_private`).
fn is_globally_routable_v4(ip: Ipv4Addr) -> bool {
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
    {
        return false;
    }
    let octets = ip.octets();
    if octets[0] == 0 {
        return false;
    }
    if octets[0] == 100 && (octets[1] & 0xc0) == 64 {
        return false;
    }
    true
}

/// Beyond std's `Ipv6Addr::is_loopback`/`is_unspecified`/`is_multicast`:
/// also rejects fc00::/7 (unique local, RFC 4193) and fe80::/10
/// (link-local) -- std doesn't expose stable checks for either yet.
fn is_globally_routable_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let seg0 = ip.segments()[0];
    if (seg0 & 0xfe00) == 0xfc00 {
        return false;
    }
    if (seg0 & 0xffc0) == 0xfe80 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_v4_is_routable() {
        assert!(is_globally_routable("8.8.8.8".parse().unwrap()));
        assert!(is_globally_routable("1.1.1.1".parse().unwrap()));
    }

    /// Covers, in order: loopback, cloud metadata (link-local),
    /// RFC1918 x3, CGNAT, unspecified, multicast, broadcast.
    #[test]
    fn private_and_special_v4_ranges_are_blocked() {
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !is_globally_routable(ip.parse().unwrap()),
                "{ip} should not be globally routable"
            );
        }
    }

    #[test]
    fn private_v6_ranges_and_mapped_v4_are_blocked() {
        for ip in [
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                !is_globally_routable(ip.parse().unwrap()),
                "{ip} should not be globally routable"
            );
        }
        assert!(is_globally_routable(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }
}
