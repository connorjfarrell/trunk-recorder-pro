//! Which plugins may be given decrypted calls.
//!
//! A call decrypted with keys the operator holds is not for public services: an upload to
//! OpenMHz or Broadcastify would publish what the system's owner encrypted. So, by default, a
//! plugin is given a decrypted call (its live audio and its concluded files) only when every
//! place it sends to is on this network (a private or loopback address, or a name that can only
//! be local). Any other plugin is withheld from them unless the config says, in the plugin's
//! own entry under `keys.shareDecrypted`, the sentence in [`PHRASE`]. That is for the config
//! file only: the interface never offers it.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::Value;

/// What a config must say, for a plugin that sends elsewhere, to be given decrypted calls.
pub const PHRASE: &str = "I understand decrypted calls will leave my own network";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Everything it sends to is on this network.
    Local,
    /// The config said, in the words asked for, that it may.
    Acknowledged,
    /// Not given decrypted calls: why.
    Withheld(String),
}

impl Verdict {
    pub fn allowed(&self) -> bool {
        !matches!(self, Verdict::Withheld(_))
    }
}

/// Whether plugin `id` (a plugin's id, not a copy's label) may be given decrypted calls, from its
/// settings (recorder-wide `global`, and each system's) and `shareDecrypted`.
pub fn judge(id: &str, global: &Value, per_system: &BTreeMap<String, Value>, share: &BTreeMap<String, String>) -> Verdict {
    let mut hosts = destinations(global);
    for v in per_system.values() {
        hosts.extend(destinations(v));
    }
    if !hosts.is_empty() && hosts.iter().all(|h| is_local_host(h)) {
        return Verdict::Local;
    }
    match share.get(id).map(|s| s.trim()) {
        Some(p) if p == PHRASE => return Verdict::Acknowledged,
        Some(_) => return Verdict::Withheld(format!("keys.shareDecrypted.{id} is not the exact sentence asked for")),
        None => {}
    }
    let why = if hosts.is_empty() {
        "it names no place on this network it sends to".to_string()
    } else {
        let outside: Vec<&str> = hosts.iter().filter(|h| !is_local_host(h)).map(String::as_str).collect();
        format!("it sends to {}, which isn't on this network", outside.join(", "))
    };
    Verdict::Withheld(why)
}

/// The hosts a plugin's settings name: the host of every URL in them, and the value of keys that
/// are plainly an address (`server`, `url`, `host`, `address`, `endpoint`, `ip`, `hostname`).
pub fn destinations(v: &Value) -> Vec<String> {
    fn walk(v: &Value, key: &str, out: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                let s = s.trim();
                if s.is_empty() {
                    return;
                }
                if let Some(h) = url_host(s) {
                    out.push(h);
                } else if matches!(key.to_ascii_lowercase().as_str(), "server" | "url" | "host" | "address" | "endpoint" | "ip" | "hostname") {
                    out.push(strip_port(s).to_string());
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, key, out)),
            Value::Object(m) => m.iter().for_each(|(k, x)| walk(x, k, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, "", &mut out);
    out
}

/// `scheme://user@host:port/path` → host.
fn url_host(s: &str) -> Option<String> {
    let rest = s.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = strip_port(authority);
    (!host.is_empty()).then(|| host.to_string())
}

fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match h.rsplit_once(':') {
        Some((a, p)) if !a.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => a,
        _ => h,
    }
}

/// A host that is on this network: a loopback, private or link-local address, `localhost`, a
/// name with no dot, or one under a name reserved for local use. A name that merely resolves to
/// a private address doesn't count (it isn't looked up).
pub fn is_local_host(h: &str) -> bool {
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return match ip.to_canonical() {
            IpAddr::V4(a) => a.is_loopback() || a.is_private() || a.is_link_local(),
            IpAddr::V6(a) => a.is_loopback() || a.is_unique_local() || a.is_unicast_link_local(),
        };
    }
    !h.contains('.') || ["local", "localhost", "lan", "internal", "home.arpa", "localdomain"].iter().any(|s| h.ends_with(&format!(".{s}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn none() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn local_hosts_are_this_network_only() {
        for h in ["localhost", "127.0.0.1", "::1", "10.1.2.3", "192.168.1.5", "172.16.0.9", "172.31.255.1", "169.254.1.1", "fd00::1", "scanner", "openmhz.lan", "pi.local", "a.b.internal", "x.home.arpa", "::ffff:192.168.1.5"] {
            assert!(is_local_host(h), "{h}");
        }
        for h in ["api.openmhz.com", "8.8.8.8", "172.32.0.1", "192.169.1.1", "2001:db8::1", "openmhz.example.com", "lan.example.com", "", "notlocal"] {
            // ("notlocal" has no dot, so it is a bare name: local.)
            if h == "notlocal" {
                assert!(is_local_host(h));
            } else {
                assert!(!is_local_host(h), "{h}");
            }
        }
    }

    #[test]
    fn destinations_are_found_in_urls_and_address_keys() {
        let v = json!({ "server": "https://api.openmhz.com", "apiKey": "abc", "nested": { "url": "http://user:pw@192.168.1.5:3000/api/call-upload", "note": "see http://x" }, "host": "pi.local:8080" });
        let mut d = destinations(&v);
        d.sort();
        assert_eq!(d, ["192.168.1.5", "api.openmhz.com", "pi.local", "x"]);
        assert!(destinations(&json!({ "apiKey": "k", "systemId": 7, "server": "" })).is_empty());
        assert_eq!(destinations(&json!({ "server": "[::1]:8080" })), ["::1"]);
    }

    #[test]
    fn a_plugin_is_judged_by_everywhere_it_sends() {
        let local = json!({ "server": "http://192.168.1.5:3000" });
        assert_eq!(judge("rdioscanner", &local, &BTreeMap::new(), &none()), Verdict::Local);
        // One place outside the network is enough.
        let mut systems = BTreeMap::new();
        systems.insert("sys".to_string(), json!({ "server": "https://api.openmhz.com" }));
        assert!(!judge("openmhz", &local, &systems, &none()).allowed());
        // Public by default, and a plugin that names nowhere is unknown, which is withheld too.
        assert!(!judge("openmhz", &json!({ "server": "https://api.openmhz.com" }), &BTreeMap::new(), &none()).allowed());
        assert!(!judge("broadcastify", &json!({}), &BTreeMap::new(), &none()).allowed());
        assert!(!judge("upload-script", &json!({ "command": "curl -T" }), &BTreeMap::new(), &none()).allowed());
    }

    #[test]
    fn only_the_exact_sentence_lets_an_outside_plugin_through() {
        let public = json!({ "server": "https://api.openmhz.com" });
        let mut share = BTreeMap::new();
        share.insert("openmhz".to_string(), PHRASE.to_string());
        assert_eq!(judge("openmhz", &public, &BTreeMap::new(), &share), Verdict::Acknowledged);
        share.insert("openmhz".to_string(), "yes".to_string());
        let v = judge("openmhz", &public, &BTreeMap::new(), &share);
        assert!(matches!(&v, Verdict::Withheld(w) if w.contains("exact sentence")), "{v:?}");
        share.insert("openmhz".to_string(), PHRASE.to_ascii_uppercase());
        assert!(!judge("openmhz", &public, &BTreeMap::new(), &share).allowed());
        // Another plugin's sentence isn't this one's.
        let mut other = BTreeMap::new();
        other.insert("broadcastify".to_string(), PHRASE.to_string());
        assert!(!judge("openmhz", &public, &BTreeMap::new(), &other).allowed());
    }
}
