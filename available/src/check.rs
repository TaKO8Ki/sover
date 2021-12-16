use publicsuffix::{List, Psl, Type};
use whois_rust::{WhoIs, WhoIsLookupOptions};

pub fn available(domain: impl Into<String>) -> bool {
    let domain = set_domain(domain);
    let list = List::new();

    let suffix = list.domain(domain.as_bytes()).unwrap();

    if matches!(suffix.suffix().typ(), Some(ty) if ty == Type::Icann) {
        return check(
            String::from_utf8(suffix.as_bytes().to_vec()).unwrap(),
            get_whois(String::from_utf8(suffix.as_bytes().to_vec()).unwrap()),
        );
    }

    false
}

fn set_domain(domain: impl Into<String>) -> String {
    let mut domain: String = domain.into();

    if domain.contains("://") {
        domain = domain
            .split("://")
            .collect::<Vec<_>>()
            .get(1)
            .unwrap()
            .to_string();
    }

    if domain.len() > 1 {
        if &domain[domain.len() - 1..] == "." {
            domain = domain[..domain.len() - 1].to_string()
        }
    }

    domain.to_lowercase()
}

fn check(tld: String, resp: String) -> bool {
    let fp = crate::fingerprint::FINGERPRINTS.lock().unwrap();

    // .ca & .lt have opposite fingerprints
    if tld == "ca" || tld == "lt" {
        if !matches!(fp.get(&tld.as_ref()), Some(fp) if resp.contains(fp)) {
            return true;
        }
    }

    /* Checks if the .tld is in our fingerprint list
    Then checks if the fingerprint is in the whois
    response data */
    if fp.get(&tld.as_ref()) != Some(&"") {
        if matches!(fp.get(&tld.as_ref()), Some(fp) if resp.contains(fp)) {
            return true;
        }
    } else {
        /* If the .tld isn't in our fingerprint list,
        this is the last resort options to check a
        list of possible responses.*/
        let afp = crate::fingerprint::ALL_FINGERPRINTS;

        for f in afp {
            if resp.contains(f) {
                return true;
            }
        }
    }

    false
}

fn get_whois(domain: String) -> String {
    let whois = WhoIs::from_host("whois.arin.net").unwrap();
    whois
        .lookup(WhoIsLookupOptions::from_string(domain).unwrap())
        .unwrap()
}
