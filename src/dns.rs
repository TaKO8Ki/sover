use crate::file::is_json;
use std::str::FromStr;
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::Resolver;

use crate::fingerprint::{detect, verify_cname};
use crate::{Options, Subdomain};

impl Subdomain {
    pub fn dns(&self, o: &Options) -> Result<(), Box<dyn std::error::Error>> {
        use colored::*;

        let config = &o.fingerprints;

        if o.all {
            log::debug!("all=true");
            detect(
                self.url.clone(),
                o.output.clone(),
                o.ssl,
                o.verbose,
                o.manual,
                o.timeout,
                config,
            )?;
        } else {
            log::debug!("all=false");
            if verify_cname(self.url.clone(), config)? {
                detect(
                    self.url.clone(),
                    o.output.clone(),
                    o.ssl,
                    o.verbose,
                    o.manual,
                    o.timeout,
                    config,
                )?;
            }

            if o.verbose {
                let out = format!("[{}] {}", "Not Vulnerable".red().bold(), self.url);
                println!("{}", out);

                if o.output != "" {
                    if is_json(o.output.clone()) {
                        // writeJSON("", s.Url, o.Output)
                    } else {
                        // write(result, o.Output)
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn resolve(url: impl Into<String>) -> Result<String, Box<dyn std::error::Error>> {
    let mut cname = String::new();

    let address = "8.8.8.8:53".parse().unwrap();
    let conn = UdpClientConnection::new(address).unwrap();
    let client = SyncClient::new(conn);

    let name = Name::from_str(&url.into()).unwrap();

    let response: DnsResponse = client
        .query(&name, DNSClass::IN, RecordType::CNAME)
        .unwrap();

    log::debug!("response");

    let answers: &[Record] = response.answers();

    for ans in answers {
        if let &RData::CNAME(ref c) = ans.rdata() {
            cname = c.to_string();
        }
    }
    Ok(cname)
}

pub fn nxdomain(nameserver: impl Into<String>) -> bool {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip(nameserver.into());
    if let Err(err) = response {
        if let ResolveErrorKind::NoRecordsFound { .. } = err.kind() {
            return true;
        }
    }
    false
}
