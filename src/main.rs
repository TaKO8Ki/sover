mod dns;
mod file;
mod fingerprint;
mod requests;

use clap::{App, AppSettings, Arg};
use log::debug;

pub struct Options {
    domain: Option<String>,
    word_list: Option<String>,
    timeout: u64,
    output: String,
    ssl: bool,
    all: bool,
    verbose: bool,
    config: Option<String>,
    manual: bool,
    fingerprints: Vec<fingerprint::Fingerprints>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            domain: None,
            word_list: None,
            timeout: 1,
            output: String::from("output.txt"),
            ssl: false,
            all: false,
            verbose: true,
            config: None,
            manual: false,
            fingerprints: fingerprint::default_fingerprints(),
        }
    }
}

pub struct Subdomain {
    url: String,
}

impl Options {
    pub fn execute(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::prelude::*;
        use std::io::BufReader;

        let mut list = Vec::new();

        let mut urls: Vec<Subdomain> = Vec::new();

        if let Some(domain) = self.domain.as_ref() {
            if domain.len() > 0 {
                list.push(domain.to_string());
            }
        } else if let Some(word_list) = self.word_list.as_ref() {
            let file = File::open(word_list)?;
            let mut buf_reader = BufReader::new(file);
            let mut contents = String::new();
            buf_reader.read_to_string(&mut contents)?;
            list.extend(
                contents
                    .split("\n")
                    .map(|line| line.to_string())
                    .collect::<Vec<_>>(),
            );
        }

        if let Some(config) = self.config.as_ref() {
            self.fingerprints = file::fingerprints(config);
        }

        for domain in list {
            urls.push(Subdomain {
                url: domain.clone(),
            });
        }

        for url in urls {
            url.dns(self)?;
        }
        Ok(())
    }
}

fn main() {
    env_logger::init();

    let matches = build_cli().get_matches();
    let mut option = Options {
        domain: matches.value_of("domain").map(|c| c.to_string()),
        word_list: matches.value_of("wordlist").map(|c| c.to_string()),
        ssl: matches.value_of("ssl").is_some(),
        all: matches.value_of("all").is_some(),
        verbose: matches.value_of("verbose").is_some(),
        config: matches.value_of("config").map(|c| c.to_string()),
        manual: matches.value_of("manual").is_some(),
        ..Options::default()
    };

    if let Some(timeout) = matches.value_of("timeout") {
        option.timeout = timeout.parse().unwrap();
    }

    if let Some(output) = matches.value_of("output") {
        option.output = output.to_string();
    }

    debug!("execute");
    option.execute().unwrap();
}

pub fn build_cli() -> App<'static, 'static> {
    App::new("sover")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("0.1.0")
        .about("Subdomain Takeover tool written in Rust")
        .arg(Arg::with_name("domain").short("d").takes_value(true))
        .arg(Arg::with_name("wordlist").short("w").takes_value(true))
        .arg(Arg::with_name("timeout").short("t").takes_value(true))
        .arg(Arg::with_name("ssl").short("ssl"))
        .arg(Arg::with_name("all").short("all").takes_value(true))
        .arg(Arg::with_name("verbose").short("v"))
        .arg(Arg::with_name("output").short("o").takes_value(true))
        .arg(Arg::with_name("config").short("c").takes_value(true))
        .arg(Arg::with_name("manual").short("m"))
}
