use crate::dns::{nxdomain, resolve};
use crate::file::is_json;
use crate::requests::get;
use available::available;

pub struct Fingerprints {
    service: String,
    cname: Vec<String>,
    fingerprint: Vec<String>,
    nxdomain: bool,
}

pub fn default_fingerprints() -> Vec<Fingerprints> {
    vec![Fingerprints {
        service: "fastly".to_string(),
        cname: vec!["fastly".to_string()],
        fingerprint: vec!["Fastly error: unknown domain".to_string()],
        nxdomain: false,
    },Fingerprints {
        service: "github".to_string(),
        cname: vec![
            "github.io".to_string()
        ],
        fingerprint: vec![
            "There isn't a GitHub Pages site here.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "heroku".to_string(),
        cname: vec![
            "herokuapp".to_string()
        ],
        fingerprint: vec![
            "herokucdn.com/error-pages/no-such-app.html".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "pantheon".to_string(),
        cname: vec![
            "pantheonsite.io".to_string()
        ],
        fingerprint: vec![
            "The gods are wise, but do not know of the site which you seek.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "tumblr".to_string(),
        cname: vec![
            "domains.tumblr.com".to_string()
        ],
        fingerprint: vec![
            "Whatever you were looking for doesn't currently exist at this address.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "wordpress".to_string(),
        cname: vec![
            "wordpress.com".to_string()
        ],
        fingerprint: vec![
            "Do you want to register".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "teamwork".to_string(),
        cname: vec![
            "teamwork.com".to_string()
        ],
        fingerprint: vec![
            "Oops - We didn't find your site.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "helpjuice".to_string(),
        cname: vec![
            "helpjuice.com".to_string()
        ],
        fingerprint: vec![
            "We could not find what you're looking for.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "helpscout".to_string(),
        cname: vec![
            "helpscoutdocs.com".to_string()
        ],
        fingerprint: vec![
            "No settings were found for this company:".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "s3 bucket".to_string(),
        cname: vec![
            "amazonaws".to_string()
        ],
        fingerprint: vec![
            "The specified bucket does not exist".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "ghost".to_string(),
        cname: vec![
            "ghost.io".to_string()
        ],
        fingerprint: vec![
            "The thing you were looking for is no longer here, or never was".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "shopify".to_string(),
        cname: vec![
            "myshopify.com".to_string()
        ],
        fingerprint: vec![
            "Sorry, this shop is currently unavailable.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "uservoice".to_string(),
        cname: vec![
            "uservoice.com".to_string()
        ],
        fingerprint: vec![
            "This UserVoice subdomain is currently available!".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "surge".to_string(),
        cname: vec![
            "surge.sh".to_string()
        ],
        fingerprint: vec![
            "project not found".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "bitbucket".to_string(),
        cname: vec![
            "bitbucket.io".to_string()
        ],
        fingerprint: vec![
            "Repository not found".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "intercom".to_string(),
        cname: vec![
            "custom.intercom.help".to_string()
        ],
        fingerprint: vec![
            "This page is reserved for artistic dogs.".to_string(),
            "<h1 class=\"headline\"Uh oh. That page doesn't exist.</h1>".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "webflow".to_string(),
        cname: vec![
            "proxy.webflow.com".to_string(),
            "proxy-ssl.webflow.com".to_string()
        ],
        fingerprint: vec![
            "<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "wishpond".to_string(),
        cname: vec![
            "wishpond.com".to_string()
        ],
        fingerprint: vec![
            "https://www.wishpond.com/404?campaign=true".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "aftership".to_string(),
        cname: vec![
            "aftership.com".to_string()
        ],
        fingerprint: vec![
            "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "aha".to_string(),
        cname: vec![
            "ideas.aha.io".to_string()
        ],
        fingerprint: vec![
            "There is no portal here ... sending you back to Aha!".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "tictail".to_string(),
        cname: vec![
            "domains.tictail.com".to_string()
        ],
        fingerprint: vec![
            "to target URL: <a href=\"https://tictail.com".to_string(),
            "Start selling on Tictail.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "brightcove".to_string(),
        cname: vec![
            "bcvp0rtal.com".to_string(),
            "brightcovegallery.com".to_string(),
            "gallery.video".to_string()
        ],
        fingerprint: vec![
            "<p class=\"bc-gallery-error-code\">Error Code: 404</p>".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "bigcartel".to_string(),
        cname: vec![
            "bigcartel.com".to_string()
        ],
        fingerprint: vec![
            "<h1>Oops! We could&#8217;t find that page.</h1>".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "campaignmonitor".to_string(),
        cname: vec![
            "createsend.com".to_string()
        ],
        fingerprint: vec![
            "Double check the URL or <a href=\"mailto:help@createsend.com".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "acquia".to_string(),
        cname: vec![
            "acquia-test.co".to_string()
        ],
        fingerprint: vec![
            "The site you are looking for could not be found.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "simplebooklet".to_string(),
        cname: vec![
            "simplebooklet.com".to_string()
        ],
        fingerprint: vec![
            "We can't find this <a href=\"https://simplebooklet.com".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "getresponse".to_string(),
        cname: vec![
            ".gr8.com".to_string()
        ],
        fingerprint: vec![
            "With GetResponse Landing Pages, lead generation has never been easier".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "vend".to_string(),
        cname: vec![
            "vendecommerce.com".to_string()
        ],
        fingerprint: vec![
            "Looks like you've traveled too far into cyberspace".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "jetbrains".to_string(),
        cname: vec![
            "myjetbrains.com".to_string()
        ],
        fingerprint: vec![
            "is not a registered InCloud YouTrack.".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "azure".to_string(),
        cname: vec![
            ".azurewebsites.net".to_string(),
            ".cloudapp.net".to_string(),
            ".cloudapp.azure.com".to_string(),
            ".trafficmanager.net".to_string(),
            ".blob.core.windows.net".to_string(),
            ".azure-api.net".to_string(),
            ".azurehdinsight.net".to_string(),
            ".azureedge.net".to_string()
        ],
        fingerprint: vec![],
        nxdomain: true
    },
    Fingerprints {
        service: "zendesk".to_string(),
        cname: vec![
            "zendesk.com".to_string()
        ],
        fingerprint: vec![
            "Help Center Closed".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "readme".to_string(),
        cname: vec![
            "readme.io".to_string()
        ],
        fingerprint: vec![
            "Project doesnt exist... yet!".to_string()
        ],
        nxdomain: false
    },
    Fingerprints {
        service: "apigee".to_string(),
        cname: vec![
            "-portal.apigee.net".to_string()
        ],
        fingerprint: vec![],
        nxdomain: true
    },
    Fingerprints {
        service: "smugmug".to_string(),
        cname: vec![
            "domains.smugmug.com".to_string()
        ],
        fingerprint: vec![],
        nxdomain: true
    },
    Fingerprints {
        service: "worksites.net".to_string(),
        cname: vec![
            "".to_string()
        ],
        fingerprint: vec![
            "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.</p>\n<a href=\"https://worksites.net/\">Learn more about Worksites.net".to_string()
        ],
        nxdomain: false
    }]
}

pub fn verify_cname(
    subdomain: String,
    config: &Vec<Fingerprints>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let cname = resolve(subdomain)?;

    for n in config {
        for c in &n.cname {
            if cname.contains(c) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub fn detect(
    url: String,
    output: String,
    ssl: bool,
    verbose: bool,
    manual: bool,
    timeout: u64,
    config: &Vec<Fingerprints>,
) -> Result<(), Box<dyn std::error::Error>> {
    use colored::*;

    log::debug!("Detecting");
    let service = identify(url.clone(), ssl, manual, timeout, config)?;

    if service != "" {
        let out = format!("[{}] {}", service.bright_green().bold(), url);
        println!("{}", out);

        if !output.is_empty() {
            if is_json(output.clone()) {
            } else {
                // write(result, output)
            }
        }
    }

    if service.is_empty() && verbose {
        let out = format!("[{}] {}", "Not Vulnerable".red().bold(), url);
        println!("{}", out);

        if !output.is_empty() {
            if is_json(output) {
                // writeJSON(service, url, output)
            } else {
                // write(result, output)
            }
        }
    }
    Ok(())
}

fn identify(
    subdomain: String,
    force_ssl: bool,
    manual: bool,
    timeout: u64,
    fingerprints: &Vec<Fingerprints>,
) -> Result<String, Box<dyn std::error::Error>> {
    log::debug!("Identifying for {}", subdomain);

    if subdomain.contains("shopify") {
        log::debug!("error=shopify");
    }
    let body = match get(&subdomain, force_ssl, timeout) {
        Ok(body) => body,
        Err(e) if e.is_connect() || e.is_builder() => {
            return Ok(String::new());
        }
        Err(e) => {
            return Err(e.into());
        }
    };

    let mut cname = resolve(&subdomain)?;

    if cname.len() <= 3 {
        cname = String::new();
    }

    let nx = nxdomain(subdomain);

    log::debug!("nxdomain");
    for f in fingerprints {
        // Begin subdomain checks if the subdomain returns NXDOMAIN
        if nx {
            // Check if we can register this domain.
            let dead = available(&cname);
            if dead {
                let service = format!("DOMAIN AVAILABLE - {}", cname);
                return Ok(service);
            }

            // Check if subdomain matches fingerprinted cname
            if f.nxdomain {
                for c in &f.cname {
                    if cname.contains(c) {
                        let service = f.service.to_uppercase();
                        return Ok(service);
                    }
                }
            }

            // Option to always print the CNAME and not check if it's available to be registered.
            if manual && !dead && cname != "" {
                let service = format!("DEAD DOMAIN - {}", cname);
                return Ok(service);
            }
        }

        // Check if body matches fingerprinted response
        for fingerprint in &f.fingerprint {
            if body.contains(fingerprint) {
                let service = f.service.to_uppercase();
                return Ok(service);
            }
        }
    }

    Ok(String::new())
}
