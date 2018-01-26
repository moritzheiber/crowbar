extern crate base64;
extern crate failure;
extern crate ini;
extern crate keyring;
#[macro_use]
extern crate log;
extern crate pretty_env_logger;
extern crate quick_xml;
extern crate reqwest;
extern crate rpassword;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_sts;
extern crate scraper;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
#[macro_use]
extern crate text_io;
extern crate username;

use structopt::StructOpt;

mod okta;
mod aws;
mod config;
mod credentials;

#[derive(StructOpt, Debug)]
#[structopt(name = "oktaws", about = "Generates temporary AWS credentials with Okta.")]
struct Opt {
    #[structopt(help = "Which profile to update")] profile: String,
    #[structopt(short = "f", long = "force-new", help = "Force new credentials")] force_new: bool,
}

fn main() {
    pretty_env_logger::init()
        .expect("Error initializing logger");

    let opt = Opt::from_args();
    debug!("Options: {:?}", opt);

    let oktaws_config = config::fetch_config(&opt.profile)
        .expect("Error fetching config");

    let (username, password) = credentials::get_credentials(opt.force_new);

    let session_token = okta::login(&oktaws_config.organization, &username, &password)
        .expect("Error logging into Okta")
        .session_token;
    debug!("Session Token: {}", session_token);

    let saml_assertion = okta::fetch_saml(
        &oktaws_config.organization,
        &oktaws_config.app_id,
        &session_token,
    ).expect("Error fetching SAML assertion from Okta");
    debug!("SAML assertion: {}", saml_assertion);

    let saml_attributes = aws::find_saml_attributes(&saml_assertion)
        .expect("Error finding SAML attributes");
    debug!("SAML attributes: {:?}", saml_attributes);

    let principal_arn = saml_attributes.get(&oktaws_config.role)
        .expect("Error getting the principal ARN from SAML attributes");
    debug!("Principal ARN: {}", principal_arn);

    let credentials = aws::assume_role(principal_arn, &oktaws_config.role, &saml_assertion)
        .expect("Error assuming role in AWS")
        .credentials
        .expect("Error fetching credentials from assumed AWS role");
    debug!("Credentials: {:?}", credentials);

    aws::set_credentials(&opt.profile, &credentials)
        .expect("Error setting AWS credentials");
    credentials::set_credentials(&username, &password);
}
