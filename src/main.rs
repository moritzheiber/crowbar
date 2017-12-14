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
    pretty_env_logger::init().unwrap();

    let opt = Opt::from_args();
    debug!("Options: {:?}", opt);

    let oktaws_config = config::fetch_config(&opt.profile).unwrap();

    let (username, password) = credentials::get_credentials(opt.force_new);

    let session_token = okta::login(&oktaws_config.organization, &username, &password)
        .unwrap()
        .session_token;
    debug!("Session Token: {}", session_token);

    let saml_assertion = okta::fetch_saml(
        &oktaws_config.organization,
        &oktaws_config.app_id,
        &session_token,
    ).unwrap();
    debug!("SAML assertion: {}", saml_assertion);

    let saml_attributes = aws::find_saml_attributes(&saml_assertion).unwrap();
    debug!("SAML attributes: {:?}", saml_attributes);

    let principal_arn = saml_attributes.get(&oktaws_config.role).unwrap();
    debug!("Principal ARN: {}", principal_arn);

    let credentials = aws::assume_role(principal_arn, &oktaws_config.role, &saml_assertion)
        .unwrap()
        .credentials
        .unwrap();
    debug!("Credentials: {:?}", credentials);

    aws::set_credentials(&opt.profile, &credentials).unwrap();
    credentials::set_credentials(&username, &password);
}
