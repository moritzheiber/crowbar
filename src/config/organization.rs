use credentials;
use failure::Error;
use okta::client::OktaClient;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use toml;
use try_from::TryFrom;

use config::profile::Profile;

#[serde(default)]
#[derive(Clone, Debug, Deserialize, Default)]
pub struct Organization {
    #[serde(skip)]
    pub name: String,
    pub username: Option<String>,
    role: Option<String>,
    profiles: HashMap<String, ProfileSpec>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ProfileSpec {
    Simple(String),
    Detailed {
        application: String,
        role: Option<String>,
    },
}

impl<'a, P> TryFrom<&'a P> for Organization
where
    P: ?Sized + AsRef<Path>,
{
    type Err = Error;

    fn try_from(path: &'a P) -> Result<Self, Self::Err> {
        match path
            .as_ref()
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
        {
            Some(name) => {
                let file_contents = File::open(path)?
                    .bytes()
                    .map(|b| b.map_err(|e| e.into()))
                    .collect::<Result<Vec<u8>, Error>>()?;

                let mut organization: Organization = toml::from_slice(&file_contents)?;
                organization.name = name;

                if organization.username.is_none() {}

                Ok(organization)
            }
            None => bail!("Organization name not parseable from {:?}", path.as_ref()),
        }
    }
}

impl Organization {
    pub fn credentials(&self, force_new: bool) -> Result<(String, String), Error> {
        let username = match self.username {
            Some(ref username) => username.to_owned(),
            None => credentials::get_username(&self.name)?,
        };

        let password = credentials::get_password(&self.name, &username, force_new)?;

        Ok((username, password))
    }

    pub fn okta_client(&self) -> OktaClient {
        OktaClient::new(self.name.clone())
    }

    pub fn profiles<'a>(
        &'a self,
        client: &OktaClient,
    ) -> Result<impl Iterator<Item = Profile> + 'a, Error> {
        let okta_apps = client.get_apps()?;

        Ok(self.profiles.iter().filter_map(move |(id, profile_spec)| {
            match (&self.role, &profile_spec) {
                (&Some(ref role), &ProfileSpec::Simple(ref app))
                | (
                    _,
                    &ProfileSpec::Detailed {
                        application: ref app,
                        role: Some(ref role),
                    },
                )
                | (
                    &Some(ref role),
                    &ProfileSpec::Detailed {
                        application: ref app,
                        role: None,
                    },
                ) => {
                    let app_link = okta_apps.clone().into_iter().find(|app_link| {
                        app_link.app_name == "amazon_aws" && &app_link.label == app
                    });

                    match app_link {
                        Some(application) => Some(Profile {
                            id: id.to_owned(),
                            application,
                            role: role.to_owned(),
                        }),
                        None => {
                            error!(
                                "Could not find Okta application for profile {}/{}",
                                self.name, id
                            );
                            None
                        }
                    }
                }
                (&None, &ProfileSpec::Detailed { role: None, .. }) | (&None, _) => {
                    error!(
                        "No role defined on profile {}/{} and no default role specified",
                        self.name, id
                    );
                    None
                }
            }
        }))
    }
}
