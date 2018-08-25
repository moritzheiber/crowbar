use credentials;
use failure::Error;
use okta::client::Client;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use toml;
use try_from::TryFrom;

use okta::users::AppLink;
use okta::Organization as OktaOrganization;

#[derive(Clone, Debug)]
pub struct Organization {
    pub okta_organization: OktaOrganization,
    pub username: String,
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

#[derive(Debug)]
pub struct Profile {
    pub id: String,
    pub application: AppLink,
    pub role: String,
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
            Some(filename) => {
                let file_contents = File::open(path)?
                    .bytes()
                    .map(|b| b.map_err(|e| e.into()))
                    .collect::<Result<Vec<u8>, Error>>()?;

                let file_toml: toml::Value = toml::from_slice(&file_contents)?;

                let okta_organization = filename.parse()?;

                Ok(Organization {
                    username: file_toml
                        .get("username")
                        .map(|u| u.clone().try_into().map_err(|e| e.into()))
                        .unwrap_or_else(|| credentials::get_username(&okta_organization))?,
                    role: file_toml
                        .get("role")
                        .map(|r| r.clone().try_into())
                        .unwrap_or(Ok(None))?,
                    profiles: file_toml
                        .get("profiles")
                        .map(|p| p.clone().try_into())
                        .unwrap_or(Ok(HashMap::new()))?,
                    okta_organization,
                })
            }
            None => bail!("Organization name not parseable from {:?}", path.as_ref()),
        }
    }
}

impl Organization {
    pub fn profiles<'a>(
        &'a self,
        client: &Client,
    ) -> Result<impl Iterator<Item = Profile> + 'a, Error> {
        let okta_apps = client.app_links(None)?;

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
                                self.okta_organization.name, id
                            );
                            None
                        }
                    }
                }
                (&None, &ProfileSpec::Detailed { role: None, .. }) | (&None, _) => {
                    error!(
                        "No role defined on profile {}/{} and no default role specified",
                        self.okta_organization.name, id
                    );
                    None
                }
            }
        }))
    }
}
