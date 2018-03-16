use failure::Error;
use serde_json;
use toml;

use std::collections::HashMap;
use std::iter::FromIterator;
use path_abs::{PathDir, PathFile, PathType};
use std::ffi::OsStr;

#[serde(default)]
#[derive(Clone, StructOpt, Debug, Deserialize, Default)]
pub struct Config {
    /// Profile to update
    pub profile: Option<String>,

    /// Okta organization to use
    #[structopt(short = "o", long = "organization")]
    pub organization: Option<String>,

    /// AWS role to use by default
    #[structopt(short = "r", long = "role")]
    pub role: Option<String>,

    /// Forces new credentials
    #[structopt(short = "f", long = "force-new")]
    pub force_new: bool,

    /// Specify Okta username (will prompt if not provided)
    #[structopt(short = "u", long = "username")]
    pub username: Option<String>,

    /// Sets the level of verbosity
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    #[serde(skip)]
    pub verbosity: u64,

    /// Profile information (in json object format)
    #[structopt(long = "profiles", parse(try_from_str = "serde_json::from_str"),
                default_value = "{}")]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ProfileConfig {
    Simple(String),
    Detailed {
        application: String,
        role: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct Profile {
    pub id: String,
    pub application: String,
    pub role: String,
}

impl Config {
    pub fn from_file(path: &PathFile) -> Result<Self, Error> {
        let config: Config = toml::from_str(&path.read_string()?)?;
        let org_config = Config {
            organization: path.as_path()
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned()),
            ..Config::default()
        };

        Ok(config.merge(org_config))
    }

    pub fn from_dir(dir_path: &PathDir) -> Result<Vec<Result<Config, Error>>, Error> {
        let mut configs = Vec::new();

        for path in dir_path.list()? {
            if let Ok(PathType::File(path)) = path {
                if Some(OsStr::new("toml")) == path.as_path().extension() {
                    configs.push(Config::from_file(&path));
                }
            }
        }

        Ok(configs)
    }

    pub fn merge(self, other: Self) -> Self {
        Self {
            profile: self.profile.or(other.profile),
            organization: self.organization.or(other.organization),
            role: self.role.or(other.role),
            force_new: self.force_new || other.force_new,
            verbosity: self.verbosity + other.verbosity,
            username: self.username.or(other.username),
            profiles: HashMap::from_iter(
                self.profiles.into_iter().chain(other.profiles.into_iter()),
            ),
        }
    }

    pub fn profiles(&self) -> Vec<Result<Profile, Error>> {
        let mut profiles = Vec::new();

        for (id, profile_config) in &self.profiles {
            let profile = match (&self.role, profile_config) {
                (&Some(ref role), &ProfileConfig::Simple(ref app))
                | (
                    _,
                    &ProfileConfig::Detailed {
                        application: ref app,
                        role: Some(ref role),
                    },
                )
                | (
                    &Some(ref role),
                    &ProfileConfig::Detailed {
                        application: ref app,
                        role: None,
                    },
                ) => Ok(Profile {
                    id: id.to_owned(),
                    application: app.to_owned(),
                    role: role.to_owned(),
                }),
                (&None, &ProfileConfig::Detailed { role: None, .. }) | (&None, _) => Err(
                    format_err!("No role defined on {} and no default role specified", id),
                ),
            };

            profiles.push(profile)
        }

        profiles
    }
}
