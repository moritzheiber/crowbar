use failure::Error;
use ini::Ini;

use std::path::PathBuf;
use std::env;

pub struct OktawsConfig {
    pub organization: String,
    pub app_id: String,
    pub role: String,
}

fn find_config_file() -> PathBuf {
    let test_paths = vec![
        env::current_dir().unwrap().join(".oktaws"),
        env::home_dir().unwrap().join(".oktaws/config"),
    ];

    if let Some(existing_file) = test_paths.iter().find(|path| path.exists()) {
        existing_file.into()
    } else {
        error!("No config files found, tried {:?}.", test_paths);
        panic!();
    }
}

pub fn fetch_config(profile: &str) -> Result<OktawsConfig, Error> {
    let path_buf = find_config_file();
    let path = path_buf.to_str().unwrap();

    debug!("Using oktaws config file at {}", path);

    let conf = Ini::load_from_file(path)?;

    if let Some(section) = conf.section(Some(profile.to_owned())) {
        Ok(OktawsConfig {
            organization: section.get("organization").unwrap().to_owned(),
            app_id: section.get("app_id").unwrap().to_owned(),
            role: section.get("role").unwrap().to_owned(),
        })
    } else {
        error!("Could not find section '{}' in {}.", profile, path);
        panic!();
    }
}
