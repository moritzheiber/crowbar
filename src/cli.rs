use crate::config::app::AppProfile;
use crate::utils::LevelFilter;
use anyhow::Result;
use clap::{crate_description, crate_version, App, AppSettings, Arg, ArgMatches, SubCommand};

#[derive(Debug)]
pub struct CliConfig {
    pub force: bool,
    pub location: Option<String>,
    pub log_level: LevelFilter,
    pub action: CliAction,
}

#[derive(Debug)]
pub enum CliAction {
    Profiles {
        action: CliSubAction,
    },
    Exec {
        command: Vec<String>,
        profile: String,
    },
    Creds {
        profile: String,
        print: bool,
    },
}

#[derive(Debug)]
pub enum CliSubAction {
    Add { profile: AppProfile },
    Delete { profile_name: String },
    List,
}

fn get_matches() -> ArgMatches<'static> {
    App::new("crowbar")
      .version(crate_version!())
      .about(crate_description!())
      .setting(AppSettings::SubcommandRequiredElseHelp)
      .setting(AppSettings::GlobalVersion)
      .setting(AppSettings::UnifiedHelpMessage)
      .setting(AppSettings::DisableHelpSubcommand)
      .arg(
          Arg::with_name("force")
              .short("f")
              .takes_value(false)
              .long("force")
              .help("Forces re-entering of your IdP credentials"),
      )
      .arg(
          Arg::with_name("log-level")
              .short("l")
              .long("log-level")
              .value_name("LOG_LEVEL")
              .help("Set the log level")
              .possible_values(&["info", "debug", "trace"])
              .default_value("info")
              .takes_value(true),
      )
      .arg(
          Arg::with_name("location")
              .short("c")
              .long("config")
              .value_name("CONFIG")
              .help("The location of the configuration file"),
      )
      .subcommand(
          SubCommand::with_name("profiles")
          .about("Add or delete profiles")
          .setting(AppSettings::SubcommandRequiredElseHelp)
          .setting(AppSettings::DisableHelpSubcommand)
          .subcommand(
              SubCommand::with_name("add")
              .about("Add a profile")
              .arg(
                  Arg::with_name("provider")
                      .short("p")
                      .long("provider")
                      .value_name("PROVIDER")
                      .required(true)
                      .help("The name of the provider to use")
                      .possible_values(&["okta","jumpcloud","adfs"])
                      .takes_value(true),
              )
              .arg(
                  Arg::with_name("username")
                      .short("u")
                      .long("username")
                      .value_name("USERNAME")
                      .required(true)
                      .help("The username to use for logging into your IdP"),
              )
              .arg(
                  Arg::with_name("url")
                      .long("url")
                      .value_name("URL")
                      .required(true)
                      .help("The URL used to log into AWS from your IdP"),
              )
              .arg(
                  Arg::with_name("role")
                      .long("r")
                      .value_name("ROLE")
                      .required(false)
                      .help("The AWS role to assume after a successful login (Optional)"),
              )
              .arg(
                  Arg::with_name("profile").required(true).help("The name of the profile"),
              ),
          )
          .subcommand(
              SubCommand::with_name("list")
              .about("List all profiles")
          )
          .subcommand(
              SubCommand::with_name("delete")
              .about("Delete a profile")
              .arg(
                  Arg::with_name("profile").required(true)
              ),
          )
      )
      .subcommand(
          SubCommand::with_name("creds")
          .about("Exposed temporary credentials on the command line using the credential_process JSON layout")
          .arg(
              Arg::with_name("print")
              .short("p")
              .takes_value(false)
              .long("print")
              .help("Print credentials to stdout"),
          )
          .arg(
              Arg::with_name("profile").required(true)
          ),
      )
      .subcommand(
        SubCommand::with_name("exec")
        .about("Exposed temporary credentials on the command line by executing a child process with environment variables")
        .arg(
            Arg::with_name("profile").required(true)
        )
        .arg(
            Arg::with_name("command")
            .takes_value(true)
            .last(true)
            .multiple(true)
        ),
    )
    .get_matches()
}

pub fn config() -> Result<CliConfig> {
    let matches = get_matches();
    let cli_action = select_action(&matches);
    let location = match matches.value_of("config") {
        Some(c) => Some(c.to_owned()),
        _ => None,
    };
    let log_level_from_matches = matches.value_of("log-level").unwrap();

    Ok(CliConfig {
        force: matches.is_present("force"),
        location,
        log_level: select_log_level(log_level_from_matches),
        action: cli_action?,
    })
}

fn select_action(matches: &ArgMatches) -> Result<CliAction> {
    match matches.subcommand() {
        ("exec", Some(m)) => {
            let parts: Vec<_> = m
                .values_of("command")
                .unwrap()
                .map(|o| o.to_owned())
                .collect();
            Ok(CliAction::Exec {
                command: parts,
                profile: m.value_of("profile").unwrap().to_owned(),
            })
        }
        ("creds", Some(m)) => Ok(CliAction::Creds {
            print: m.is_present("print"),
            profile: m.value_of("profile").unwrap().to_owned(),
        }),
        ("profiles", Some(action)) => Ok(CliAction::Profiles {
            action: match action.subcommand() {
                ("add", Some(action)) => CliSubAction::Add {
                    profile: AppProfile::from(action),
                },
                ("delete", Some(action)) => CliSubAction::Delete {
                    profile_name: action.value_of("profile").unwrap().to_owned(),
                },
                ("list", Some(_action)) => CliSubAction::List,
                _ => unreachable!(),
            },
        }),
        _ => unreachable!(),
    }
}

fn select_log_level(selected_level: &str) -> LevelFilter {
    match selected_level {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        _ => LevelFilter::Info,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn log_levels_as_expected() {
        assert_eq!(LevelFilter::Info, select_log_level("info"));
        assert_eq!(LevelFilter::Debug, select_log_level("debug"));
        assert_eq!(LevelFilter::Trace, select_log_level("trace"));
        assert_eq!(LevelFilter::Info, select_log_level("something"))
    }
}
