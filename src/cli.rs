use crate::config::app::AppProfile;
use crate::utils::LevelFilter;
use anyhow::Result;
use clap::{crate_description, crate_version, Arg, ArgAction, ArgMatches, Command};

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

fn get_matches() -> ArgMatches {
    Command::new("crowbar")
      .version(crate_version!())
      .about(crate_description!())
      .subcommand_required(true)
        .propagate_version(true)
            .subcommand_required(true)      .disable_help_subcommand(true)
      .arg(
          Arg::new("force")
              .short('f')
              .action(ArgAction::SetTrue)
              .long("force")
              .help("Forces re-entering of your Okta credentials"),
      )
      .arg(
          Arg::new("log-level")
              .short('l')
              .long("log-level")
              .value_name("LOG_LEVEL")
              .help("Set the log level")
              .value_parser(clap::builder::PossibleValuesParser::new(["info", "debug", "trace"]))
              .default_value("info")
      )
      .arg(
          Arg::new("location")
              .short('c')
              .long("config")
              .value_name("CONFIG")
              .help("The location of the configuration file"),
      )
      .subcommand(
          Command::new("profiles")
          .about("Add or delete profiles")
          .arg_required_else_help(true)
          .disable_help_subcommand(true)
        .subcommand(
              Command::new("add")
              .about("Add a profile")
              .arg(
                  Arg::new("provider")
                      .short('p')
                      .long("provider")
                      .value_name("PROVIDER")
                      .required(true)
                      .help("The name of the provider to use")
                      .value_parser(clap::builder::PossibleValuesParser::new(["okta","jumpcloud"]))
              )
              .arg(
                  Arg::new("username")
                      .short('u')
                      .long("username")
                      .value_name("USERNAME")
                      .required(true)
                      .help("The username to use for logging into your IdP"),
              )
              .arg(
                  Arg::new("url")
                      .long("url")
                      .value_name("URL")
                      .required(true)
                      .help("The URL used to log into AWS from your IdP"),
              )
              .arg(
                  Arg::new("role")
                      .long("r")
                      .value_name("ROLE")
                      .required(false)
                      .help("The AWS role to assume after a successful login (Optional)"),
              )
              .arg(
                  Arg::new("profile").required(true).help("The name of the profile"),
              ),
          )
          .subcommand(
              Command::new("list")
              .about("List all profiles")
          )
          .subcommand(
              Command::new("delete")
              .about("Delete a profile")
              .arg(
                  Arg::new("profile").required(true)
              ),
          )
      )
      .subcommand(
          Command::new("creds")
          .about("Exposed temporary credentials on the command line using the credential_process JSON layout")
          .arg(
              Arg::new("print")
              .short('p')
              .action(ArgAction::SetTrue)
              .long("print")
              .help("Print credentials to stdout"),
          )
          .arg(
              Arg::new("profile").required(true)
          ),
      )
      .subcommand(
        Command::new("exec")
        .about("Exposed temporary credentials on the command line by executing a child process with environment variables")
        .arg(
            Arg::new("profile").required(true)
        )
        .arg(
            Arg::new("command")
            .last(true)
            .action(ArgAction::Append)
        ),
    )
    .get_matches()
}

pub fn config() -> Result<CliConfig> {
    let matches = get_matches();
    let cli_action = select_action(&matches);
    let location = matches.get_one::<String>("location").map(|c| c.to_string());
    let log_level_from_matches = matches.get_one::<String>("log-level").unwrap();

    Ok(CliConfig {
        force: matches.get_flag("force"),
        location,
        log_level: select_log_level(log_level_from_matches),
        action: cli_action?,
    })
}

fn select_action(matches: &ArgMatches) -> Result<CliAction> {
    match matches.subcommand() {
        Some(("exec", m)) => {
            let parts = m
                .get_many::<String>("command")
                .unwrap()
                .map(|o| o.to_owned())
                .collect();
            Ok(CliAction::Exec {
                command: parts,
                profile: m.get_one::<String>("profile").unwrap().to_string(),
            })
        }
        Some(("creds", m)) => Ok(CliAction::Creds {
            print: m.get_flag("print"),
            profile: m.get_one::<String>("profile").unwrap().to_string(),
        }),
        Some(("profiles", action)) => Ok(CliAction::Profiles {
            action: match action.subcommand() {
                Some(("add", action)) => CliSubAction::Add {
                    profile: AppProfile::from(action),
                },
                Some(("delete", action)) => CliSubAction::Delete {
                    profile_name: action.get_one::<String>("profile").unwrap().to_string(),
                },
                Some(("list", _)) => CliSubAction::List,
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
