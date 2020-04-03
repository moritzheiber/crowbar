use crate::credentials::aws::AwsCredentials;
use anyhow::Result;
use std::collections::HashMap;
use std::env;
use std::process::Child as ExecutorResult;
use std::process::{Command, Stdio};

pub struct Executor {
    command: Option<Vec<String>>,
    credentials: AwsCredentials,
    stdout: Stdio,
    stderr: Stdio,
    stdin: Stdio,
}

impl Default for Executor {
    fn default() -> Executor {
        Executor {
            command: None,
            credentials: AwsCredentials::default(),
            stdout: Stdio::inherit(),
            stderr: Stdio::inherit(),
            stdin: Stdio::inherit(),
        }
    }
}

impl Executor {
    pub fn set_command(mut self, command: Vec<String>) -> Self {
        self.command = Some(command);
        self
    }

    pub fn set_credentials(mut self, credentials: AwsCredentials) -> Self {
        self.credentials = credentials;
        self
    }

    pub fn run(self) -> Result<ExecutorResult> {
        let mut variables: HashMap<String, Option<String>> = self.credentials.into();
        // We don't want to pollute the environment with the expiration time
        variables.remove_entry("expiration");

        let variables: HashMap<String, String> = variables
            .iter()
            .map(|(k, v)| (format!("AWS_{}", k.to_uppercase()), v.clone().unwrap()))
            .collect();

        let command = self.command.unwrap().join(" ");
        let shell = shell()?;

        Command::new(&shell[0])
            .arg(&shell[1])
            .arg(command)
            .stdin(self.stdin)
            .stderr(self.stderr)
            .stdout(self.stdout)
            .envs(variables)
            .spawn()
            .map_err(|e| e.into())
    }
}

fn shell() -> Result<Vec<String>> {
    if cfg!(windows) {
        Ok(vec!["cmd.exec".into(), "/C".into()])
    } else if let Ok(shell) = env::var("SHELL") {
        Ok(vec![shell, "-c".into()])
    } else {
        Ok(vec!["/bin/bash".into(), "-c".into()])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn runs_with_credentials() -> Result<()> {
        let variable = os_specific_var("AWS_ACCESS_KEY_ID");
        let result = get_stdout_for_variable(variable)?;

        assert_eq!(String::from("some_key"), result.trim());

        Ok(())
    }

    #[test]
    fn removes_expiration() -> Result<()> {
        let variable = os_specific_var("AWS_EXPIRATION");
        let result = get_stdout_for_variable(variable)?;
        assert_ne!("some_key", result.trim());

        Ok(())
    }

    fn create_credentials() -> AwsCredentials {
        AwsCredentials {
            version: 1,
            access_key_id: Some("some_key".to_string()),
            secret_access_key: Some("some_secret".to_string()),
            session_token: Some("some_token".to_string()),
            expiration: Some("2038-01-01T10:10:10Z".to_string()),
        }
    }

    fn os_specific_var(s: &str) -> String {
        if cfg!(windows) {
            format!("%{}%", s)
        } else {
            format!("\"${{{}}}\"", s)
        }
    }

    fn get_stdout_for_variable(variable: String) -> Result<String> {
        let variable = format!("echo {}", variable);
        let command = Some(vec![variable]);
        let credentials = create_credentials();
        let executor = Executor {
            command,
            credentials: credentials.clone(),
            stdout: Stdio::piped(),
            ..Default::default()
        };

        let result = executor.run()?.wait_with_output()?;

        Ok(String::from_utf8_lossy(&result.stdout).into())
    }
}
