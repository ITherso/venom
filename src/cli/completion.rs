use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellCompletion {
    pub shell_type: ShellType,
    pub commands: Vec<String>,
    pub options: Vec<String>,
    pub subcommands: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionScript {
    pub shell: ShellType,
    pub script: String,
    pub install_path: String,
}

impl ShellCompletion {
    pub fn new(shell_type: ShellType) -> Self {
        Self {
            shell_type,
            commands: vec![
                "scan".to_string(),
                "proxy".to_string(),
                "exploit".to_string(),
                "report".to_string(),
                "config".to_string(),
            ],
            options: vec![
                "--help".to_string(),
                "--version".to_string(),
                "--verbose".to_string(),
                "--output".to_string(),
                "--config".to_string(),
            ],
            subcommands: vec![
                "start".to_string(),
                "stop".to_string(),
                "status".to_string(),
                "list".to_string(),
            ],
        }
    }

    pub fn generate_bash(&self) -> String {
        let commands = self.commands.join(" ");
        let options = self.options.join(" ");

        format!(
            r#"_venom_completion() {{
    local cur prev opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"

    opts="{} {}"

    if [[ ${{cur}} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${{opts}}" -- ${{cur}}) )
        return 0
    fi

    COMPREPLY=( $(compgen -W "{}" -- ${{cur}}) )
    return 0
}}

complete -o bashdefault -o default -o nospace -F _venom_completion venom
"#,
            commands, options, commands
        )
    }

    pub fn generate_zsh(&self) -> String {
        let commands = self.commands.join("' '");

        format!(
            r#"#compdef venom

_venom() {{
  local -a commands
  commands=(
    '{}':''
  )

  _arguments \
    '(-h --help){{-h,--help}}[show help]' \
    '(-v --version){{-v,--version}}[show version]' \
    '*::command:->command' \
    '*::options:->options'
}}

_venom
"#,
            commands
        )
    }

    pub fn generate_fish(&self) -> String {
        let commands = self.commands.iter()
            .map(|c| format!("complete -c venom -n '__fish_seen_subcommand_from {}' -f", c))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"# Fish completion for venom

# Main commands
{}

# Global options
complete -c venom -s h -l help -d "Show help"
complete -c venom -s v -l version -d "Show version"
complete -c venom -s V -l verbose -d "Verbose output"
"#,
            commands
        )
    }

    pub fn generate_powershell(&self) -> String {
        let commands = self.commands.join("', '");

        format!(
            r#"# PowerShell completion for venom

$__VenomCommands = @('{}'
)

Register-ArgumentCompleter -CommandName venom -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)

    $__VenomCommands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        New-Object System.Management.Automation.CompletionResult $_
    }}
}}
"#,
            commands
        )
    }

    pub fn get_install_instruction(&self) -> String {
        match self.shell_type {
            ShellType::Bash => "echo 'eval \"$(venom completion bash)\"' >> ~/.bashrc".to_string(),
            ShellType::Zsh => "echo 'eval \"$(venom completion zsh)\"' >> ~/.zshrc".to_string(),
            ShellType::Fish => "venom completion fish | source".to_string(),
            ShellType::PowerShell => "$PROFILE contents should include: venom completion powershell | Out-String | Invoke-Expression".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_completion_generation() {
        let completion = ShellCompletion::new(ShellType::Bash);
        let script = completion.generate_bash();
        assert!(script.contains("_venom_completion"));
    }

    #[test]
    fn test_zsh_completion_generation() {
        let completion = ShellCompletion::new(ShellType::Zsh);
        let script = completion.generate_zsh();
        assert!(script.contains("compdef"));
    }

    #[test]
    fn test_fish_completion_generation() {
        let completion = ShellCompletion::new(ShellType::Fish);
        let script = completion.generate_fish();
        assert!(script.contains("complete -c venom"));
    }
}
