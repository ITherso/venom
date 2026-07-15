use super::commands::{Command, CommandContext};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CommandParser {
    command_aliases: HashMap<String, String>,
}

impl CommandParser {
    pub fn new() -> Self {
        let mut aliases = HashMap::new();

        // Scan aliases
        aliases.insert("s:start".to_string(), "scan:start".to_string());
        aliases.insert("s:status".to_string(), "scan:status".to_string());
        aliases.insert("s:stop".to_string(), "scan:stop".to_string());

        // Backup aliases
        aliases.insert("b:create".to_string(), "backup:create".to_string());
        aliases.insert("b:restore".to_string(), "backup:restore".to_string());
        aliases.insert("b:list".to_string(), "backup:list".to_string());

        // Deployment aliases
        aliases.insert("d:status".to_string(), "deploy:status".to_string());
        aliases.insert("d:health".to_string(), "deploy:health".to_string());

        // RBAC aliases
        aliases.insert("r:create".to_string(), "role:create".to_string());
        aliases.insert("u:create".to_string(), "user:create".to_string());

        // DR aliases
        aliases.insert("dr:drill".to_string(), "dr:drill:start".to_string());

        Self {
            command_aliases: aliases,
        }
    }

    pub fn parse(&self, input: &str) -> Result<CommandContext, String> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();

        if parts.is_empty() {
            return Err("No command provided".to_string());
        }

        let command_str = parts[0];
        let resolved_command = self.resolve_alias(command_str);

        let cmd = Command::from_string(&resolved_command)
            .ok_or_else(|| format!("Unknown command: {}", command_str))?;

        let mut context = CommandContext::new(resolved_command);
        let mut args = Vec::new();
        let mut flags = HashMap::new();
        let mut i = 1;

        while i < parts.len() {
            let part = parts[i];

            if part.starts_with("--") {
                let flag_name = &part[2..];
                if let Some(eq_pos) = flag_name.find('=') {
                    let key = flag_name[..eq_pos].to_string();
                    let value = flag_name[eq_pos + 1..].to_string();
                    flags.insert(key, value);
                } else if i + 1 < parts.len() && !parts[i + 1].starts_with("--") {
                    i += 1;
                    let key = flag_name.to_string();
                    let value = parts[i].to_string();
                    flags.insert(key, value);
                } else {
                    flags.insert(flag_name.to_string(), "true".to_string());
                }
            } else if part.starts_with("-") && part.len() > 1 {
                let flag_char = &part[1..];
                if i + 1 < parts.len() && !parts[i + 1].starts_with("-") {
                    i += 1;
                    let key = flag_char.to_string();
                    let value = parts[i].to_string();
                    flags.insert(key, value);
                } else {
                    flags.insert(flag_char.to_string(), "true".to_string());
                }
            } else {
                args.push(part.to_string());
            }

            i += 1;
        }

        context.args = args;
        context.flags = flags;

        Ok(context)
    }

    fn resolve_alias(&self, command: &str) -> String {
        self.command_aliases
            .get(command)
            .cloned()
            .unwrap_or_else(|| command.to_string())
    }

    pub fn add_alias(&mut self, alias: String, command: String) {
        self.command_aliases.insert(alias, command);
    }

    pub fn get_suggestions(&self, partial: &str) -> Vec<String> {
        let mut suggestions = self.command_aliases
            .keys()
            .filter(|cmd| cmd.starts_with(partial))
            .cloned()
            .collect::<Vec<_>>();

        let base_commands = [
            "scan", "backup", "deploy", "sla", "audit", "role", "user",
            "permission", "dr", "status", "config", "help", "version", "health",
        ];

        for cmd in base_commands.iter() {
            if cmd.starts_with(partial) {
                suggestions.push(cmd.to_string());
            }
        }

        suggestions
    }
}

impl Default for CommandParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_command() {
        let parser = CommandParser::new();
        let result = parser.parse("scan:start");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_with_flags() {
        let parser = CommandParser::new();
        let result = parser.parse("scan:start --target example.com --timeout 30");
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.get_flag("target"), Some(&"example.com".to_string()));
    }

    #[test]
    fn test_parse_with_args() {
        let parser = CommandParser::new();
        let result = parser.parse("backup:restore backup123 /restore/path");
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.args.len(), 2);
    }

    #[test]
    fn test_alias_resolution() {
        let parser = CommandParser::new();
        let result = parser.parse("s:start");
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.command, "scan:start");
    }

    #[test]
    fn test_suggestions() {
        let parser = CommandParser::new();
        let suggestions = parser.get_suggestions("scan");
        assert!(!suggestions.is_empty());
    }
}
