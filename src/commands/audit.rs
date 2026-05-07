use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::cli::AuditArgs;
use crate::config;
use crate::crypto::audit::{self, Severity};
use crate::vault::storage::VaultStorage;

fn resolve_vault_path(override_path: Option<&Path>) -> std::path::PathBuf {
    override_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(config::vault_path)
}

pub fn handle_audit(args: &AuditArgs, vault_path_override: Option<&Path>) -> Result<()> {
    let path = resolve_vault_path(vault_path_override);
    let password = rpassword::prompt_password("Master password: ")?;
    let vault = VaultStorage::load(&path, password.as_bytes()).map_err(|e| anyhow::anyhow!(e))?;

    let report = audit::audit_vault(&vault);

    // Print score
    let score_color = if report.score >= 80 {
        report.score.to_string().green()
    } else if report.score >= 50 {
        report.score.to_string().yellow()
    } else {
        report.score.to_string().red()
    };

    println!("\n{} Vault Security Audit", "===".bold());
    println!("Total entries: {}", report.total_entries);
    println!("Security score: {}/100\n", score_color);

    fn print_issues(title: &str, issues: &[audit::AuditIssue]) {
        if issues.is_empty() {
            return;
        }
        println!("{}:", title.bold());
        for issue in issues {
            let severity_str = match issue.severity {
                Severity::Critical => format!("[{}]", issue.severity).red(),
                Severity::Warning => format!("[{}]", issue.severity).yellow(),
                Severity::Info => format!("[{}]", issue.severity).cyan(),
            };
            println!(
                "  {} {}: {}",
                severity_str,
                issue.entry_name.bold(),
                issue.description
            );
        }
        println!();
    }

    print_issues("Expired / Expiring", &report.expiring_entries);
    print_issues("Weak Passwords", &report.weak_passwords);
    print_issues("Duplicate Passwords", &report.duplicate_passwords);
    print_issues("Short Passwords", &report.short_passwords);
    print_issues("Old Passwords", &report.old_passwords);
    print_issues("Reused Usernames", &report.reused_usernames);

    let total_issues = report.expiring_entries.len()
        + report.weak_passwords.len()
        + report.duplicate_passwords.len()
        + report.short_passwords.len()
        + report.old_passwords.len()
        + report.reused_usernames.len();

    if total_issues == 0 {
        println!("{} No issues found. Your vault looks great!", "✓".green());
    } else {
        println!(
            "{} Found {} issue(s) across your vault.",
            "!".yellow(),
            total_issues
        );
    }

    // Breach check
    if args.breach {
        println!(
            "\n{}",
            "Checking passwords against Have I Been Pwned...".bold()
        );
        println!("(Only the first 5 characters of the SHA-1 hash are sent)\n");

        for entry in &vault.entries {
            print!("  Checking {}... ", entry.name);
            std::io::Write::flush(&mut std::io::stdout())?;

            match audit::check_breach(&entry.password) {
                Ok(Some(count)) => {
                    println!("{}", format!("EXPOSED in {count} breach(es)!").red().bold());
                }
                Ok(None) => {
                    println!("{}", "OK".green());
                }
                Err(e) => {
                    println!("{}", format!("Error: {e}").yellow());
                }
            }
        }
        println!();
    }

    Ok(())
}
