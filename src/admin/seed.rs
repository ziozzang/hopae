//! `admin.users[]` as seeded grants (ADR-0016): the entries keep their
//! original key, the import runs in one store transaction (at start and by
//! `hopae admin import`), and `--check` previews the same rule read-only.

use std::time::Duration;

use crate::config::{AdminRoleCfg, AdminUserEntry};
use crate::crypto::{Clock, Rng};
use crate::event::types::{Event, EventBuilder, EventKind, Outcome, reasons};
use crate::identity::types::{NormalizedEmail, UserId};
use crate::store::types::{
    AdminGrant, Deadline, ForceTarget, GrantImportReport, GrantTarget, SeedEntry, SeedKey, skip,
};
use crate::store::{AdminRole, Directory, StoreResult, UserStatus};

/// The longest note a grant carries (characters).
pub const NOTE_MAX_CHARS: usize = 256;

/// The deadline of the import transaction.
pub const IMPORT_DEADLINE: Duration = Duration::from_secs(30);

/// `admin.users[]` as store entries, plus the entries that could not be read
/// (validation rejects these before they get here; kept as a defensive path).
pub struct Seed {
    pub entries: Vec<SeedEntry>,
    pub malformed: Vec<(usize, String)>,
}

/// A note as stored: control characters become `?`, nothing else changes; an
/// empty note is no note.
pub fn sanitize_note(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if t.is_empty() { None } else { Some(t) }
}

fn role(r: Option<AdminRoleCfg>) -> AdminRole {
    match r {
        Some(AdminRoleCfg::Viewer) => AdminRole::Viewer,
        Some(AdminRoleCfg::Admin) | None => AdminRole::Admin,
    }
}

/// Every entry of the file with its position and its key as written.
pub fn entries(users: &[AdminUserEntry]) -> Seed {
    let mut out = Seed {
        entries: Vec::new(),
        malformed: Vec::new(),
    };
    for (index, u) in users.iter().enumerate() {
        let id = u.user_id.as_deref().filter(|s| !s.is_empty());
        let email = match u.email.as_deref().filter(|s| !s.is_empty()) {
            Some(e) => match NormalizedEmail::parse(e) {
                Ok(e) => Some(e),
                Err(_) => {
                    out.malformed
                        .push((index, "email is not a valid address".to_string()));
                    continue;
                }
            },
            None => None,
        };
        if let Some(id) = id
            && !crate::config::valid_user_id(id)
        {
            out.malformed
                .push((index, "user_id is not a valid user id".to_string()));
            continue;
        }
        let key = match (id, email) {
            (Some(id), Some(email)) => SeedKey::Both {
                user_id: UserId::new(id),
                email,
            },
            (Some(id), None) => SeedKey::ById(UserId::new(id)),
            (None, Some(email)) => SeedKey::ByEmail(email),
            (None, None) => {
                out.malformed
                    .push((index, "needs user_id or email".to_string()));
                continue;
            }
        };
        out.entries.push(SeedEntry {
            index,
            key,
            role: role(u.role),
            note: u.note.as_deref().and_then(sanitize_note),
        });
    }
    out
}

/// `--force <user_id or email>`.
pub fn force_target(arg: &str) -> Result<ForceTarget, String> {
    if arg.contains('@') {
        NormalizedEmail::parse(arg)
            .map(ForceTarget::ByEmail)
            .map_err(|_| "--force: not a valid email address".to_string())
    } else if crate::config::valid_user_id(arg) {
        Ok(ForceTarget::ById(UserId::new(arg)))
    } else {
        Err("--force: expected a user id (u_...) or an email address".to_string())
    }
}

/// How an entry is named in output: its `user_id`, else its address.
pub fn entry_label(e: &SeedEntry) -> String {
    match &e.key {
        SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => u.to_string(),
        SeedKey::ByEmail(em) => em.to_string(),
    }
}

fn entry_email(e: &SeedEntry) -> Option<&NormalizedEmail> {
    match &e.key {
        SeedKey::ByEmail(em) | SeedKey::Both { email: em, .. } => Some(em),
        SeedKey::ById(_) => None,
    }
}

/// A skip reason as printed: the run-time ones read as prose.
pub fn skip_text(reason: &str) -> String {
    match reason {
        skip::CHANGED_AT_RUN_TIME => "changed at run time".to_string(),
        skip::REVOKED_AT_RUN_TIME => "revoked at run time".to_string(),
        other => other.to_string(),
    }
}

/// Whether a skip is a defect of the entry (a warning in `--check`) rather
/// than a recorded run-time decision.
pub fn is_defect(reason: &str) -> bool {
    !matches!(
        reason,
        skip::CHANGED_AT_RUN_TIME | skip::REVOKED_AT_RUN_TIME
    )
}

/// The warning for one skipped entry.
pub fn skip_warning(index: usize, reason: &str, label: &str) -> String {
    match reason {
        skip::EMAIL_NOT_AUTHORITATIVE => {
            format!("admin.users[{index}]: {reason}; add user_id to apply")
        }
        skip::EMAIL_BINDING_AMBIGUOUS => {
            format!("admin.users[{index}]: {reason}; use --force <user_id>")
        }
        skip::CHANGED_AT_RUN_TIME | skip::REVOKED_AT_RUN_TIME => {
            format!(
                "admin.users[{index}]: skipped ({}): {label}",
                skip_text(reason)
            )
        }
        _ => format!("admin.users[{index}]: {reason}"),
    }
}

fn rebound_warning(index: usize, email: &str, bound: &UserId, now: &UserId) -> String {
    format!("admin.users[{index}]: {email} now belongs to {now}; the grant stays bound to {bound}")
}

fn find(entries: &[SeedEntry], index: usize) -> Option<&SeedEntry> {
    entries.iter().find(|e| e.index == index)
}

/// The grants bound through `email`, for output (`h@example.test → u_h, u_h2`).
fn bound_to(grants: &[AdminGrant], email: &NormalizedEmail) -> Vec<String> {
    let mut v: Vec<String> = grants
        .iter()
        .filter(|g| g.source_email.as_ref() == Some(email))
        .map(|g| g.user_id.to_string())
        .collect();
    v.sort();
    v
}

/// The entry as named beside a skip: an address-only entry also names the
/// users it is bound to.
pub fn skip_label(e: &SeedEntry, grants: &[AdminGrant]) -> String {
    match &e.key {
        SeedKey::ByEmail(em) => {
            let bound = bound_to(grants, em);
            if bound.is_empty() {
                em.to_string()
            } else {
                format!("{em} \u{2192} {}", bound.join(", "))
            }
        }
        _ => entry_label(e),
    }
}

/// Run the file rule in one transaction. `actor` is `file`; the events carry
/// `attrs.actor`, `role`, `managed_by`, `previous_role` and `forced`.
pub async fn run_import(
    directory: &dyn Directory,
    entries: Vec<SeedEntry>,
    force: Option<ForceTarget>,
    clock: &dyn Clock,
    rng: &dyn Rng,
    request_id: &str,
) -> StoreResult<GrantImportReport> {
    let at = clock.now();
    let mk = |user: &UserId,
              kind: EventKind,
              prev: Option<AdminRole>,
              role: AdminRole,
              forced: bool|
     -> Event {
        let shown = if kind == EventKind::AdminRevoke {
            prev.unwrap_or(role)
        } else {
            role
        };
        let mut b = EventBuilder::new(clock, rng, kind, Outcome::Info, request_id)
            .reason(reasons::ADMIN)
            .user(user)
            .attr("actor", "file")
            .attr("role", shown.as_str())
            .attr("managed_by", "file");
        if let Some(p) = prev {
            b = b.attr("previous_role", p.as_str());
        }
        if forced {
            b = b.attr("forced", true);
        }
        b.build()
    };
    directory
        .import_grants(entries, force, Deadline::after(IMPORT_DEADLINE), at, &mk)
        .await
}

/// The warnings an import produces: one per skipped entry and one per email
/// entry whose address moved to another user.
pub fn report_warnings(
    report: &GrantImportReport,
    entries: &[SeedEntry],
    grants: &[AdminGrant],
    include_run_time: bool,
) -> Vec<String> {
    let mut w = Vec::new();
    for (index, reason) in &report.skipped {
        if !include_run_time && !is_defect(reason) {
            continue;
        }
        let label = find(entries, *index)
            .map(|e| skip_label(e, grants))
            .unwrap_or_default();
        w.push(skip_warning(*index, reason, &label));
    }
    for (index, bound, now) in &report.rebound_warnings {
        let email = find(entries, *index)
            .and_then(entry_email)
            .map(|e| e.to_string())
            .unwrap_or_default();
        w.push(rebound_warning(*index, &email, bound, now));
    }
    w
}

/// What the import would complain about, read-only (`hopae --check`): the
/// resolution defects of unmatched entries, mismatched entries, ambiguous
/// bindings and email entries whose address moved. Mirrors the store's rule.
pub async fn preview(
    directory: &dyn Directory,
    entries: &[SeedEntry],
    deadline: Deadline,
) -> StoreResult<Vec<String>> {
    let grants = directory.admin_grants(true, deadline).await?;
    let mut w = Vec::new();
    for e in entries {
        let matched: Vec<&AdminGrant> = match &e.key {
            SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => {
                grants.iter().filter(|g| &g.user_id == u).collect()
            }
            SeedKey::ByEmail(em) => grants
                .iter()
                .filter(|g| g.source_email.as_ref() == Some(em))
                .collect(),
        };
        if matched.len() > 1 {
            w.push(skip_warning(e.index, skip::EMAIL_BINDING_AMBIGUOUS, ""));
            continue;
        }
        if let Some(g) = matched.first() {
            match &e.key {
                SeedKey::ByEmail(em) => {
                    if let Some((holder, _)) = directory
                        .resolve_grant_target(&GrantTarget::Email(em.clone()), deadline)
                        .await?
                        && holder.user_id != g.user_id
                    {
                        w.push(rebound_warning(
                            e.index,
                            em.as_str(),
                            &g.user_id,
                            &holder.user_id,
                        ));
                    }
                }
                SeedKey::Both { user_id, email } => {
                    let primary = directory
                        .resolve_grant_target(&GrantTarget::Id(user_id.clone()), deadline)
                        .await?
                        .and_then(|(u, _)| u.primary_email);
                    if primary.as_ref() != Some(email) {
                        w.push(skip_warning(e.index, skip::USER_EMAIL_MISMATCH, ""));
                    }
                }
                SeedKey::ById(_) => {}
            }
            continue;
        }
        let target = match &e.key {
            SeedKey::ById(u) | SeedKey::Both { user_id: u, .. } => GrantTarget::Id(u.clone()),
            SeedKey::ByEmail(em) => GrantTarget::Email(em.clone()),
        };
        let Some((user, _)) = directory.resolve_grant_target(&target, deadline).await? else {
            w.push(skip_warning(e.index, skip::NO_SUCH_USER, ""));
            continue;
        };
        let defect = match &e.key {
            SeedKey::ByEmail(_) if !user.email_verified => Some(skip::EMAIL_UNVERIFIED),
            SeedKey::ByEmail(_) if !user.email_authoritative => Some(skip::EMAIL_NOT_AUTHORITATIVE),
            SeedKey::Both { email, .. } if user.primary_email.as_ref() != Some(email) => {
                Some(skip::USER_EMAIL_MISMATCH)
            }
            _ if user.status != UserStatus::Active => Some(skip::USER_DISABLED),
            _ => None,
        };
        if let Some(reason) = defect {
            w.push(skip_warning(e.index, reason, ""));
        }
    }
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        user_id: Option<&str>,
        email: Option<&str>,
        role: Option<AdminRoleCfg>,
    ) -> AdminUserEntry {
        AdminUserEntry {
            user_id: user_id.map(String::from),
            email: email.map(String::from),
            role,
            note: None,
        }
    }

    #[test]
    fn entries_keep_their_key_position_and_default_role() {
        let s = entries(&[
            entry(Some("u_a"), None, None),
            entry(None, Some("V@Example.test"), Some(AdminRoleCfg::Viewer)),
            entry(Some("u_n"), Some("n@example.test"), None),
        ]);
        assert!(s.malformed.is_empty());
        assert!(matches!(s.entries[0].key, SeedKey::ById(_)));
        assert_eq!(s.entries[0].role, AdminRole::Admin);
        match &s.entries[1].key {
            SeedKey::ByEmail(e) => assert_eq!(e.as_str(), "V@example.test"),
            k => panic!("{k:?}"),
        }
        assert_eq!(s.entries[1].index, 1);
        assert_eq!(s.entries[1].role, AdminRole::Viewer);
        assert!(matches!(s.entries[2].key, SeedKey::Both { .. }));
    }

    #[test]
    fn malformed_entries_are_reported_with_their_position() {
        let s = entries(&[
            entry(None, None, None),
            entry(Some("x"), None, None),
            entry(None, Some("a@b@c"), None),
            entry(Some("u_ok"), None, None),
        ]);
        assert_eq!(s.malformed.len(), 3);
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].index, 3);
    }

    #[test]
    fn force_arguments_are_a_user_id_or_an_address() {
        assert!(matches!(force_target("u_a"), Ok(ForceTarget::ById(_))));
        assert!(matches!(
            force_target("H@Example.test"),
            Ok(ForceTarget::ByEmail(e)) if e.as_str() == "H@example.test"
        ));
        assert!(force_target("nope").is_err());
        assert!(force_target("a@b@c").is_err());
    }

    #[test]
    fn notes_lose_control_characters_and_empty_notes_vanish() {
        assert_eq!(sanitize_note("a\u{7}b").as_deref(), Some("a?b"));
        assert_eq!(sanitize_note(""), None);
        assert_eq!(
            sanitize_note("\u{c6b4}\u{c601}").as_deref(),
            Some("\u{c6b4}\u{c601}")
        );
    }

    #[test]
    fn warnings_read_as_pinned() {
        assert_eq!(
            skip_warning(1, skip::EMAIL_NOT_AUTHORITATIVE, ""),
            "admin.users[1]: email_not_authoritative; add user_id to apply"
        );
        assert_eq!(
            skip_warning(0, skip::REVOKED_AT_RUN_TIME, "u_a"),
            "admin.users[0]: skipped (revoked at run time): u_a"
        );
        assert_eq!(
            rebound_warning(
                0,
                "h@example.test",
                &UserId::new("u_h"),
                &UserId::new("u_h2")
            ),
            "admin.users[0]: h@example.test now belongs to u_h2; the grant stays bound to u_h"
        );
    }
}
