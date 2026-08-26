use anyhow::{Context, Result, bail};
use landlock::{
    AccessFs, AccessNet, CompatLevel, Compatible, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    Scope,
};
use log::info;
use nix::unistd::{Gid, Group, Uid, User, setgroups, setresgid, setresuid};

/// The default `--sandbox-user`: the conventional unprivileged account.
pub const DEFAULT_SANDBOX_USER: &str = "nobody";

/// The uid/gid `nobody` falls back to on a host with
/// no matching passwd/group entry.
const NOBODY_ID: u32 = 65534;

/// How [`init_sandbox`] should restrict the process, assembled from the CLI in
/// [`crate::app`].
pub struct SandboxConfig<'a> {
    /// Drop to [`user`](Self::user)/[`group`](Self::group). Off when a signal
    /// still needs privileges afterwards (the profiler reads `/proc/<pid>/maps`
    /// of every traced process).
    pub drop_privs: bool,
    /// The user to drop to: a name or a numeric uid.
    pub user: &'a str,
    /// The group to drop to: a name or a numeric gid. `None` uses the user's
    /// primary group.
    pub group: Option<&'a str>,
    /// Set `PR_SET_NO_NEW_PRIVS` as part of the Landlock ruleset. Cleared by
    /// `--slurm-use-sudo`, which needs setuid `sudo` to work.
    pub no_new_privs: bool,
}

pub fn init_sandbox(cfg: &SandboxConfig<'_>) -> Result<()> {
    // Resolve the identity up front: the passwd/group lookup may go through NSS,
    // so keep it clear of both restrictions.
    let ids = cfg
        .drop_privs
        .then(|| resolve_ids(cfg.user, cfg.group))
        .transpose()?;

    if cfg.no_new_privs {
        // `PR_SET_NO_NEW_PRIVS` is what lets the (by then unprivileged) thread
        // restrict itself, and the ruleset sets it, so drop first.
        if let Some((uid, gid)) = ids {
            drop_privs(uid, gid)?;
        }
        init_landlock(true)?;
    } else {
        // Without the flag, `landlock_restrict_self` needs `CAP_SYS_ADMIN`, so
        // restrict while it is still held and drop afterwards. The ruleset is
        // inherited across the drop (and across the `sudo` execs it exists to
        // allow), so the end state is the same.
        init_landlock(false)?;
        if let Some((uid, gid)) = ids {
            drop_privs(uid, gid)?;
        }
    }
    Ok(())
}

fn init_landlock(no_new_privs: bool) -> Result<()> {
    let abi = landlock::ABI::V7;
    let ruleset = landlock::Ruleset::default();
    let status = ruleset
        .handle_access(AccessFs::from_write(abi))?
        .handle_access(AccessNet::BindTcp)?
        .scope(Scope::Signal)?
        .set_compatibility(CompatLevel::BestEffort)
        .create()?
        .no_new_privs(no_new_privs)
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => {
            info!("Landlock sandboxing enabled (no_new_privs: {no_new_privs})");
        }
        RulesetStatus::NotEnforced => {
            info!("Failed to enable landlock, is the kernel too old?");
        }
    }
    Ok(())
}

/// Resolve `--sandbox-user`/`--sandbox-group` to the ids to drop to. Either may
/// be a name or a numeric id; with no group given the user's primary group is
/// used, which is what the fixed `nobody` drop did before these were
/// configurable.
fn resolve_ids(user_spec: &str, group_spec: Option<&str>) -> Result<(Uid, Gid)> {
    let numeric = user_spec.parse::<u32>().ok();
    // The passwd entry, when there is one: it settles both the uid and the
    // default gid. A numeric spec is looked up too, so it can still supply the
    // primary group.
    let entry = match numeric {
        Some(raw) => User::from_uid(Uid::from_raw(raw)),
        None => User::from_name(user_spec),
    }
    .with_context(|| format!("looking up --sandbox-user {user_spec:?}"))?;

    let uid = match (&entry, numeric) {
        (Some(user), _) => user.uid,
        // A numeric id needs no entry to be usable.
        (None, Some(raw)) => Uid::from_raw(raw),
        (None, None) if user_spec == DEFAULT_SANDBOX_USER => Uid::from_raw(NOBODY_ID),
        (None, None) => bail!("--sandbox-user: no such user {user_spec:?}"),
    };

    let gid = match group_spec {
        Some(spec) => resolve_group(spec)?,
        None => match &entry {
            Some(user) => user.gid,
            None if user_spec == DEFAULT_SANDBOX_USER => Gid::from_raw(NOBODY_ID),
            None => bail!(
                "--sandbox-user {user_spec:?} has no passwd entry, \
                 so its primary group is unknown: pass --sandbox-group"
            ),
        },
    };

    Ok((uid, gid))
}

/// Resolve a `--sandbox-group` value: a group name, or a numeric gid used as-is
/// (so a site can drop to a gid with no group entry).
fn resolve_group(spec: &str) -> Result<Gid> {
    if let Ok(raw) = spec.parse::<u32>() {
        return Ok(Gid::from_raw(raw));
    }
    Group::from_name(spec)
        .with_context(|| format!("looking up --sandbox-group {spec:?}"))?
        .map(|group| group.gid)
        .ok_or_else(|| anyhow::anyhow!("--sandbox-group: no such group {spec:?}"))
}

fn drop_privs(uid: Uid, gid: Gid) -> Result<()> {
    info!("Dropping privileges to uid {uid}, gid {gid}");
    setgroups(&[])?;
    setresgid(gid, gid, gid)?;
    setresuid(uid, uid, uid)?;

    Ok(())
}
