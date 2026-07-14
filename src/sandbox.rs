use anyhow::Result;
use landlock::{
    AccessFs, AccessNet, CompatLevel, Compatible, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    Scope,
};
use log::info;
use nix::unistd::{Gid, Uid, User, setgroups, setresgid, setresuid};

pub fn init_sandbox(drop_privs: bool) -> Result<()> {
    if drop_privs {
        crate::sandbox::drop_privs()?;
    }
    init_landlock()?;
    Ok(())
}

fn init_landlock() -> Result<()> {
    let abi = landlock::ABI::V7;
    let ruleset = landlock::Ruleset::default();
    let status = ruleset
        .handle_access(AccessFs::from_write(abi))?
        .handle_access(AccessNet::BindTcp)?
        .scope(Scope::Signal)?
        .set_compatibility(CompatLevel::BestEffort)
        .create()?
        .no_new_privs(true)
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => {
            info!("Landlock sandboxing enabled");
        }
        RulesetStatus::NotEnforced => {
            info!("Failed to enable landlock, is the kernel too old?");
        }
    }
    Ok(())
}

fn drop_privs() -> Result<()> {
    let nobody = User::from_name("nobody")?;
    let uid = nobody
        .as_ref()
        .map(|user| user.uid)
        .unwrap_or_else(|| Uid::from_raw(65534));
    let gid = nobody
        .as_ref()
        .map(|user| user.gid)
        .unwrap_or_else(|| Gid::from_raw(65534));
    info!(
        "Dropping privileges to user 'nobody' (uid: {}, gid: {})",
        uid, gid
    );
    setgroups(&[])?;
    setresgid(gid, gid, gid)?;
    setresuid(uid, uid, uid)?;

    Ok(())
}
