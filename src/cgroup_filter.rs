//! Configurable, ordered coalescing of cgroups into tracked telemetry series.
//!
//! The exporter tracks one [`CgroupMeter`](crate::cgroup::CgroupMeter) per
//! *canonical* cgroup. By default the canonical cgroup is the leaf a task ran in,
//! but a [`CgroupFilter`] can fold many related leaves onto a shared ancestor, e.g. a
//! SLURM job's `step_*/task_*` sub-cgroups onto the job, a user's login sessions
//! onto `user-<uid>.slice`,` and tag the resulting series with extra attributes.
//!
//! Filters are selected at startup (`--cgroup-filters`) and applied in order to
//! each leaf cgroup's mount-relative path (see [`apply_filters`]). With no filters
//! configured every leaf is tracked on its own, unfiltered.
//!
//! ## Why a coalesce target must be a real directory
//!
//! Cgroups are keyed by inode and liveness is a walk of the real directories under
//! the tracked mount (see [`collect_live_cgroup_ids`](crate::cgroup)). A filter
//! therefore returns the mount-relative path of a real ancestor directory
//! ([`Filtered::Coalesce::coalesce_to`]). The registry `stat`s it for the
//! canonical inode and relies on it appearing in the liveness walk. Kept separate
//! from the short human [`name`](Filtered::Coalesce::name) used for labels.

use std::num::NonZeroUsize;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use lru::LruCache;
use nix::unistd::{Uid, User};
use opentelemetry::KeyValue;

/// The verdict a [`CgroupFilter`] returns for one cgroup path.
pub enum Filtered {
    /// This filter doesn't handle the cgroup: leave the name/path/attrs as they
    /// are and let the next filter in the chain decide.
    PassThrough,
    /// Drop the cgroup entirely. No metrics or profiles are emitted for it, and
    /// the decision is cached so repeat events are rejected cheaply.
    #[allow(dead_code)]
    Drop,
    /// Coalesce this cgroup into a shared tracked series.
    Coalesce {
        /// Mount-relative path of the real cgroup directory the series is keyed
        /// by. `stat`'d for the canonical inode and fed to the next filter, so it
        /// must name an existing ancestor (or the cgroup itself).
        coalesce_to: String,
        /// Extra metric attributes / profile labels for every series of this
        /// cgroup (e.g. `slurm.job_id`, `uid`).
        attrs: Vec<KeyValue>,
    },
}

/// Coalesces cgroups into shared, labelled telemetry series. Implementations are
/// effectively pure functions of the cgroup path (any internal state is
/// memoization only), so one instance serves every cgroup.
pub trait CgroupFilter: Send + Sync {
    /// Classify a mount-relative cgroup path (see [`Filtered`]).
    fn apply(&self, path: &str) -> Filtered;
}

/// The result of running the whole filter chain over one leaf cgroup path.
pub struct FilterOutcome {
    /// Mount-relative path of the directory the leaf is tracked under (the leaf
    /// itself when no filter coalesced it). Used for the canonical inode.
    pub path: String,
    /// Accumulated extra attributes from every filter that coalesced.
    pub attrs: Vec<KeyValue>,
}

/// Run `filters` in order over a leaf cgroup's mount-relative `leaf_rel` path.
///
/// Threads the (possibly rewritten) path through the chain, accumulating attributes
/// from each [`Filtered::Coalesce`]. Returns `None` the moment any filter yields
/// [`Filtered::Drop`]. With no filters the leaf passes through unchanged, i.e. it is
/// tracked on its own. The unfiltered default.
///
/// When `drop_unhandled` is set, a leaf that no filter coalesced (every filter
/// returned [`Filtered::PassThrough`]) is dropped too, i.e. only cgroups a filter
/// claimed are tracked (a whitelist). With no filters configured this drops every
/// cgroup.
pub fn apply_filters(
    filters: &[Box<dyn CgroupFilter>],
    leaf_rel: &str,
    drop_unhandled: bool,
) -> Option<FilterOutcome> {
    let mut path = leaf_rel.to_owned();
    let mut attrs = Vec::new();
    let mut matched = false;

    for filter in filters {
        match filter.apply(&path) {
            Filtered::PassThrough => {}
            Filtered::Drop => return None,
            Filtered::Coalesce {
                coalesce_to,
                attrs: mut a,
            } => {
                matched = true;
                path = coalesce_to;
                attrs.append(&mut a);
            }
        }
    }

    if drop_unhandled && !matched {
        return None;
    }

    Some(FilterOutcome { path, attrs })
}

/// Build the ordered filter chain from CLI filter names (the comma-separated
/// `--cgroup-filters` value). Returns an error naming the first unknown filter.
pub fn parse_filters(names: &[String]) -> Result<Vec<Box<dyn CgroupFilter>>, String> {
    names
        .iter()
        .map(|name| -> Result<Box<dyn CgroupFilter>, String> {
            match name.as_str() {
                "slurm" => Ok(Box::new(SlurmFilter::default())),
                "user-session" => Ok(Box::new(UserSessionFilter)),
                other => Err(format!(
                    "unknown cgroup filter {other:?} (known: slurm, user-session)"
                )),
            }
        })
        .collect()
}

/// Coalesces a SLURM job's `step_*/task_*` sub-cgroups onto the job cgroup and
/// tags the series with `slurm.job_id` plus the owning `user.id`/`user.name`.
///
/// The owner is read from the `uid_<N>` path segment on the cgroup/v1 layout. The
/// cgroup/v2 layout carries no uid segment (`system.slice/slurmstepd.scope/job_<N>`,
/// see <https://slurm.schedmd.com/cgroup_v2.html>), so there we fall back to asking
/// `squeue` for the job's owner, memoized per job in [`user_cache`](Self::user_cache).
pub struct SlurmFilter {
    /// `job_id` -> resolved owner, so the `squeue` fallback runs at most once per
    /// job instead of once per step/task sub-cgroup that resolves through the
    /// filter. A `None` value memoizes a failed/absent lookup so a job squeue can't
    /// answer for isn't re-queried. Bounded (LRU) so a long-lived node's job churn
    /// can't grow it without limit.
    user_cache: Mutex<LruCache<u64, Option<SlurmUser>>>,
}

impl Default for SlurmFilter {
    fn default() -> Self {
        // A node runs far fewer than 1024 jobs concurrently, so this only ever
        // evicts entries for long-finished jobs no longer producing events.
        let cap = NonZeroUsize::new(1024).expect("nonzero");
        Self {
            user_cache: Mutex::new(LruCache::new(cap)),
        }
    }
}

impl CgroupFilter for SlurmFilter {
    fn apply(&self, path: &str) -> Filtered {
        let rel = Path::new(path);
        let Some(parsed) = parse_slurm(rel) else {
            return Filtered::PassThrough;
        };

        // The job cgroup is the first `depth` non-empty components of the path.
        let coalesce_to = rel
            .iter()
            .filter_map(|c| c.to_str())
            .filter(|c| !c.is_empty())
            .take(parsed.depth)
            .collect::<Vec<_>>()
            .join("/");

        let mut attrs = vec![KeyValue::new("slurm.job_id", parsed.job.job_id as i64)];
        // Prefer the uid carried in the path (v1); otherwise ask squeue (v2).
        let owner = match parsed.job.uid {
            Some(uid) => Some(SlurmUser {
                name: User::from_uid(Uid::from_raw(uid))
                    .ok()
                    .flatten()
                    .map(|u| u.name),
                uid,
            }),
            None => self.lookup_owner(parsed.job.job_id),
        };
        if let Some(owner) = owner {
            attrs.push(KeyValue::new("user.id", i64::from(owner.uid)));
            if let Some(name) = owner.name {
                attrs.push(KeyValue::new("user.name", name));
            }
        }

        Filtered::Coalesce { coalesce_to, attrs }
    }
}

impl SlurmFilter {
    /// Resolve a job's owner via `squeue`, memoizing the result (success or not)
    /// per job in [`user_cache`](Self::user_cache) so the subprocess runs once per
    /// job rather than once per sub-cgroup.
    fn lookup_owner(&self, job_id: u64) -> Option<SlurmUser> {
        let mut cache = self.user_cache.lock().unwrap();
        if let Some(cached) = cache.get(&job_id) {
            return cached.clone();
        }
        let owner = squeue_owner(job_id);
        cache.put(job_id, owner.clone());
        owner
    }
}

/// A SLURM job's owning user.
#[derive(Clone)]
struct SlurmUser {
    uid: u32,
    /// The account name, when it could be resolved (from squeue's `%u`, or the
    /// passwd database for a uid parsed from the path).
    name: Option<String>,
}

/// Ask `squeue` for the owner of `job_id`, for the cgroup/v2 layout whose path
/// carries no uid segment. Runs `squeue -j <job_id> -h -o "%u %U"`, whose one output
/// line is `<user_name> <user_id>`. Returns `None` if squeue is absent, errors, or
/// the job is no longer queued.
fn squeue_owner(job_id: u64) -> Option<SlurmUser> {
    let output = Command::new("squeue")
        .args(["-j", &job_id.to_string(), "-h", "-o", "%u %U"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_squeue_owner(&String::from_utf8_lossy(&output.stdout))
}

/// Parse `squeue -h -o "%u %U"` output (`<user_name> <user_id>`) into a
/// [`SlurmUser`]. Takes the first non-empty line (a job array reports one line per
/// element, all with the same owner). Returns `None` if no line parses.
fn parse_squeue_owner(stdout: &str) -> Option<SlurmUser> {
    let line = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
    let mut fields = line.split_whitespace();
    let name = fields.next()?.to_owned();
    let uid: u32 = fields.next()?.parse().ok()?;
    Some(SlurmUser {
        uid,
        name: (!name.is_empty()).then_some(name),
    })
}

/// Coalesces a user's login sessions and services
/// (`user.slice/user-<uid>.slice/session-<n>.scope/...`,
/// `.../user@<uid>.service/...`) onto the `user-<uid>.slice` cgroup and tags the
/// series with `uid`.
pub struct UserSessionFilter;

impl CgroupFilter for UserSessionFilter {
    fn apply(&self, path: &str) -> Filtered {
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();

        // Key off the `user-<digits>.slice` component (the per-user slice), like
        // the SLURM filter keys off `job_<N>`.
        let Some(idx) = comps.iter().position(|c| user_slice_uid(c).is_some()) else {
            return Filtered::PassThrough;
        };
        let uid = user_slice_uid(comps[idx]).expect("position matched");

        let mut attrs = vec![KeyValue::new("user.id", i64::from(uid))];
        if let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid)) {
            attrs.push(KeyValue::new("user.name", user.name));
        }

        Filtered::Coalesce {
            coalesce_to: comps[..=idx].join("/"),
            attrs,
        }
    }
}

/// Parse the uid out of a `user-<digits>.slice` path component, or `None` if the
/// component isn't a per-user slice.
fn user_slice_uid(component: &str) -> Option<u32> {
    component
        .strip_prefix("user-")
        .and_then(|rest| rest.strip_suffix(".slice"))
        .and_then(|digits| {
            (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
                .then(|| digits.parse().ok())
                .flatten()
        })
}

/// The SLURM identity parsed from a job cgroup path.
struct SlurmJob {
    job_id: u64,
    /// The owning user, from the `uid_<N>` path segment when present (v1 layout);
    /// `None` when the layout carries no uid segment (some v2 layouts).
    uid: Option<u32>,
}

/// A parsed SLURM job cgroup path: the [`SlurmJob`] identity plus how many leading
/// path components form the job cgroup (everything below it is aggregated into the job).
struct SlurmParse {
    job: SlurmJob,
    /// Number of leading components of the mount-relative path, up to and
    /// including `job_<N>`, that name the job cgroup directory.
    depth: usize,
}

/// Detect a SLURM job in a mount-relative cgroup path and find the job cgroup to
/// aggregate it into. Generic across the v1 layout (`slurm/uid_<U>/job_<J>/step_*/
/// task_*`) and v2 layouts (which may differ and may omit the `uid_` segment): we
/// key purely off the first `job_<digits>` component, and pick up an `uid_<digits>`
/// component preceding it when present. Returns `None` for non-SLURM cgroups.
fn parse_slurm(rel: &Path) -> Option<SlurmParse> {
    let comps: Vec<&str> = rel
        .iter()
        .filter_map(|c| c.to_str())
        .filter(|c| !c.is_empty())
        .collect();

    let job_idx = comps
        .iter()
        .position(|c| parse_prefixed_u64(c, "job_").is_some())?;
    let job_id = parse_prefixed_u64(comps[job_idx], "job_")?;

    // The owning uid, from a `uid_<N>` segment before the job component (v1).
    let uid = comps[..job_idx]
        .iter()
        .rev()
        .find_map(|c| parse_prefixed_u64(c, "uid_"))
        .and_then(|u| u32::try_from(u).ok());

    Some(SlurmParse {
        job: SlurmJob { job_id, uid },
        depth: job_idx + 1,
    })
}

/// Parse `<prefix><digits>` (e.g. `job_1349782`) into the trailing number, or
/// `None` if the component doesn't have the prefix or isn't all-digits after it.
fn parse_prefixed_u64(component: &str, prefix: &str) -> Option<u64> {
    let digits = component.strip_prefix(prefix)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert `filtered` is a `Coalesce` with the given fields; returns nothing.
    fn assert_coalesce(filtered: Filtered, coalesce_to: &str, attrs: &[(&str, &str)]) {
        match filtered {
            Filtered::Coalesce {
                coalesce_to: c,
                attrs: a,
            } => {
                assert_eq!(c, coalesce_to);
                let got: Vec<(String, String)> = a
                    .iter()
                    .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                    .collect();
                for attr in attrs {
                    assert!(
                        got.contains(&(attr.0.to_string(), attr.1.to_string())),
                        "missing attr {attr:?}",
                    );
                }
            }
            _ => panic!("expected Coalesce"),
        }
    }

    fn is_passthrough(filtered: &Filtered) -> bool {
        matches!(filtered, Filtered::PassThrough)
    }

    #[test]
    fn parse_slurm_v1_layout() {
        // v1: /slurm/uid_<U>/job_<J>/step_<S>/task_<T>.
        let parsed = parse_slurm(Path::new(
            "slurm/uid_38262/job_1349782/step_interactive/task_0",
        ))
        .expect("recognized as a SLURM job");
        assert_eq!(parsed.job.job_id, 1349782);
        assert_eq!(parsed.job.uid, Some(38262));
        // Canonical job dir = slurm/uid_38262/job_1349782 (3 components).
        assert_eq!(parsed.depth, 3);
    }

    #[test]
    fn parse_slurm_v2_layout_without_uid() {
        // A v2-style layout that carries no uid_ segment: uid is omitted, the job
        // is still recognized and aggregated at the job_ component.
        let parsed = parse_slurm(Path::new(
            "system.slice/slurmstepd.scope/job_42/step_0/user/task_special",
        ))
        .expect("recognized as a SLURM job");
        assert_eq!(parsed.job.job_id, 42);
        assert_eq!(parsed.job.uid, None);
        assert_eq!(parsed.depth, 3); // system.slice/slurmstepd.scope/job_42
    }

    #[test]
    fn parse_slurm_rejects_non_slurm_and_malformed() {
        assert!(parse_slurm(Path::new("system.slice/chronyd.service")).is_none());
        assert!(parse_slurm(Path::new("user.slice/user-1000.slice")).is_none());
        // `job_` with no digits, or non-numeric, is not a job component.
        assert!(parse_slurm(Path::new("slurm/job_/step_0")).is_none());
        assert!(parse_slurm(Path::new("slurm/job_abc")).is_none());
    }

    #[test]
    fn slurm_filter_coalesces_to_job_dir_with_labels() {
        assert_coalesce(
            SlurmFilter::default().apply("slurm/uid_38262/job_1349782/step_interactive/task_0"),
            "slurm/uid_38262/job_1349782",
            &[("slurm.job_id", "1349782"), ("user.id", "38262")],
        );
        // v2 layout without a uid segment: still coalesces to the job dir and tags
        // the job id. The uid comes from the squeue fallback, absent in the test
        // environment, so only the job id is asserted here.
        assert_coalesce(
            SlurmFilter::default().apply("system.slice/slurmstepd.scope/job_42/step_0/task_0"),
            "system.slice/slurmstepd.scope/job_42",
            &[("slurm.job_id", "42")],
        );
    }

    #[test]
    fn slurm_filter_passes_through_non_slurm() {
        assert!(is_passthrough(
            &SlurmFilter::default().apply("system.slice/chronyd.service")
        ));
        assert!(is_passthrough(
            &SlurmFilter::default().apply("user.slice/user-1000.slice")
        ));
    }

    #[test]
    fn parse_squeue_owner_reads_name_and_uid() {
        // `squeue -h -o "%u %U"` -> "<name> <uid>".
        let owner = parse_squeue_owner("alice 1001\n").expect("parsed");
        assert_eq!(owner.uid, 1001);
        assert_eq!(owner.name.as_deref(), Some("alice"));

        // Job array: one line per element, all the same owner. First line wins.
        let owner = parse_squeue_owner("bob 2002\nbob 2002\n").expect("parsed");
        assert_eq!(owner.uid, 2002);
        assert_eq!(owner.name.as_deref(), Some("bob"));
    }

    #[test]
    fn parse_squeue_owner_rejects_empty_and_malformed() {
        // No output (job gone), a header-only line, and a non-numeric uid.
        assert!(parse_squeue_owner("").is_none());
        assert!(parse_squeue_owner("\n  \n").is_none());
        assert!(parse_squeue_owner("alice\n").is_none());
        assert!(parse_squeue_owner("alice notanumber\n").is_none());
    }

    #[test]
    fn user_session_filter_coalesces_sessions_and_services() {
        assert_coalesce(
            UserSessionFilter.apply("user.slice/user-1000.slice/session-3.scope/app.service"),
            "user.slice/user-1000.slice",
            &[("user.id", "1000")],
        );
        // A user@<uid>.service tree under the same slice folds onto the slice too.
        assert_coalesce(
            UserSessionFilter.apply("user.slice/user-1000.slice/user@1000.service/foo.service"),
            "user.slice/user-1000.slice",
            &[("user.id", "1000")],
        );
        // The bare per-user slice coalesces onto itself.
        assert_coalesce(
            UserSessionFilter.apply("user.slice/user-42.slice"),
            "user.slice/user-42.slice",
            &[("user.id", "42")],
        );
    }

    #[test]
    fn user_session_filter_passes_through_others() {
        assert!(is_passthrough(
            &UserSessionFilter.apply("system.slice/chronyd.service")
        ));
        // `user.slice` alone (no per-user slice) is not coalesced.
        assert!(is_passthrough(&UserSessionFilter.apply("user.slice")));
        // A non-numeric uid is not a per-user slice.
        assert!(is_passthrough(
            &UserSessionFilter.apply("user.slice/user-root.slice")
        ));
    }

    #[test]
    fn chain_applies_filters_in_order() {
        let filters = parse_filters(&["slurm".to_owned(), "user-session".to_owned()]).unwrap();

        // A system cgroup neither filter handles passes through unchanged.
        let sys = apply_filters(&filters, "system.slice/chronyd.service", false).unwrap();
        assert_eq!(sys.path, "system.slice/chronyd.service");
        assert!(sys.attrs.is_empty());

        // A SLURM path is coalesced by the first filter; the second leaves it be.
        let job =
            apply_filters(&filters, "slurm/uid_38262/job_1349782/step_0/task_0", false).unwrap();
        assert_eq!(job.path, "slurm/uid_38262/job_1349782");
        assert!(
            job.attrs
                .contains(&KeyValue::new("slurm.job_id", 1349782i64))
        );
        assert!(job.attrs.contains(&KeyValue::new("user.id", 38262i64)));

        // A user-session path is passed through by slurm, coalesced by the second.
        let user = apply_filters(
            &filters,
            "user.slice/user-1000.slice/session-3.scope",
            false,
        )
        .unwrap();
        assert_eq!(user.path, "user.slice/user-1000.slice");
        assert!(user.attrs.contains(&KeyValue::new("user.id", 1000i64)));
    }

    #[test]
    fn drop_unhandled_drops_only_uncoalesced_cgroups() {
        let filters = parse_filters(&["slurm".to_owned()]).unwrap();

        // A cgroup a filter coalesced is kept regardless of drop_unhandled.
        assert!(apply_filters(&filters, "slurm/uid_1/job_7/step_0", true).is_some());
        // A cgroup no filter claimed is dropped only under drop_unhandled.
        assert!(apply_filters(&filters, "system.slice/chronyd.service", false).is_some());
        assert!(apply_filters(&filters, "system.slice/chronyd.service", true).is_none());
        // With no filters, drop_unhandled drops everything.
        assert!(apply_filters(&[], "system.slice/chronyd.service", true).is_none());
    }

    #[test]
    fn parse_filters_rejects_unknown() {
        assert!(parse_filters(&["slurm".to_owned(), "bogus".to_owned()]).is_err());
        assert!(parse_filters(&[]).unwrap().is_empty());
    }
}
