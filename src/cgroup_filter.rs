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

use std::path::Path;

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
/// pure functions of the cgroup path and hold no per-cgroup state, so one instance
/// serves every cgroup.
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
                "slurm" => Ok(Box::new(SlurmFilter)),
                "user-session" => Ok(Box::new(UserSessionFilter)),
                other => Err(format!(
                    "unknown cgroup filter {other:?} (known: slurm, user-session)"
                )),
            }
        })
        .collect()
}

/// Coalesces a SLURM job's `step_*/task_*` sub-cgroups onto the job cgroup and
/// tags the series with `slurm.job_id` (and `uid` when the layout carries one).
pub struct SlurmFilter;

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
        if let Some(uid) = parsed.job.uid {
            attrs.push(KeyValue::new("user.id", i64::from(uid)));
            if let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid)) {
                attrs.push(KeyValue::new("user.name", user.name));
            }
        }

        Filtered::Coalesce { coalesce_to, attrs }
    }
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
            SlurmFilter.apply("slurm/uid_38262/job_1349782/step_interactive/task_0"),
            "slurm/uid_38262/job_1349782",
            &[("slurm.job_id", "1349782"), ("user.id", "38262")],
        );
        // v2 layout without a uid segment: no uid attribute.
        assert_coalesce(
            SlurmFilter.apply("system.slice/slurmstepd.scope/job_42/step_0/task_0"),
            "system.slice/slurmstepd.scope/job_42",
            &[("slurm.job_id", "42")],
        );
    }

    #[test]
    fn slurm_filter_passes_through_non_slurm() {
        assert!(is_passthrough(
            &SlurmFilter.apply("system.slice/chronyd.service")
        ));
        assert!(is_passthrough(
            &SlurmFilter.apply("user.slice/user-1000.slice")
        ));
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
