use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use log::{debug, warn};
use reqwest::StatusCode;
use tokio::io::AsyncWriteExt;

/// A client for fetching debug info from one or more debuginfod servers, caching
/// results on the local file system so repeated drains (and other debuginfod
/// tools) reuse the same files.
pub(crate) struct DebuginfodClient {
    /// Server base URLs in decreasing order of preference, each already stripped
    /// of any trailing `/`.
    base_urls: Vec<String>,
    /// Root of the on-disk cache; one `<hexid>/debuginfo` file per build ID.
    cache_dir: PathBuf,
    client: reqwest::Client,
}

impl DebuginfodClient {
    /// Build a client from the standard debuginfod configuration, returning
    /// `Ok(None)` when no servers are configured — i.e. the operator has not
    /// opted in. `Err` only on a genuine misconfiguration (un-decodable URLs, no
    /// usable cache directory, or an HTTP client that won't build).
    ///
    /// Server URLs follow elfutils' precedence: an explicitly *set*
    /// `DEBUGINFOD_URLS` (even empty, which disables) is used verbatim;
    /// otherwise the system-wide [`/etc/debuginfod/*.urls`][system] files are
    /// read.
    ///
    /// [system]: urls_from_system_config
    pub(crate) fn discover() -> Result<Option<Self>> {
        let base_urls = match env::var_os("DEBUGINFOD_URLS") {
            // A set variable wins outright, even when empty (the standard opt-out
            // — the system config files are then deliberately ignored).
            Some(urls) => {
                let urls = urls
                    .to_str()
                    .context("DEBUGINFOD_URLS is not valid UTF-8")?;
                parse_urls(urls)
            }
            None => urls_from_system_config(),
        };
        if base_urls.is_empty() {
            return Ok(None);
        }

        let cache_dir = cache_dir()?;
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("creating debuginfod cache dir {}", cache_dir.display()))?;

        let client = reqwest::Client::builder()
            .build()
            .context("building debuginfod HTTP client")?;

        debug!(
            "debuginfod enabled: urls={base_urls:?}, cache={}",
            cache_dir.display()
        );
        Ok(Some(Self {
            base_urls,
            cache_dir,
            client,
        }))
    }

    /// The base URLs this client will query, for logging at startup.
    pub(crate) fn urls(&self) -> &[String] {
        &self.base_urls
    }

    /// Resolve the debug-info file for `build_id`, returning its cached path.
    ///
    /// On a cache hit the existing path is returned without any network access.
    /// Otherwise each server is queried in turn: the first one with the build ID
    /// wins and its response is streamed into the cache; a `404` from a server
    /// just moves on to the next. `Ok(None)` means no server had it (so the
    /// caller should fall back to local debug info); `Err` is reserved for a
    /// server/transport failure when none served the file.
    pub(crate) async fn fetch_debug_info(&self, build_id: &[u8]) -> Result<Option<PathBuf>> {
        let hex = hex_build_id(build_id);
        let entry_dir = self.cache_dir.join(&hex);
        let path = entry_dir.join("debuginfo");

        // try_exists distinguishes "not there" from a real stat error; on a stat
        // error fall through to a fetch rather than failing outright.
        if path.try_exists().unwrap_or(false) {
            debug!("debuginfod cache hit for build id {hex}");
            return Ok(Some(path));
        }

        let mut last_err: Option<anyhow::Error> = None;
        for base in &self.base_urls {
            let url = format!("{base}/buildid/{hex}/debuginfo");
            debug!("debuginfod GET {url}");

            let resp = match self.client.get(&url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("debuginfod request to {url} failed: {e}");
                    last_err = Some(anyhow!(e).context(format!("requesting {url}")));
                    continue;
                }
            };

            let status = resp.status();
            if status == StatusCode::NOT_FOUND {
                // This server simply doesn't index the build ID; try the next.
                continue;
            }
            if !status.is_success() {
                warn!("debuginfod {url} returned HTTP {status}");
                last_err = Some(anyhow!("{url} returned HTTP {status}"));
                continue;
            }

            let path = self
                .stream_to_cache(resp, &entry_dir, &path)
                .await
                .with_context(|| format!("caching debug info from {url}"))?;
            return Ok(Some(path));
        }

        // Every server we reached returned 404 -> genuinely not found (let the
        // caller fall back). A transport/server error with no success is an
        // error worth surfacing.
        match last_err {
            Some(e) => Err(e.context(format!("fetching debug info for build id {hex}"))),
            None => Ok(None),
        }
    }

    /// Stream a successful response body into `final_path`, writing first to a
    /// uniquely-named temp file in the *same* directory and atomically renaming
    /// it into place, so a reader (or a concurrent fetcher) never observes a
    /// half-written file.
    async fn stream_to_cache(
        &self,
        mut resp: reqwest::Response,
        entry_dir: &Path,
        final_path: &Path,
    ) -> Result<PathBuf> {
        fs::create_dir_all(entry_dir)
            .with_context(|| format!("creating {}", entry_dir.display()))?;

        // Same directory as the final path keeps the rename on one filesystem
        // (so it's atomic); the uuid keeps concurrent fetchers from colliding on
        // the temp name.
        let tmp_path = entry_dir.join(format!(".tmp-{}", uuid::Uuid::now_v7()));
        let write = async {
            let mut file = tokio::fs::File::create(&tmp_path)
                .await
                .with_context(|| format!("creating {}", tmp_path.display()))?;
            // Stream chunk-by-chunk rather than buffering a potentially large
            // debug file in memory. `Response::chunk` needs no extra feature.
            while let Some(chunk) = resp.chunk().await.context("reading response body")? {
                file.write_all(&chunk)
                    .await
                    .context("writing debug info to cache")?;
            }
            file.flush().await.context("flushing cache file")?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        if let Err(e) = write {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }

        // Publish atomically. If another worker raced us to the same build ID the
        // rename simply replaces an identical (content-addressed) file, and any
        // reader holding the old inode keeps a valid fd — so overwriting is safe.
        if let Err(e) = tokio::fs::rename(&tmp_path, final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(
                anyhow!(e).context(format!("publishing cache file {}", final_path.display()))
            );
        }
        Ok(final_path.to_path_buf())
    }
}

/// Split a debuginfod URL list into normalized base URLs. Accepts the comma-,
/// space-, and newline-separated forms used by both `DEBUGINFOD_URLS` and the
/// `/etc/debuginfod/*.urls` files, trimming each entry and its trailing `/`.
fn parse_urls(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_owned())
        .collect()
}

/// Read the system-wide server URLs from `/etc/debuginfod/*.urls` (e.g.
/// `elfutils.urls`). These are the files `/etc/profile.d/debuginfod.sh` would
/// fold into `DEBUGINFOD_URLS` for login shells; a daemon may not inherit that
/// environment, so we read them directly. Files are consumed in sorted order so
/// URL preference is stable; a missing directory means "not configured" and an
/// unreadable file is skipped with a warning.
fn urls_from_system_config() -> Vec<String> {
    const CONFIG_DIR: &str = "/etc/debuginfod";

    let entries = match fs::read_dir(CONFIG_DIR) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "urls"))
        .collect();
    files.sort();

    let mut urls = Vec::new();
    for path in files {
        match fs::read_to_string(&path) {
            Ok(contents) => urls.extend(parse_urls(&contents)),
            Err(e) => warn!("skipping debuginfod config {}: {e}", path.display()),
        }
    }
    urls
}

/// Resolve the on-disk cache root, mirroring `debuginfod-find`: explicit
/// `DEBUGINFOD_CACHE_PATH`, else `$XDG_CACHE_HOME/debuginfod_client`, else
/// `$HOME/.cache/debuginfod_client`.
fn cache_dir() -> Result<PathBuf> {
    if let Some(p) = env::var_os("DEBUGINFOD_CACHE_PATH").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    if let Some(xdg) = env::var_os("XDG_CACHE_HOME").filter(|x| !x.is_empty()) {
        return Ok(PathBuf::from(xdg).join("debuginfod_client"));
    }
    if let Some(home) = env::var_os("HOME").filter(|h| !h.is_empty()) {
        return Ok(PathBuf::from(home).join(".cache").join("debuginfod_client"));
    }
    bail!("no debuginfod cache directory: set DEBUGINFOD_CACHE_PATH, XDG_CACHE_HOME, or HOME")
}

/// Lower-case hex encoding of a raw build ID, as used in debuginfod URLs and
/// cache paths. Only emits `[0-9a-f]`, so the result can never escape the cache
/// directory when joined as a path component.
fn hex_build_id(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls_handles_separators_and_normalizes() {
        // Space-, comma-, and newline-separated forms all parse; trailing
        // slashes are stripped and blank entries dropped (as in a `.urls` file).
        assert_eq!(
            parse_urls("https://a.example/ https://b.example"),
            vec!["https://a.example", "https://b.example"]
        );
        assert_eq!(
            parse_urls("https://a.example,https://b.example"),
            vec!["https://a.example", "https://b.example"]
        );
        assert_eq!(
            parse_urls("\nhttps://a.example/\n\nhttps://b.example/\n"),
            vec!["https://a.example", "https://b.example"]
        );
        assert!(parse_urls("   \n  ").is_empty());
    }

    #[test]
    fn hex_build_id_matches_debuginfod_formatting() {
        let bytes = [
            0xae, 0xb9, 0xa9, 0x83, 0xac, 0xe1, 0xfb, 0x04, 0x7b, 0x23, 0x41, 0xb1, 0x95, 0x01,
            0x65, 0x44, 0x0f, 0xb2, 0xa8, 0xb9,
        ];
        assert_eq!(
            hex_build_id(&bytes),
            "aeb9a983ace1fb047b2341b1950165440fb2a8b9"
        );
        assert_eq!(hex_build_id(&[]), "");
        // Single-byte values are zero-padded to two hex digits.
        assert_eq!(hex_build_id(&[0x00, 0x0f]), "000f");
    }
}
