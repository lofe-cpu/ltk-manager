//! Builds the patcher delivery client of this manager build and runs its syncs.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fs_err as fs;
use ltk_manager_base::config::Config;
use ltk_manager_base::hashing::sha256_file;
use ltk_manager_runtime::patcher::delivery::{
    attested_build, Channel, DeliveryError, PatcherDelivery, StagedPatcher,
};
use parking_lot::Mutex;
use semver::{Prerelease, Version};

use crate::patcher::host::{HOOK_DLL_NAME, HOST_EXE_NAME};

/// Base URL and base64 minisign manifest key of the staging delivery service.
const STAGING: (&str, &str) = (
    "https://patcher-staging.leaguetoolkit.dev",
    "RWRHh5bl7JOIscd3lf1Sw2xqd5qcoSeau1GmXjBm7C4KA4YSB0DOf+Kx",
);
/// Base URL and base64 minisign manifest key of the production delivery service.
const PRODUCTION: (&str, &str) = (
    "https://patcher.leaguetoolkit.dev",
    "RWSk74swcHfkZfLblm3iSk9RLVHJ1xjtqn/zySIPaCBM1hecnlFy1Bxi",
);

/// Build attestation that the release workflow signed for this manager version.
///
/// Read by `option_env!` at compile time. A build without it reads the staged DLLs only.
const ATTESTATION: Option<&str> = option_env!("LTK_PATCHER_ATTESTATION");

/// Delivery environment that the attestation is for. `staging` selects staging, and any
/// other value or no value selects production.
///
/// Read by `option_env!` at compile time, beside [`ATTESTATION`].
const DELIVERY: Option<&str> = option_env!("LTK_PATCHER_DELIVERY");

/// Host protocol of `resources/ltk_patcher_host.exe`, as decimal text.
///
/// The release workflow reads the same file into the build attestation, so the file must
/// change together with the binary.
const BUNDLED_HOST_PROTOCOL: &str = include_str!("../../host-protocol");

/// Environment variable that names a patcher DLL to run instead of a delivered one.
///
/// Read at runtime. A build that has no attestation cannot download a DLL, so a fork reads
/// this to run a DLL it provides, without the delivery service.
const DLL_OVERRIDE: &str = "LTK_PATCHER_DLL";

/// Staging directory name for the DLL that [`DLL_OVERRIDE`] names. Not a digest, so
/// `remove_unused` keeps it.
const OVERRIDE_DIR: &str = "local-override";

/// Tauri-managed delivery client, and the lock that allows one sync at a time.
#[derive(Clone)]
pub struct PatcherDeliveryState {
    delivery: Option<Arc<PatcherDelivery>>,
    syncing: Arc<Mutex<()>>,
}

impl PatcherDeliveryState {
    /// Builds the client with its state under `data_dir`.
    ///
    /// Removes the staged builds that no cached manifest offers, before any session can
    /// select one. Returns a state without a client if the target is not Windows or if
    /// `data_dir` is `None`. The client has no attestation if the build has none or if its
    /// attestation names another manager version or host protocol.
    pub fn new(data_dir: Option<&Path>) -> Self {
        let manager = Version {
            pre: Prerelease::EMPTY,
            ..Version::parse(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION is semver")
        };
        let release = manager.to_string();
        let protocol: u32 = BUNDLED_HOST_PROTOCOL
            .trim()
            .parse()
            .expect("src-tauri/host-protocol holds a decimal protocol number");
        let (url, public_key) = match DELIVERY {
            Some("staging") => STAGING,
            _ => PRODUCTION,
        };
        let attestation = ATTESTATION.filter(|attestation| {
            attested_build(attestation)
                .is_some_and(|build| build.version == release && build.protocol == protocol)
        });
        if ATTESTATION.is_some() && attestation.is_none() {
            tracing::warn!(
                %release,
                protocol,
                "The build attestation does not name this manager version and host protocol. The patcher DLL is not downloaded"
            );
        }

        let delivery = data_dir.filter(|_| cfg!(windows)).map(|dir| {
            Arc::new(PatcherDelivery {
                root: dir.join(crate::data_location::PATCHER),
                url: url.to_string(),
                public_key: public_key.to_string(),
                attestation: attestation.map(str::to_string),
                manager,
                protocol,
            })
        });
        if let Some(delivery) = &delivery {
            delivery.remove_unused();
        }

        Self {
            delivery,
            syncing: Arc::new(Mutex::new(())),
        }
    }

    /// Returns the client, or `None` if this target does not use delivery.
    pub fn delivery(&self) -> Option<&PatcherDelivery> {
        self.delivery.as_deref()
    }

    /// Syncs the channel of `config` on a background thread, after any running sync.
    ///
    /// Skips the sync if the build has no attestation.
    pub fn sync_in_background(&self, config: &Config) {
        let Some(delivery) = self
            .delivery
            .clone()
            .filter(|delivery| delivery.attestation.is_some())
        else {
            return;
        };

        let syncing = Arc::clone(&self.syncing);
        let channel = channel(config);
        std::thread::spawn(move || {
            let _guard = syncing.lock();
            sync(&delivery, channel);
        });
    }

    /// Selects the build that a session on `channel` runs, downloading it if needed.
    ///
    /// Returns the staged build at once if it is within its end of life. Otherwise waits
    /// for any running sync, then syncs. This blocks on the network, so it must not run on
    /// the main thread.
    ///
    /// # Errors
    ///
    /// Fails if no usable build is staged after the sync, or if the host cannot be copied
    /// beside the DLL.
    pub fn prepare(
        &self,
        channel: Channel,
        bundled_host: &Path,
    ) -> Result<StagedPatcher, DeliveryError> {
        let Some(delivery) = self.delivery() else {
            return Err(DeliveryError::NoRelease);
        };

        if let Some(staged) = local_override(&delivery.root, bundled_host)? {
            return Ok(staged);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if let Some(staged) = delivery
            .select(channel, bundled_host)?
            .filter(|staged| !staged.is_expired(now))
        {
            return Ok(staged);
        }

        let _guard = self.syncing.lock();
        delivery.refresh(channel, bundled_host, now)
    }
}

/// Stages the DLL that [`DLL_OVERRIDE`] names under `root`, beside a copy of `bundled_host`.
///
/// Returns `None` if the variable is unset or empty. Fails if the variable names a path that
/// is not a readable file, or if a copy fails. The staged build never expires.
fn local_override(root: &Path, bundled_host: &Path) -> Result<Option<StagedPatcher>, DeliveryError> {
    let Some(source) = std::env::var_os(DLL_OVERRIDE).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let source = PathBuf::from(source);

    let dir = root.join(OVERRIDE_DIR);
    fs::create_dir_all(&dir)?;

    let dll = dir.join(HOOK_DLL_NAME);
    if !dll.exists() || sha256_file(&dll)? != sha256_file(&source)? {
        fs::copy(&source, &dll)?;
    }

    let host = dir.join(HOST_EXE_NAME);
    if !host.exists() || sha256_file(&host)? != sha256_file(bundled_host)? {
        fs::copy(bundled_host, &host)?;
    }

    let digest = sha256_file(&dll)?;
    tracing::warn!(
        source = %source.display(),
        %digest,
        "Running a local patcher DLL from LTK_PATCHER_DLL, bypassing the delivery service"
    );

    Ok(Some(StagedPatcher {
        dir,
        version: "local".to_string(),
        digest,
        eol: u32::MAX,
    }))
}

/// Returns the delivery channel that `config` selects.
pub fn channel(config: &Config) -> Channel {
    if config.beta_patcher {
        Channel::Beta
    } else {
        Channel::Stable
    }
}

/// Syncs `channel`, and logs and reports a failure.
fn sync(delivery: &PatcherDelivery, channel: Channel) {
    if let Err(error) = delivery.sync(channel) {
        tracing::warn!(%channel, %error, "Patcher delivery sync failed");
        crate::telemetry::report_delivery_sync_failed(channel.as_str(), error.kind().as_str());
    }
}
