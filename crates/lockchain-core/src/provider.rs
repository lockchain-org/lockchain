//! Provider contracts used by `lockchain-core` workflows.
//!
//! Concrete implementations live in provider crates such as `lockchain-zfs` and
//! `lockchain-luks`. The shared traits/types are sourced from `lockchain-provider`
//! so the core crate stays focused on workflows and policy handling.

use std::error::Error;

pub use lockchain_provider::luks::{LuksMappingDescriptor, LuksProvider, LuksState};
pub use lockchain_provider::zfs::{DatasetKeyDescriptor, KeyState, KeyStatusSnapshot, ZfsProvider};
pub use lockchain_provider::ProviderKind;

/// High-level provider trait used by unlock/status workflows.
///
/// This trait deliberately models the "unlock a tree of resources using raw key
/// bytes" workflow so the rest of the stack can switch providers without
/// duplicating orchestration logic.
pub trait KeyProvider {
    type Error: Error + Send + Sync + 'static;

    /// Identify which provider implementation backs this instance.
    fn kind(&self) -> ProviderKind;

    /// Resolve the encryption root responsible for `target`.
    fn encryption_root(&self, target: &str) -> Result<String, Self::Error>;

    /// Return managed resources under `root` (including the root itself) that still
    /// report a sealed/inactive state.
    fn locked_descendants(&self, root: &str) -> Result<Vec<String>, Self::Error>;

    /// Attempt to load a key for `root` and any descendants that share it.
    fn load_key_tree(&self, root: &str, key: &[u8]) -> Result<Vec<String>, Self::Error>;

    /// Describe the key status for the provided target list.
    fn describe_targets(&self, targets: &[String]) -> Result<KeyStatusSnapshot, Self::Error>;
}

impl<T> KeyProvider for T
where
    T: ZfsProvider,
{
    type Error = T::Error;

    fn kind(&self) -> ProviderKind {
        ProviderKind::Zfs
    }

    fn encryption_root(&self, target: &str) -> Result<String, Self::Error> {
        ZfsProvider::encryption_root(self, target)
    }

    fn locked_descendants(&self, root: &str) -> Result<Vec<String>, Self::Error> {
        ZfsProvider::locked_descendants(self, root)
    }

    fn load_key_tree(&self, root: &str, key: &[u8]) -> Result<Vec<String>, Self::Error> {
        ZfsProvider::load_key_tree(self, root, key)
    }

    fn describe_targets(&self, targets: &[String]) -> Result<KeyStatusSnapshot, Self::Error> {
        ZfsProvider::describe_datasets(self, targets)
    }
}

/// Adapter that models a LUKS provider as a `KeyProvider` for shared workflows.
#[derive(Debug, Clone)]
pub struct LuksKeyProvider<P> {
    inner: P,
}

impl<P> LuksKeyProvider<P> {
    pub fn new(inner: P) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &P {
        &self.inner
    }

    pub fn into_inner(self) -> P {
        self.inner
    }
}

impl<P> KeyProvider for LuksKeyProvider<P>
where
    P: LuksProvider,
{
    type Error = P::Error;

    fn kind(&self) -> ProviderKind {
        ProviderKind::Luks
    }

    fn encryption_root(&self, target: &str) -> Result<String, Self::Error> {
        Ok(target.to_string())
    }

    fn locked_descendants(&self, root: &str) -> Result<Vec<String>, Self::Error> {
        match self.inner.mapping_state(root)? {
            LuksState::Active => Ok(Vec::new()),
            LuksState::Inactive => Ok(vec![root.to_string()]),
            LuksState::Unknown(_) => Ok(vec![root.to_string()]),
        }
    }

    fn load_key_tree(&self, root: &str, key: &[u8]) -> Result<Vec<String>, Self::Error> {
        self.inner.unlock_mapping(root, key)?;
        Ok(vec![root.to_string()])
    }

    fn describe_targets(&self, targets: &[String]) -> Result<KeyStatusSnapshot, Self::Error> {
        let mut entries = Vec::with_capacity(targets.len());
        for target in targets {
            let state = self.inner.mapping_state(target)?;
            let key_state = match state {
                LuksState::Active => KeyState::Available,
                LuksState::Inactive => KeyState::Unavailable,
                LuksState::Unknown(reason) => KeyState::Unknown(reason),
            };
            entries.push(DatasetKeyDescriptor {
                dataset: target.clone(),
                encryption_root: target.clone(),
                state: key_state,
            });
        }
        Ok(entries)
    }
}
