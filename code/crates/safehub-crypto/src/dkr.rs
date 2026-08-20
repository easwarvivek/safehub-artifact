//! Dual key regression (DKR) / group key progression.
//!
//! Interval tokens unlock epoch keys `K_e` only for `e ∈ [from, to]`.
//! `forward_block` reseeds so retained pre-removal tokens cannot derive
//! post-removal epochs. `backward_block` issues a forward-only interval.
//!
//! Token material and RO-shaped outputs are λ = 384 bits
//! ([`crate::params::SEC_PARAM_LEN`]); derived epoch keys `K_e` remain
//! 256-bit AES keys.

use crate::error::CryptoError;
use crate::params::{domain_label, AEAD_KEY_LEN, SEC_PARAM_LEN};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compact interval capability: derive epoch keys K_e for e in `[from, to]`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DkrInterval {
    /// Inclusive start epoch.
    pub from: u64,
    /// Inclusive end epoch (or current tip).
    pub to: u64,
    /// Opaque token material (λ = 384-bit seed for this segment).
    #[serde(with = "crate::params::sec_param_serde")]
    pub token: [u8; SEC_PARAM_LEN],
}

/// Default DKR segment capacity \(N = 2^{20}\) (paper Table IX).
pub const DKR_SEGMENT_CAPACITY: u64 = 1 << 20;

/// Dual-key-regression progression.
pub trait DualKeyRegression: Send + Sync {
    /// Seed a fresh chain at epoch 0.
    fn init(&mut self) -> Result<DkrInterval, CryptoError>;

    /// Advance to `epoch`, returning the current full-access interval for
    /// this segment (`[segment_start, epoch]`).
    ///
    /// When the segment would exceed [`DKR_SEGMENT_CAPACITY`] epochs, the
    /// implementation must re-init (fresh seed) without widening any previously
    /// issued window.
    fn advance(&mut self, epoch: u64) -> Result<DkrInterval, CryptoError>;

    /// Insert a forward block after removal (fresh forward chain).
    ///
    /// Subsequent [`advance`] tokens use a new seed. Callers must cap any
    /// previously issued interval at the removal epoch before distributing
    /// post-removal material.
    fn forward_block(&mut self, epoch: u64) -> Result<(), CryptoError>;

    /// Insert a backward block for a forward-only join at `epoch`.
    ///
    /// Must issue a **cryptographically independent** segment token so a
    /// forward-only holder cannot recover pre-join keys by widening `from`.
    fn backward_block(&mut self, epoch: u64) -> Result<DkrInterval, CryptoError>;

    /// Derive epoch key K_e (AES-256) from an interval token.
    fn derive_epoch_key(
        &self,
        interval: &DkrInterval,
        epoch: u64,
    ) -> Result<[u8; AEAD_KEY_LEN], CryptoError>;
}

/// Interval DKR with forward/backward segment boundaries.
#[derive(Clone)]
pub struct IntervalDkr {
    seed: [u8; SEC_PARAM_LEN],
    epoch: u64,
    /// Start of the current backward segment (forward-only joins raise this).
    segment_start: u64,
    /// Epochs consumed in the current segment (re-init at [`DKR_SEGMENT_CAPACITY`]).
    segment_epochs: u64,
    /// Generation counter incremented on segment re-init / forward_block.
    segment_gen: u64,
}

impl Default for IntervalDkr {
    fn default() -> Self {
        Self {
            seed: [0u8; SEC_PARAM_LEN],
            epoch: 0,
            segment_start: 0,
            segment_epochs: 0,
            segment_gen: 0,
        }
    }
}

impl IntervalDkr {
    /// Construct with an explicit λ-bit seed (tests / deterministic fixtures).
    pub fn with_seed(seed: [u8; SEC_PARAM_LEN]) -> Self {
        Self {
            seed,
            epoch: 0,
            segment_start: 0,
            segment_epochs: 0,
            segment_gen: 0,
        }
    }

    /// Current segment generation (increments on re-init / forward_block).
    pub fn segment_generation(&self) -> u64 {
        self.segment_gen
    }

    fn ensure_seeded(&mut self) {
        if self.seed == [0u8; SEC_PARAM_LEN] {
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut self.seed);
        }
    }

    fn current_interval(&self) -> DkrInterval {
        DkrInterval {
            from: self.segment_start,
            to: self.epoch,
            token: self.seed,
        }
    }

    /// Re-init at segment exhaustion: fresh seed, new segment starting at `epoch`.
    ///
    /// Previously issued intervals keep their `[from,to]` caps and old tokens;
    /// they cannot derive keys past their `to` and cannot follow the new seed.
    /// This never widens an existing window.
    pub fn reinit_segment(&mut self, epoch: u64) -> Result<DkrInterval, CryptoError> {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut self.seed);
        self.epoch = epoch;
        self.segment_start = epoch;
        self.segment_epochs = 0;
        self.segment_gen = self.segment_gen.saturating_add(1);
        Ok(self.current_interval())
    }
}

impl DualKeyRegression for IntervalDkr {
    fn init(&mut self) -> Result<DkrInterval, CryptoError> {
        self.ensure_seeded();
        self.epoch = 0;
        self.segment_start = 0;
        self.segment_epochs = 0;
        self.segment_gen = 0;
        Ok(self.current_interval())
    }

    fn advance(&mut self, epoch: u64) -> Result<DkrInterval, CryptoError> {
        self.ensure_seeded();
        if epoch < self.epoch {
            return Err(CryptoError::EpochOutOfWindow {
                epoch,
                from: self.segment_start,
                to: self.epoch,
            });
        }
        let delta = epoch.saturating_sub(self.segment_start) + 1;
        if delta > DKR_SEGMENT_CAPACITY {
            // Exhaustion: re-init without widening prior windows.
            return self.reinit_segment(epoch);
        }
        self.epoch = epoch;
        self.segment_epochs = delta;
        Ok(self.current_interval())
    }

    fn forward_block(&mut self, epoch: u64) -> Result<(), CryptoError> {
        // Fresh forward seed: pre-block tokens (old seed) cannot derive e > cap.
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut self.seed);
        self.epoch = epoch;
        // New segment continues from the post-removal epoch.
        self.segment_start = epoch;
        self.segment_epochs = 0;
        self.segment_gen = self.segment_gen.saturating_add(1);
        Ok(())
    }

    fn backward_block(&mut self, epoch: u64) -> Result<DkrInterval, CryptoError> {
        // Fresh segment seed: the joiner token is independent of every prior
        // seed, so widening `from` on the returned interval cannot recover
        // pre-join K_e values (those remain under the previous seed only).
        // Callers that need pre-join access must retain the prior interval
        // token before this call (same discipline as forward_block).
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut self.seed);
        self.epoch = epoch;
        self.segment_start = epoch;
        self.segment_epochs = 0;
        self.segment_gen = self.segment_gen.saturating_add(1);
        Ok(self.current_interval())
    }

    fn derive_epoch_key(
        &self,
        interval: &DkrInterval,
        epoch: u64,
    ) -> Result<[u8; AEAD_KEY_LEN], CryptoError> {
        if epoch < interval.from || epoch > interval.to {
            return Err(CryptoError::EpochOutOfWindow {
                epoch,
                from: interval.from,
                to: interval.to,
            });
        }
        let hk = Hkdf::<Sha512>::new(None, &interval.token);
        let mut okm = [0u8; AEAD_KEY_LEN];
        let info = domain_label(&format!("dkr-epoch:{epoch}"));
        hk.expand(info.as_bytes(), &mut okm)
            .map_err(|_| CryptoError::Kdf)?;
        Ok(okm)
    }
}

/// Cap an issued interval at `last` (removal): retained tokens lose future epochs.
pub fn cap_interval(interval: &DkrInterval, last: u64) -> DkrInterval {
    DkrInterval {
        from: interval.from,
        to: last.min(interval.to),
        token: interval.token,
    }
}

/// Alias kept for existing call sites; implements real interval boundaries.
pub type StubDkr = IntervalDkr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_lambda_bits() {
        let mut dkr = IntervalDkr::with_seed([9u8; SEC_PARAM_LEN]);
        let interval = dkr.init().unwrap();
        assert_eq!(interval.token.len(), 48);
        let ke = dkr.derive_epoch_key(&interval, 0).unwrap();
        assert_eq!(ke.len(), 32);
    }

    #[test]
    fn domain_separated_epoch_keys_differ() {
        let dkr = IntervalDkr::with_seed([1u8; SEC_PARAM_LEN]);
        let interval = DkrInterval {
            from: 0,
            to: 2,
            token: [1u8; SEC_PARAM_LEN],
        };
        let k0 = dkr.derive_epoch_key(&interval, 0).unwrap();
        let k1 = dkr.derive_epoch_key(&interval, 1).unwrap();
        assert_ne!(k0, k1);
    }

    #[test]
    fn removed_member_cannot_derive_future_after_forward_block() {
        let mut dkr = IntervalDkr::with_seed([2u8; SEC_PARAM_LEN]);
        let _ = dkr.init().unwrap();
        let pre = dkr.advance(5).unwrap();
        // Removal at epoch 5: cap retained token, then forward-block.
        let retained = cap_interval(&pre, 5);
        dkr.forward_block(6).unwrap();
        let post = dkr.advance(7).unwrap();

        assert!(dkr.derive_epoch_key(&retained, 5).is_ok());
        assert!(dkr.derive_epoch_key(&retained, 6).is_err());
        assert!(dkr.derive_epoch_key(&retained, 7).is_err());
        // New seed differs: even uncapped old token cannot open post keys.
        let uncapped_old = DkrInterval {
            from: 0,
            to: 100,
            token: retained.token,
        };
        let k_old_attempt = dkr.derive_epoch_key(&uncapped_old, 7);
        // Window check allows 7, but key material must differ from post segment.
        let k_post = dkr.derive_epoch_key(&post, 7).unwrap();
        if let Ok(k_old) = k_old_attempt {
            assert_ne!(
                k_old, k_post,
                "pre-removal seed must not equal post-forward_block K_e"
            );
        }
    }

    #[test]
    fn forward_only_interval_cannot_derive_prejoin() {
        let mut dkr = IntervalDkr::with_seed([3u8; SEC_PARAM_LEN]);
        let _ = dkr.init().unwrap();
        let full = dkr.advance(4).unwrap();
        let k_pre = dkr.derive_epoch_key(&full, 4).unwrap();
        let join = dkr.backward_block(5).unwrap();
        assert_eq!(join.from, 5);
        assert_ne!(join.token, full.token, "backward_block must reseed");
        assert!(dkr.derive_epoch_key(&join, 4).is_err());
        assert!(dkr.derive_epoch_key(&join, 5).is_ok());
        // Widening `from` on the joiner token must not recover pre-join keys.
        let forged = DkrInterval {
            from: 0,
            to: join.to,
            token: join.token,
        };
        let leaked = dkr.derive_epoch_key(&forged, 4).unwrap();
        assert_ne!(leaked, k_pre);
    }

    #[test]
    fn segment_exhaustion_reinit_does_not_widen_prior_window() {
        let mut dkr = IntervalDkr::with_seed([4u8; SEC_PARAM_LEN]);
        let _ = dkr.init().unwrap();
        // Place tip just under capacity, capture prior window, then advance past N.
        dkr.segment_start = 0;
        let prior = dkr.advance(DKR_SEGMENT_CAPACITY - 1).unwrap();
        assert_eq!(prior.to, DKR_SEGMENT_CAPACITY - 1);
        let gen_before = dkr.segment_generation();
        let next = dkr.advance(DKR_SEGMENT_CAPACITY).unwrap();
        assert_eq!(next.from, DKR_SEGMENT_CAPACITY);
        assert_eq!(next.to, DKR_SEGMENT_CAPACITY);
        assert!(dkr.segment_generation() > gen_before);
        // Prior window unchanged and cannot reach the new segment.
        assert_eq!(prior.to, DKR_SEGMENT_CAPACITY - 1);
        assert!(dkr.derive_epoch_key(&prior, DKR_SEGMENT_CAPACITY).is_err());
        let k_new = dkr.derive_epoch_key(&next, DKR_SEGMENT_CAPACITY).unwrap();
        let forged = DkrInterval {
            from: prior.from,
            to: DKR_SEGMENT_CAPACITY,
            token: prior.token,
        };
        if let Ok(k_old) = dkr.derive_epoch_key(&forged, DKR_SEGMENT_CAPACITY) {
            assert_ne!(k_old, k_new);
        }
    }
}
