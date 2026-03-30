//! EVM-friendly Fiat-Shamir transcript based on a keccak256 hash chain.
//!
//! This construction is designed so that each absorb/squeeze operation
//! maps to a single `SHA3` (keccak256) EVM opcode call (30 gas),
//! avoiding the need for a manual Keccak-f[1600] permutation (~40,000 gas).
//!
//! ## Protocol
//!
//! - **absorb**(input): `state = keccak256(state ‖ input)`
//! - **squeeze**(n bytes): for each 32-byte block, `output_i = keccak256(state ‖ "squeeze" ‖ counter_be)`, counter++
//! - **ratchet**: `state = keccak256(state ‖ "ratchet")`, counter = 0

use sha3::{Digest, Keccak256};
use spongefish::DuplexSpongeInterface;

/// A keccak256-based hash chain implementing the spongefish [`DuplexSpongeInterface`].
///
/// Every state transition is a single `keccak256(...)` call, making it
/// straightforward to replicate in Solidity using the `SHA3` opcode.
#[derive(Clone, Debug, Default)]
pub struct Keccak256Chain {
    /// The 32-byte running chain state.
    state: [u8; 32],
    /// Counter used during squeeze to derive distinct output blocks.
    squeeze_counter: u64,
}

impl DuplexSpongeInterface for Keccak256Chain {
    type U = u8;

    fn absorb(&mut self, input: &[Self::U]) -> &mut Self {
        // state = keccak256(state || input)
        let mut hasher = Keccak256::new();
        hasher.update(self.state);
        hasher.update(input);
        self.state = hasher.finalize().into();
        self.squeeze_counter = 0;
        self
    }

    fn squeeze(&mut self, output: &mut [Self::U]) -> &mut Self {
        let mut offset = 0;
        while offset < output.len() {
            // output_block = keccak256(state || "squeeze" || counter_be)
            let mut hasher = Keccak256::new();
            hasher.update(self.state);
            hasher.update(b"squeeze");
            hasher.update(self.squeeze_counter.to_be_bytes());
            let block: [u8; 32] = hasher.finalize().into();

            let remaining = output.len() - offset;
            let copy_len = remaining.min(32);
            output[offset..offset + copy_len].copy_from_slice(&block[..copy_len]);

            self.squeeze_counter += 1;
            offset += copy_len;
        }
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        // state = keccak256(state || "ratchet")
        let mut hasher = Keccak256::new();
        hasher.update(self.state);
        hasher.update(b"ratchet");
        self.state = hasher.finalize().into();
        self.squeeze_counter = 0;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absorb_squeeze_deterministic() {
        let mut chain = Keccak256Chain::default();
        chain.absorb(b"hello");
        let mut out1 = [0u8; 32];
        chain.squeeze(&mut out1);

        let mut chain2 = Keccak256Chain::default();
        chain2.absorb(b"hello");
        let mut out2 = [0u8; 32];
        chain2.squeeze(&mut out2);

        assert_eq!(out1, out2);
    }

    #[test]
    fn squeeze_streaming() {
        // squeeze(64) == squeeze(32) || squeeze(32)
        let mut chain1 = Keccak256Chain::default();
        chain1.absorb(b"test");
        let mut out_combined = [0u8; 64];
        chain1.squeeze(&mut out_combined);

        let mut chain2 = Keccak256Chain::default();
        chain2.absorb(b"test");
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        chain2.squeeze(&mut out_a);
        chain2.squeeze(&mut out_b);

        assert_eq!(&out_combined[..32], &out_a);
        assert_eq!(&out_combined[32..], &out_b);
    }

    #[test]
    fn absorb_resets_squeeze_counter() {
        let mut chain = Keccak256Chain::default();
        chain.absorb(b"first");
        let mut out1 = [0u8; 32];
        chain.squeeze(&mut out1);

        // absorb again should reset counter
        chain.absorb(b"second");
        let mut out2 = [0u8; 32];
        chain.squeeze(&mut out2);

        // outputs should differ (different state)
        assert_ne!(out1, out2);
    }

    #[test]
    fn ratchet_changes_state() {
        let mut chain1 = Keccak256Chain::default();
        chain1.absorb(b"data");
        let mut out1 = [0u8; 32];
        chain1.squeeze(&mut out1);

        let mut chain2 = Keccak256Chain::default();
        chain2.absorb(b"data");
        chain2.ratchet();
        let mut out2 = [0u8; 32];
        chain2.squeeze(&mut out2);

        assert_ne!(out1, out2);
    }

    #[test]
    fn evm_compatible_known_vector() {
        // Verify a known keccak256 computation:
        // keccak256(0x00..00 || "hello") should match the EVM result.
        let mut chain = Keccak256Chain::default();
        chain.absorb(b"hello");

        // Manually compute: keccak256([0u8; 32] || b"hello")
        let mut hasher = Keccak256::new();
        hasher.update([0u8; 32]);
        hasher.update(b"hello");
        let expected_state: [u8; 32] = hasher.finalize().into();

        assert_eq!(chain.state, expected_state);
    }
}
