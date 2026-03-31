# Keccak256Chain: EVM-friendly Fiat-Shamir transcript

## Goal
Replace the spongefish `StdHash` (Shake128 XOF) with a simple keccak256 hash chain that can be verified on-chain using the EVM's `SHA3` opcode (30 gas), avoiding the need for manual Keccak-f[1600] permutation (~40,000 gas).

## Architecture

The spongefish crate's `Hash<D>` bridge (which wraps any `digest::Digest`) already works with `sha3::Keccak256`, but its internal protocol (masking, squeeze_end, etc.) is complex and not EVM-friendly. We need a **custom** `DuplexSpongeInterface` implementation with a simple, Solidity-reproducible protocol.

### New type: `Keccak256Chain`

**Location:** `src/transcript/keccak256_chain.rs`

**State:**
- `state: [u8; 32]` — the running chain value
- `squeeze_counter: u64` — counter for squeeze derivation

**Operations:**
- `absorb(input)`: `state = keccak256(state || input)` (for each block if input is large, or just concatenate — simple approach: just hash the concatenation)
- `squeeze(output)`: fill output by hashing `keccak256(state || b"squeeze" || counter.to_be_bytes())` repeatedly, incrementing counter for each 32-byte block
- `ratchet()`: `state = keccak256(state || b"ratchet")`, reset counter to 0

This implements `DuplexSpongeInterface` with `type U = u8`.

## Changes

### 1. New file: `src/transcript/keccak256_chain.rs`
- Define `Keccak256Chain` struct
- Implement `DuplexSpongeInterface` for it
- Implement `Default`, `Clone`

### 2. Modify: `src/transcript/mod.rs`
- Add `mod keccak256_chain;`
- `pub use keccak256_chain::Keccak256Chain;`
- Add `Keccak256ChainHash` type alias (or just use `Keccak256Chain` directly)
- Change `StdHash` default type parameter and `new_std` to use `Keccak256Chain` instead of spongefish's `StdHash` (Shake128)
- Also change the domain separation hashes (`Sha3_512`, `Sha3_256`) to use `Keccak256` for consistency

### 3. No other files need changes
All call sites use `ProverState::new_std()` / `VerifierState::new_std()`, which will automatically pick up the new default. The `H` generic parameter with `DuplexSpongeInterface` bound stays the same.

## Verification
- `cargo build` should compile
- `cargo test` should pass (transcript consistency between prover and verifier is the key invariant)
