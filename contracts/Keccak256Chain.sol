// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Keccak256Chain
/// @notice EVM-friendly Fiat-Shamir transcript using keccak256 hash chain.
///         Matches the Rust Keccak256Chain in src/transcript/keccak256_chain.rs.
///
///   absorb(input): state = keccak256(state || input), counter = 0
///   squeeze(n):    output_i = keccak256(state || "squeeze" || counter_be), counter++
///   ratchet():     state = keccak256(state || "ratchet"), counter = 0
library Keccak256Chain {
    struct Sponge {
        bytes32 state;
        uint64 squeezeCounter;
    }

    /// @notice Initialize a fresh sponge (state = 0, counter = 0).
    function init() internal pure returns (Sponge memory s) {
        // default zero-initialized
    }

    /// @notice Absorb arbitrary bytes: state = keccak256(state || input), counter = 0.
    function absorb(Sponge memory s, bytes memory input) internal pure {
        s.state = keccak256(abi.encodePacked(s.state, input));
        s.squeezeCounter = 0;
    }

    /// @notice Squeeze n bytes: each 32-byte block = keccak256(state || "squeeze" || counter_be).
    ///         Counter is big-endian uint64 (matches Rust's .to_be_bytes()).
    function squeeze(Sponge memory s, uint256 n) internal pure returns (bytes memory output) {
        output = new bytes(n);
        uint256 offset = 0;
        while (offset < n) {
            bytes32 h = keccak256(
                abi.encodePacked(s.state, "squeeze", bytes8(s.squeezeCounter))
            );
            s.squeezeCounter++;
            uint256 copyLen = n - offset;
            if (copyLen > 32) copyLen = 32;
            for (uint256 i = 0; i < copyLen; i++) {
                output[offset + i] = h[i];
            }
            offset += copyLen;
        }
    }

    /// @notice Ratchet: state = keccak256(state || "ratchet"), counter = 0.
    function ratchet(Sponge memory s) internal pure {
        s.state = keccak256(abi.encodePacked(s.state, "ratchet"));
        s.squeezeCounter = 0;
    }
}
