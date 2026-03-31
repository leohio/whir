// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {Keccak256Chain} from "../Keccak256Chain.sol";

/// @title Keccak256ChainTest
/// @notice Unit tests for Keccak256Chain matching Rust Keccak256Chain.
contract Keccak256ChainTest is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    /// @notice Verify absorb produces correct state.
    function test_absorb_hello() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();

        // state = keccak256(0x00..00 || "hello")
        s.absorb(bytes("hello"));

        bytes32 expected = keccak256(abi.encodePacked(bytes32(0), bytes("hello")));
        assertEq(s.state, expected, "absorb state mismatch");
    }

    /// @notice Verify squeeze output matches manual computation.
    function test_squeeze_after_absorb() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();
        s.absorb(bytes("hello"));

        bytes memory out = s.squeeze(32);

        // squeeze output = keccak256(state || "squeeze" || counter_be(0))
        bytes32 state = keccak256(abi.encodePacked(bytes32(0), bytes("hello")));
        bytes32 expected = keccak256(abi.encodePacked(state, "squeeze", bytes8(uint64(0))));

        bytes32 actual;
        assembly { actual := mload(add(out, 32)) }
        assertEq(actual, expected, "squeeze output mismatch");
    }

    /// @notice Verify squeeze associativity: squeeze(64) == squeeze(32) || squeeze(32).
    function test_squeeze_streaming() public pure {
        Keccak256Chain.Sponge memory s1 = Keccak256Chain.init();
        s1.absorb(bytes("test"));
        bytes memory combined = s1.squeeze(64);

        Keccak256Chain.Sponge memory s2 = Keccak256Chain.init();
        s2.absorb(bytes("test"));
        bytes memory a = s2.squeeze(32);
        bytes memory b = s2.squeeze(32);

        // First 32 bytes should match
        for (uint256 i = 0; i < 32; i++) {
            assertEq(combined[i], a[i], "first half mismatch");
        }
        // Second 32 bytes should match
        for (uint256 i = 0; i < 32; i++) {
            assertEq(combined[32 + i], b[i], "second half mismatch");
        }
    }

    /// @notice Verify ratchet changes state.
    function test_ratchet() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();
        s.absorb(bytes("data"));
        bytes32 stateBeforeRatchet = s.state;

        s.ratchet();

        bytes32 expectedAfterRatchet = keccak256(abi.encodePacked(stateBeforeRatchet, "ratchet"));
        assertEq(s.state, expectedAfterRatchet, "ratchet state mismatch");
        assertEq(s.squeezeCounter, 0, "ratchet counter not reset");
    }

    /// @notice Test domain separator initialization matches fixture expectations.
    ///         Replay the first few transcript operations and check sponge state.
    function test_domain_separator_init() public view {
        string memory json = vm.readFile("test/data/whir/keccak256chain_verifier_data.json");
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");

        Keccak256Chain.Sponge memory s = Keccak256Chain.init();

        // Step 1: absorb protocol_id (64 bytes)
        s.absorb(protocolId);
        assertEq(protocolId.length, 64, "protocol_id should be 64 bytes");

        // Step 2: absorb session_id (32 bytes)
        s.absorb(sessionId);
        assertEq(sessionId.length, 32, "session_id should be 32 bytes");

        // Step 3: instance = empty bytes (0x) → absorb 0 bytes (no-op for Keccak256Chain)
        // After init, state should be keccak256(keccak256(0 || protocolId) || sessionId)
        bytes32 state0 = bytes32(0);
        bytes32 state1 = keccak256(abi.encodePacked(state0, protocolId));
        bytes32 state2 = keccak256(abi.encodePacked(state1, sessionId));

        assertEq(s.state, state2, "sponge state after domain separator init");
        assertEq(s.squeezeCounter, 0, "counter should be 0 after absorb");
    }
}
