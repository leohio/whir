// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {Keccak256Chain} from "../Keccak256Chain.sol";

contract AbsorbEmptyTest is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    function test_absorb_empty_bytes() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();

        // absorb empty bytes
        bytes memory empty = hex"";
        s.absorb(empty);

        // Manual: keccak256(0x00...00 || "") = keccak256(0x00...00)
        bytes32 expected = keccak256(abi.encodePacked(bytes32(0)));
        assertEq(s.state, expected, "absorb empty should = keccak256(state)");
    }

    function test_init_sequence_matches_fixture() public {
        string memory json = vm.readFile("test/data/whir/keccak256chain_verifier_data.json");
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");

        Keccak256Chain.Sponge memory s = Keccak256Chain.init();

        // Step 1: absorb protocolId (64 bytes)
        s.absorb(protocolId);
        // Step 2: absorb sessionId (32 bytes)
        s.absorb(sessionId);
        // Step 3: absorb instance (empty)
        s.absorb(instance);

        // Manually compute
        bytes32 s0 = bytes32(0);
        bytes32 s1 = keccak256(abi.encodePacked(s0, protocolId));
        bytes32 s2 = keccak256(abi.encodePacked(s1, sessionId));
        bytes32 s3 = keccak256(abi.encodePacked(s2, instance));

        assertEq(s.state, s3, "init sequence mismatch");

        // Now squeeze 32 bytes and verify
        bytes memory squeezed = s.squeeze(32);
        bytes32 expectedSqueeze = keccak256(abi.encodePacked(s3, "squeeze", bytes8(uint64(0))));
        bytes32 actualSqueeze;
        assembly { actualSqueeze := mload(add(squeezed, 32)) }
        assertEq(actualSqueeze, expectedSqueeze, "first squeeze mismatch");

        emit log_named_bytes32("state after init", s3);
        emit log_named_bytes32("first squeeze", expectedSqueeze);
    }
}
