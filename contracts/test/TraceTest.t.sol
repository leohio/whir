// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {Keccak256Chain} from "../Keccak256Chain.sol";
import {SpongefishWhir} from "../SpongefishWhir.sol";
import {GoldilocksExt3} from "../GoldilocksExt3.sol";

/// @title TraceTest
/// @notice Trace sponge state through verification phases to compare with Rust.
contract TraceTest is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    function test_trace_verification() public {
        string memory json = vm.readFile("test/data/whir/keccak256chain_verifier_data.json");
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");

        SpongefishWhir.TranscriptState memory ts = SpongefishWhir.initTranscript(protocolId, sessionId, instance);
        emit log_named_bytes32("After init", ts.sponge.state);
        // Expected: 80bcc89a5b1e2026e5b3f69e1fede2cb445843ff9b339e1ce11381c0b28e9f82

        // Phase 1: proverMessage(Hash) - 32 bytes
        SpongefishWhir.proverMessageHash(ts, transcript);
        emit log_named_bytes32("After merkle root absorb", ts.sponge.state);
        // Expected: ff7ca6b7cf7ee00b17bc37d4ff56d870388bc5728321f5fc14ea683bad14ce77

        // verifierMessage(Field64_3) - squeeze 120
        SpongefishWhir.verifierMessageField64x3(ts);
        emit log_named_uint("Counter after OOD squeeze", ts.sponge.squeezeCounter);
        // Expected counter: 4

        // proverMessage(Field64_3) - 24 bytes
        SpongefishWhir.proverMessageField64x3(ts, transcript);
        emit log_named_bytes32("After OOD answer absorb", ts.sponge.state);

        // geometric_challenge(1) - no squeeze
        GoldilocksExt3.Ext3[] memory gc1 = SpongefishWhir.geometricChallenge(ts, 1);
        emit log_named_uint("gc1 length", gc1.length);
        emit log_named_uint("Counter after gc(1)", ts.sponge.squeezeCounter);

        // geometric_challenge(2) - squeeze 120
        GoldilocksExt3.Ext3[] memory gc2 = SpongefishWhir.geometricChallenge(ts, 2);
        emit log_named_uint("Counter after gc(2)", ts.sponge.squeezeCounter);
        emit log_named_bytes32("State after gc(2)", ts.sponge.state);
        // Expected state: 948d3b37dda5626746d09af6e15574e4dc172c686ad638f29d537de4e0124ef8
        // Expected counter: 4

        // Phase 3: 4 sumcheck rounds
        for (uint256 r = 0; r < 4; r++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript); // c0
            SpongefishWhir.proverMessageField64x3(ts, transcript); // c2
            SpongefishWhir.verifierMessageField64x3(ts); // folding r
        }
        emit log_named_bytes32("After 4 sumcheck", ts.sponge.state);
        emit log_named_uint("After 4 sumcheck counter", ts.sponge.squeezeCounter);
        emit log_named_uint("After 4 sumcheck tpos", ts.transcriptPos);
        // Expected state: 6f69b6c9b0fc0a90685ff9ef634097469278311e7020dcec7f495d67ffb71e23
        // Expected counter: 4, tpos: 248

        // Phase 4: round commitment
        SpongefishWhir.proverMessageHash(ts, transcript); // round root
        SpongefishWhir.verifierMessageField64x3(ts); // OOD point
        SpongefishWhir.proverMessageField64x3(ts, transcript); // OOD answer

        emit log_named_bytes32("Before challenge_indices", ts.sponge.state);
        emit log_named_uint("Before challenge_indices counter", ts.sponge.squeezeCounter);
        // Expected state: 203022d532734fded4d244d55d79768190e87e461904d8c01fd157e90669860e
        // Expected counter: 0

        // challenge_indices(512, 108) - one byte at a time
        uint256 sizeBytes = 2; // ceil(log2(512)/8) = 2
        uint256 totalBytes = 108 * sizeBytes;
        bytes memory entropy = new bytes(totalBytes);
        for (uint256 i = 0; i < totalBytes; i++) {
            bytes memory oneByte = ts.sponge.squeeze(1);
            entropy[i] = oneByte[0];
        }
        emit log_named_uint("After challenge_indices counter", ts.sponge.squeezeCounter);
        // Expected: 216

        // Check first bytes
        emit log_named_bytes32("First 32 entropy bytes", bytes32(abi.encodePacked(
            entropy[0], entropy[1], entropy[2], entropy[3],
            entropy[4], entropy[5], entropy[6], entropy[7],
            bytes24(0)
        )));
        // Expected first 8: 68301fff8b35a4ae

        // Compute first 5 indices
        for (uint256 i = 0; i < 5; i++) {
            uint256 val = 0;
            for (uint256 j = 0; j < sizeBytes; j++) {
                val = (val << 8) | uint256(uint8(entropy[i * sizeBytes + j]));
            }
            emit log_named_uint(string(abi.encodePacked("index_", vm.toString(i))), val % 512);
        }
        // Expected: [48, 511, 309, 174, 129]
    }
}
