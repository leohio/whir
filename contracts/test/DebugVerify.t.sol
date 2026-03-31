// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SpongefishWhir} from "../SpongefishWhir.sol";
import {SpongefishWhirVerify} from "../SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../GoldilocksExt3.sol";
import {Keccak256Chain} from "../Keccak256Chain.sol";

contract DebugVerifyTest is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    string constant FIXTURE_PATH = "test/data/whir/keccak256chain_verifier_data.json";

    function test_debug_phase3_merkle() public {
        string memory json = vm.readFile(FIXTURE_PATH);
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        SpongefishWhir.TranscriptState memory ts = SpongefishWhir.initTranscript(protocolId, sessionId, instance);

        // Phase 1: Initial commitment
        bytes32 initialRoot = SpongefishWhir.proverMessageHash(ts, transcript);
        emit log_named_bytes32("Initial root", initialRoot);

        // OOD points (all first)
        SpongefishWhir.verifierMessageField64x3(ts);
        // OOD answers (all after)
        SpongefishWhir.proverMessageField64x3(ts, transcript);
        // geometric_challenge(1) - no squeeze
        // geometric_challenge(2) - squeeze 120
        SpongefishWhir.geometricChallenge(ts, 1);
        SpongefishWhir.geometricChallenge(ts, 2);

        // Phase 2: 4 sumcheck rounds
        for (uint256 i = 0; i < 4; i++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript); // c0
            SpongefishWhir.proverMessageField64x3(ts, transcript); // c2
            SpongefishWhir.verifierMessageField64x3(ts);           // folding r
        }

        emit log_named_bytes32("State before intermediate", ts.sponge.state);
        emit log_named_uint("transcriptPos", ts.transcriptPos);

        // Phase 3: Intermediate round
        bytes32 roundRoot = SpongefishWhir.proverMessageHash(ts, transcript);
        emit log_named_bytes32("Round root", roundRoot);

        // OOD points (all first), then answers (all after)
        SpongefishWhir.verifierMessageField64x3(ts);
        SpongefishWhir.proverMessageField64x3(ts, transcript);

        emit log_named_bytes32("Before challenge_indices", ts.sponge.state);
        emit log_named_uint("squeezeCounter", ts.sponge.squeezeCounter);

        // Challenge indices(512, 108) - squeeze one byte at a time
        uint256 sizeBytes = 2;
        uint256 totalBytes = 108 * sizeBytes;
        bytes memory entropy = new bytes(totalBytes);
        for (uint256 i = 0; i < totalBytes; i++) {
            entropy[i] = bytes1(ts.sponge.squeezeByte());
        }

        // Compute first 5 indices
        uint256[] memory indices = new uint256[](108);
        for (uint256 i = 0; i < 108; i++) {
            uint256 val = (uint256(uint8(entropy[i*2])) << 8) | uint256(uint8(entropy[i*2+1]));
            indices[i] = val % 512;
        }
        emit log_named_uint("index_0", indices[0]);
        emit log_named_uint("index_1", indices[1]);
        emit log_named_uint("index_2", indices[2]);

        // Read hint: skip Vec prefix
        SpongefishWhir.proverHint(ts, hints, 8);
        emit log_named_uint("hintPos after prefix", ts.hintPos);

        // Read first row, hash it
        bytes memory row0 = SpongefishWhir.proverHint(ts, hints, 128);
        bytes32 hash0;
        assembly { hash0 := keccak256(add(row0, 0x20), 128) }
        emit log_named_bytes32("leaf hash 0", hash0);

        // Skip remaining rows
        for (uint256 i = 1; i < 108; i++) {
            SpongefishWhir.proverHint(ts, hints, 128);
        }
        emit log_named_uint("hintPos after all rows", ts.hintPos);

        // Sort and dedup indices with hashes
        bytes32[] memory allHashes = new bytes32[](108);
        // Recompute all hashes - this time reading from hints again won't work.
        // Instead, let me just check the hintPos
        emit log_named_uint("hints.length", hints.length);
    }
}
