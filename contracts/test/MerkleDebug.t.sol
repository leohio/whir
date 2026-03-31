// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {Keccak256Chain} from "../Keccak256Chain.sol";
import {SpongefishWhir} from "../SpongefishWhir.sol";
import {SpongefishMerkle} from "../SpongefishMerkle.sol";
import {GoldilocksExt3} from "../GoldilocksExt3.sol";

contract MerkleDebugTest is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    function _challengeIndicesRaw(
        SpongefishWhir.TranscriptState memory ts,
        uint256 numLeaves,
        uint256 count
    ) internal pure returns (uint256[] memory indices) {
        uint256 sizeBytes = (numLeaves == 1) ? 0 : _ceilDiv(_log2(numLeaves), 8);
        if (count == 0 || numLeaves == 1) {
            indices = new uint256[](count);
            return indices;
        }
        uint256 totalBytes = count * sizeBytes;
        bytes memory entropy = new bytes(totalBytes);
        for (uint256 i = 0; i < totalBytes; i++) {
            bytes memory oneByte = ts.sponge.squeeze(1);
            entropy[i] = oneByte[0];
        }
        indices = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 val = 0;
            for (uint256 j = 0; j < sizeBytes; j++) {
                val = (val << 8) | uint256(uint8(entropy[i * sizeBytes + j]));
            }
            indices[i] = val % numLeaves;
        }
    }

    function _sortAndDedupWithHashes(
        uint256[] memory indices,
        bytes32[] memory hashes
    ) internal pure returns (uint256[] memory, bytes32[] memory) {
        uint256 n = indices.length;
        for (uint256 i = 1; i < n; i++) {
            uint256 keyIdx = indices[i];
            bytes32 keyHash = hashes[i];
            uint256 j = i;
            while (j > 0 && indices[j - 1] > keyIdx) {
                indices[j] = indices[j - 1];
                hashes[j] = hashes[j - 1];
                j--;
            }
            indices[j] = keyIdx;
            hashes[j] = keyHash;
        }
        if (n <= 1) return (indices, hashes);
        uint256 write = 1;
        for (uint256 i = 1; i < n; i++) {
            if (indices[i] != indices[i - 1]) {
                indices[write] = indices[i];
                hashes[write] = hashes[i];
                write++;
            }
        }
        assembly { mstore(indices, write) mstore(hashes, write) }
        return (indices, hashes);
    }

    function _ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) { return (a + b - 1) / b; }
    function _log2(uint256 x) internal pure returns (uint256 n) { while (x > 1) { x >>= 1; n++; } }

    function test_full_verification_trace() public {
        string memory json = vm.readFile("test/data/whir/keccak256chain_verifier_data.json");
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        SpongefishWhir.TranscriptState memory ts = SpongefishWhir.initTranscript(protocolId, sessionId, instance);

        // ===== Phase 1: Initial commitment =====
        bytes32 initialRoot = SpongefishWhir.proverMessageHash(ts, transcript);
        SpongefishWhir.verifierMessageField64x3(ts); // OOD point
        SpongefishWhir.proverMessageField64x3(ts, transcript); // OOD answer
        SpongefishWhir.geometricChallenge(ts, 1); // vector RLC
        SpongefishWhir.geometricChallenge(ts, 2); // constraint RLC (1 OOD + 1 linear form)
        emit log("Phase 1 OK");

        // ===== Phase 3: Initial sumcheck (4 rounds) =====
        for (uint256 r = 0; r < 4; r++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript); // c0
            SpongefishWhir.proverMessageField64x3(ts, transcript); // c2
            SpongefishWhir.verifierMessageField64x3(ts); // folding randomness
        }
        emit log("Phase 3 (initial sumcheck) OK");

        // ===== Phase 4: Intermediate round =====
        bytes32 roundRoot = SpongefishWhir.proverMessageHash(ts, transcript);
        SpongefishWhir.verifierMessageField64x3(ts); // round OOD
        SpongefishWhir.proverMessageField64x3(ts, transcript); // round OOD answer
        emit log("Round commitment received");

        // Open initial commitment
        uint256[] memory rawIndices = _challengeIndicesRaw(ts, 512, 108);
        SpongefishWhir.proverHint(ts, hints, 8); // Vec length prefix
        bytes32[] memory rawHashes = new bytes32[](108);
        for (uint256 i = 0; i < 108; i++) {
            bytes memory row = SpongefishWhir.proverHint(ts, hints, 128);
            rawHashes[i] = keccak256(row);
        }
        (uint256[] memory si, bytes32[] memory sh) = _sortAndDedupWithHashes(rawIndices, rawHashes);
        ts.hintPos = SpongefishMerkle.verify(initialRoot, 9, si, sh, hints, ts.hintPos);
        emit log("Initial Merkle verification OK");

        // Constraint RLC for intermediate round
        SpongefishWhir.geometricChallenge(ts, 1 + 108); // roundOutDomainSamples + rawIndices
        emit log("Intermediate constraint RLC OK");

        // Round sumcheck (4 rounds)
        for (uint256 r = 0; r < 4; r++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript);
            SpongefishWhir.proverMessageField64x3(ts, transcript);
            SpongefishWhir.verifierMessageField64x3(ts);
        }
        emit log("Round sumcheck OK");

        emit log_named_uint("Transcript pos after round sumcheck", ts.transcriptPos);

        // ===== Phase 5: Final vector =====
        for (uint256 i = 0; i < 8; i++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript);
        }
        emit log("Final vector read OK");
        emit log_named_uint("Transcript pos after final vector", ts.transcriptPos);
        emit log_named_bytes32("State before final challenge_indices", ts.sponge.state);
        emit log_named_uint("Counter before final challenge_indices", ts.sponge.squeezeCounter);

        // Open round commitment (256 leaves, 42 samples)
        uint256[] memory finalRawIndices = _challengeIndicesRaw(ts, 256, 42);
        emit log_named_uint("BEFORE SORT finalRawIndices[0]", finalRawIndices[0]);
        emit log_named_uint("BEFORE SORT finalRawIndices[1]", finalRawIndices[1]);
        emit log_named_uint("BEFORE SORT finalRawIndices[2]", finalRawIndices[2]);
        SpongefishWhir.proverHint(ts, hints, 8); // Vec length prefix
        bytes32[] memory finalRawHashes = new bytes32[](42);
        for (uint256 i = 0; i < 42; i++) {
            bytes memory row = SpongefishWhir.proverHint(ts, hints, 128); // 16 * 8
            finalRawHashes[i] = keccak256(row);
        }
        (uint256[] memory fsi, bytes32[] memory fsh) = _sortAndDedupWithHashes(finalRawIndices, finalRawHashes);

        // Print first few raw indices
        for (uint256 i = 0; i < 5 && i < finalRawIndices.length; i++) {
            emit log_named_uint(string(abi.encodePacked("finalIdx_", vm.toString(i))), finalRawIndices[i]);
        }
        emit log_named_uint("Final unique indices", fsi.length);
        emit log_named_bytes32("Round root for final Merkle", roundRoot);
        emit log_named_uint("hintPos before final Merkle", ts.hintPos);

        ts.hintPos = SpongefishMerkle.verify(roundRoot, 8, fsi, fsh, hints, ts.hintPos);
        emit log("Final Merkle verification OK");

        // ===== Phase 6: Final sumcheck (3 rounds) =====
        for (uint256 r = 0; r < 3; r++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript);
            SpongefishWhir.proverMessageField64x3(ts, transcript);
            SpongefishWhir.verifierMessageField64x3(ts);
        }
        emit log("Final sumcheck OK");
        emit log_named_uint("Total transcript consumed", ts.transcriptPos);
        emit log_named_uint("Total hints consumed", ts.hintPos);

        assertTrue(ts.transcriptPos == transcript.length, "transcript not fully consumed");
    }
}
