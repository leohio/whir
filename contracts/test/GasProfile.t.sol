// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SpongefishWhir} from "../SpongefishWhir.sol";
import {SpongefishWhirVerify} from "../SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../GoldilocksExt3.sol";
import {Keccak256Chain} from "../Keccak256Chain.sol";

contract GasProfileTest is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    string constant FIXTURE_PATH = "test/data/whir/keccak256chain_verifier_data.json";

    function test_gas_squeezeByte_216() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();
        s.absorb(bytes("test"));
        for (uint256 i = 0; i < 216; i++) {
            s.squeezeByte();
        }
    }

    function test_gas_squeezeByte_42() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();
        s.absorb(bytes("test"));
        for (uint256 i = 0; i < 42; i++) {
            s.squeezeByte();
        }
    }

    function test_gas_squeeze_120() public pure {
        Keccak256Chain.Sponge memory s = Keccak256Chain.init();
        s.absorb(bytes("test"));
        s.squeeze(120);
    }

    function test_gas_ext3_mul_100() public pure {
        GoldilocksExt3.Ext3 memory a = GoldilocksExt3.Ext3(123456789, 987654321, 111111111);
        GoldilocksExt3.Ext3 memory b = GoldilocksExt3.Ext3(999999999, 888888888, 777777777);
        for (uint256 i = 0; i < 100; i++) {
            a = GoldilocksExt3.mul(a, b);
        }
    }

    function test_gas_ext3_inv() public pure {
        GoldilocksExt3.Ext3 memory a = GoldilocksExt3.Ext3(123456789, 987654321, 111111111);
        GoldilocksExt3.inv(a);
    }

    function test_gas_profile_phases() public {
        string memory json = vm.readFile(FIXTURE_PATH);
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        uint64 evalC0 = uint64(vm.parseJsonUint(json, ".evaluations[0].c0"));
        uint64 evalC1 = uint64(vm.parseJsonUint(json, ".evaluations[0].c1"));
        uint64 evalC2 = uint64(vm.parseJsonUint(json, ".evaluations[0].c2"));
        GoldilocksExt3.Ext3[] memory evaluations = new GoldilocksExt3.Ext3[](1);
        evaluations[0] = GoldilocksExt3.Ext3(evalC0, evalC1, evalC2);

        SpongefishWhir.TranscriptState memory ts = SpongefishWhir.initTranscript(protocolId, sessionId, instance);

        // === Phase 1: Initial commitment + OOD + RLC ===
        uint256 g0 = gasleft();
        bytes32 root = SpongefishWhir.proverMessageHash(ts, transcript);
        // OOD
        for (uint256 i = 0; i < 1; i++) {
            SpongefishWhir.verifierMessageField64x3(ts);
        }
        for (uint256 i = 0; i < 1; i++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript);
        }
        SpongefishWhir.geometricChallenge(ts, 1);
        SpongefishWhir.geometricChallenge(ts, 2);
        uint256 g1 = gasleft();
        emit log_named_uint("Phase 1 (init+OOD+RLC)", g0 - g1);

        // === Phase 2: Initial sumcheck (4 rounds) ===
        g0 = gasleft();
        for (uint256 i = 0; i < 4; i++) {
            SpongefishWhir.proverMessageField64x3(ts, transcript);
            SpongefishWhir.proverMessageField64x3(ts, transcript);
            SpongefishWhir.verifierMessageField64x3(ts);
        }
        g1 = gasleft();
        emit log_named_uint("Phase 2 (initial sumcheck 4 rounds)", g0 - g1);

        // === Phase 3: Intermediate round (receive commitment) ===
        g0 = gasleft();
        SpongefishWhir.proverMessageHash(ts, transcript);
        SpongefishWhir.verifierMessageField64x3(ts);
        SpongefishWhir.proverMessageField64x3(ts, transcript);
        g1 = gasleft();
        emit log_named_uint("Phase 3a (receive commitment)", g0 - g1);

        // === Phase 3b: Challenge indices (512, 108) ===
        g0 = gasleft();
        uint256 sizeBytes = 2;
        uint256 totalBytes = 108 * sizeBytes;
        bytes memory entropy = new bytes(totalBytes);
        for (uint256 i = 0; i < totalBytes; i++) {
            entropy[i] = bytes1(ts.sponge.squeezeByte());
        }
        g1 = gasleft();
        emit log_named_uint("Phase 3b (challenge_indices 216 bytes)", g0 - g1);

        // === Phase 3c: Read rows + hash ===
        g0 = gasleft();
        SpongefishWhir.proverHint(ts, hints, 8);
        for (uint256 i = 0; i < 108; i++) {
            bytes memory rowData = SpongefishWhir.proverHint(ts, hints, 128);
            bytes32 h;
            assembly { h := keccak256(add(rowData, 0x20), 128) }
        }
        g1 = gasleft();
        emit log_named_uint("Phase 3c (read 108 rows + hash)", g0 - g1);

        // === Phase 3d: Merkle verify ===
        // (need sorted indices, skip for gas measurement)
        emit log_named_uint("hintPos after rows", ts.hintPos);
        emit log_named_uint("hints.length", hints.length);
    }
}
