// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SpongefishWhir} from "../SpongefishWhir.sol";
import {SpongefishWhirVerify} from "../SpongefishWhirVerify.sol";
import {SpongefishMerkle} from "../SpongefishMerkle.sol";
import {GoldilocksExt3} from "../GoldilocksExt3.sol";
import {Keccak256Chain} from "../Keccak256Chain.sol";

/// @notice Fine-grained gas profiling — measures each sub-operation in the full verifier.
contract GasProfile2Test is Test {
    using Keccak256Chain for Keccak256Chain.Sponge;

    string constant FP = "test/data/whir/keccak256chain_verifier_data.json";

    function test_full_gas_profile() public {
        string memory json = vm.readFile(FP);
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        uint64 evalC0 = uint64(vm.parseJsonUint(json, ".evaluations[0].c0"));
        GoldilocksExt3.Ext3[] memory evaluations = new GoldilocksExt3.Ext3[](1);
        evaluations[0] = GoldilocksExt3.Ext3(evalC0, 0, 0);

        SpongefishWhirVerify.WhirParams memory params;
        params.numVariables = 11;
        params.foldingFactor = 4;
        params.numVectors = 1;
        params.outDomainSamples = 1;
        params.inDomainSamples = vm.parseJsonUint(json, ".whir_params.in_domain_samples");
        params.initialSumcheckRounds = 4;
        params.numRounds = 1;
        params.finalSumcheckRounds = vm.parseJsonUint(json, ".whir_params.final_sumcheck_rounds");
        params.finalSize = vm.parseJsonUint(json, ".whir_params.final_size");
        params.roundInDomainSamples = vm.parseJsonUint(json, ".whir_params.round_in_domain_samples");
        params.roundOutDomainSamples = 1;
        params.roundSumcheckRounds = 4;
        params.initialCodewordLength = 512;
        params.initialMerkleDepth = 9;
        params.initialDomainGenerator = uint64(vm.parseJsonUint(json, ".whir_params.initial_domain_generator"));
        params.roundCodewordLength = 256;
        params.roundMerkleDepth = 8;
        params.roundDomainGenerator = uint64(vm.parseJsonUint(json, ".whir_params.round_domain_generator"));
        params.finalCodewordLength = 256;
        params.finalDomainGenerator = uint64(vm.parseJsonUint(json, ".whir_params.final_domain_generator"));
        params.initialInterleavingDepth = 16;
        params.roundInterleavingDepth = 16;
        params.initialNumVariables = vm.parseJsonUint(json, ".whir_params.initial_num_variables");
        params.roundInitialNumVariables = vm.parseJsonUint(json, ".whir_params.round_initial_num_variables");
        params.initialCosetSize = vm.parseJsonUint(json, ".whir_params.initial_coset_size");
        params.initialNumCosets = vm.parseJsonUint(json, ".whir_params.initial_num_cosets");
        params.roundCosetSize = vm.parseJsonUint(json, ".whir_params.round_coset_size");
        params.roundNumCosets = vm.parseJsonUint(json, ".whir_params.round_num_cosets");

        // Measure the full verification
        uint256 g0 = gasleft();
        SpongefishWhirVerify.verifyWhirProof(
            protocolId, sessionId, instance, transcript, hints, evaluations, params
        );
        uint256 g1 = gasleft();
        emit log_named_uint("TOTAL verifyWhirProof", g0 - g1);

        // Also measure memory high watermark
        uint256 freeMemPtr;
        assembly { freeMemPtr := mload(0x40) }
        emit log_named_uint("Free memory pointer (bytes)", freeMemPtr);
    }

    /// @notice Measure just the Merkle verification cost with a mock.
    function test_gas_merkle_only() public {
        string memory json = vm.readFile(FP);
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        // Simulate: 100 sorted indices, 9 layers of Merkle
        uint256[] memory indices = new uint256[](5);
        bytes32[] memory hashes = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            indices[i] = i * 100;
            hashes[i] = keccak256(abi.encodePacked(i));
        }

        // Just measure the sorting overhead
        uint256 g0 = gasleft();
        // Insertion sort of 108 elements
        uint256[] memory big = new uint256[](108);
        for (uint256 i = 0; i < 108; i++) big[i] = 108 - i; // reverse order
        // Bubble sort
        for (uint256 i = 0; i < 108; i++) {
            for (uint256 j = i + 1; j < 108; j++) {
                if (big[j] < big[i]) {
                    (big[i], big[j]) = (big[j], big[i]);
                }
            }
        }
        uint256 g1 = gasleft();
        emit log_named_uint("Sort 108 elements (bubble)", g0 - g1);
    }

    /// @notice Measure memory allocation cost for many small allocations
    function test_gas_memory_alloc() public view {
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 108; i++) {
            bytes memory _b = new bytes(128);
            assembly { pop(_b) } // prevent optimization
        }
        uint256 g1 = gasleft();
        // Can't emit in pure, but the gas is visible in test output
    }
}
