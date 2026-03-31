// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SpongefishWhirVerify} from "../SpongefishWhirVerify.sol";
import {GoldilocksExt3} from "../GoldilocksExt3.sol";

/// @title WhirVerifyTest
/// @notice End-to-end WHIR verification test using Keccak256Chain transcript fixture.
contract WhirVerifyTest is Test {
    string constant FIXTURE_PATH = "test/data/whir/keccak256chain_verifier_data.json";

    struct FixtureEval {
        uint64 c0;
        uint64 c1;
        uint64 c2;
    }

    /// @notice Load fixture and run full WHIR verification.
    function test_whir_verify_keccak256chain() public view {
        string memory json = vm.readFile(FIXTURE_PATH);

        // Load raw bytes
        bytes memory protocolId = vm.parseJsonBytes(json, ".protocol_id");
        bytes memory sessionId = vm.parseJsonBytes(json, ".session_id");
        bytes memory instance = vm.parseJsonBytes(json, ".instance");
        bytes memory transcript = vm.parseJsonBytes(json, ".transcript");
        bytes memory hints = vm.parseJsonBytes(json, ".hints");

        // Load evaluations
        uint64 evalC0 = uint64(vm.parseJsonUint(json, ".evaluations[0].c0"));
        uint64 evalC1 = uint64(vm.parseJsonUint(json, ".evaluations[0].c1"));
        uint64 evalC2 = uint64(vm.parseJsonUint(json, ".evaluations[0].c2"));
        GoldilocksExt3.Ext3[] memory evaluations = new GoldilocksExt3.Ext3[](1);
        evaluations[0] = GoldilocksExt3.Ext3(evalC0, evalC1, evalC2);

        // Load WHIR params
        SpongefishWhirVerify.WhirParams memory params = _loadParams(json);

        // Run verification
        bool ok = SpongefishWhirVerify.verifyWhirProof(
            protocolId,
            sessionId,
            instance,
            transcript,
            hints,
            evaluations,
            params
        );
        assertTrue(ok, "WHIR verification failed");
    }

    function _loadParams(string memory json) internal pure returns (SpongefishWhirVerify.WhirParams memory p) {
        p.numVariables = vm.parseJsonUint(json, ".whir_params.num_variables");
        p.foldingFactor = vm.parseJsonUint(json, ".whir_params.folding_factor");
        p.numVectors = vm.parseJsonUint(json, ".whir_params.num_vectors");
        p.outDomainSamples = vm.parseJsonUint(json, ".whir_params.out_domain_samples");
        p.inDomainSamples = vm.parseJsonUint(json, ".whir_params.in_domain_samples");
        p.initialSumcheckRounds = vm.parseJsonUint(json, ".whir_params.initial_sumcheck_rounds");
        p.numRounds = vm.parseJsonUint(json, ".whir_params.num_rounds");
        p.finalSumcheckRounds = vm.parseJsonUint(json, ".whir_params.final_sumcheck_rounds");
        p.finalSize = vm.parseJsonUint(json, ".whir_params.final_size");
        p.roundInDomainSamples = vm.parseJsonUint(json, ".whir_params.round_in_domain_samples");
        p.roundOutDomainSamples = vm.parseJsonUint(json, ".whir_params.round_out_domain_samples");
        p.roundSumcheckRounds = vm.parseJsonUint(json, ".whir_params.round_sumcheck_rounds");
        p.initialCodewordLength = vm.parseJsonUint(json, ".whir_params.initial_codeword_length");
        p.initialMerkleDepth = vm.parseJsonUint(json, ".whir_params.initial_merkle_depth");
        p.initialDomainGenerator = uint64(vm.parseJsonUint(json, ".whir_params.initial_domain_generator"));
        p.roundCodewordLength = vm.parseJsonUint(json, ".whir_params.round_codeword_length");
        p.roundMerkleDepth = vm.parseJsonUint(json, ".whir_params.round_merkle_depth");
        p.roundDomainGenerator = uint64(vm.parseJsonUint(json, ".whir_params.round_domain_generator"));
        p.finalCodewordLength = vm.parseJsonUint(json, ".whir_params.final_codeword_length");
        p.finalDomainGenerator = uint64(vm.parseJsonUint(json, ".whir_params.final_domain_generator"));
        p.initialInterleavingDepth = vm.parseJsonUint(json, ".whir_params.initial_interleaving_depth");
        p.roundInterleavingDepth = vm.parseJsonUint(json, ".whir_params.round_interleaving_depth");
    }
}
