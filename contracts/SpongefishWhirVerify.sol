// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SpongefishWhir} from "./SpongefishWhir.sol";
import {SpongefishMerkle} from "./SpongefishMerkle.sol";
import {GoldilocksExt3} from "./GoldilocksExt3.sol";
import {WhirLinearAlgebra} from "./WhirLinearAlgebra.sol";
import {Keccak256Chain} from "./Keccak256Chain.sol";

/// @title SpongefishWhirVerify
/// @notice Full WHIR verification matching WizardOfMenlo/whir verifier.rs
library SpongefishWhirVerify {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;
    using Keccak256Chain for Keccak256Chain.Sponge;
    using SpongefishWhir for SpongefishWhir.TranscriptState;

    uint64 constant GL_P = 0xFFFFFFFF00000001;

    struct WhirParams {
        uint256 numVariables;
        uint256 foldingFactor;
        uint256 numVectors;
        uint256 outDomainSamples;
        uint256 inDomainSamples;
        uint256 initialSumcheckRounds;
        uint256 numRounds;
        uint256 finalSumcheckRounds;
        uint256 finalSize;
        uint256 roundInDomainSamples;
        uint256 roundOutDomainSamples;
        uint256 roundSumcheckRounds;
        uint256 initialCodewordLength;
        uint256 initialMerkleDepth;
        uint64 initialDomainGenerator;
        uint256 roundCodewordLength;
        uint256 roundMerkleDepth;
        uint64 roundDomainGenerator;
        uint256 finalCodewordLength;
        uint64 finalDomainGenerator;
        uint256 initialInterleavingDepth;
        uint256 roundInterleavingDepth;
        // FinalClaim params
        uint256 initialNumVariables;
        uint256 roundInitialNumVariables;
        uint256 initialCosetSize;
        uint256 initialNumCosets;
        uint256 roundCosetSize;
        uint256 roundNumCosets;
    }

    /// @notice One entry in round_constraints: RLC coefficients + evaluation points for UnivariateEvaluation
    struct RoundConstraintEntry {
        GoldilocksExt3.Ext3[] rlcCoeffs;
        GoldilocksExt3.Ext3[] univariatePoints;  // OOD points ++ in-domain points (as base-field-embedded Ext3)
        uint256 numVariables;                      // for eval_point slice
    }

    struct VerifyState {
        GoldilocksExt3.Ext3 theSum;
        GoldilocksExt3.Ext3[] allFoldingRandomness;
        uint256 foldIdx;
        uint256 totalFoldingLen;
        bytes32 prevRoot;
        // Initial phase
        GoldilocksExt3.Ext3[] initialConstraintRlc;
        uint256 numLinearForms;
        // Round constraints for FinalClaim subtraction
        // Entry 0: initial OOD constraints
        // Entry 1+: intermediate round constraints (OOD + in-domain)
        RoundConstraintEntry[] roundConstraints;
    }

    // =====================================================================
    // Main entry point
    // =====================================================================
    function verifyWhirProof(
        bytes memory protocolId,
        bytes memory sessionId,
        bytes memory instance,
        bytes memory transcript,
        bytes memory hints,
        GoldilocksExt3.Ext3[] memory evaluations,
        WhirParams memory params
    ) internal pure returns (bool) {
        SpongefishWhir.TranscriptState memory ts = SpongefishWhir.initTranscript(protocolId, sessionId, instance);

        VerifyState memory vs;
        vs.totalFoldingLen = params.initialSumcheckRounds
            + params.numRounds * params.roundSumcheckRounds
            + params.finalSumcheckRounds;
        vs.allFoldingRandomness = new GoldilocksExt3.Ext3[](vs.totalFoldingLen);
        vs.roundConstraints = new RoundConstraintEntry[](1 + params.numRounds);

        // Phase 1: Initial commitment + OOD + RLC + compute "the sum"
        _phaseInitial(ts, transcript, evaluations, params, vs);

        // Phase 2: Initial sumcheck
        _phaseSumcheck(ts, transcript, params.initialSumcheckRounds, vs);

        // Phase 3: Intermediate rounds
        _phaseIntermediateRounds(ts, transcript, hints, params, vs);

        // Phase 4: Final vector + final Merkle open
        GoldilocksExt3.Ext3[] memory finalVector = _phaseFinalVectorAndMerkle(ts, transcript, hints, params, vs);

        // Phase 5: Final sumcheck
        _phaseSumcheck(ts, transcript, params.finalSumcheckRounds, vs);

        // Phase 6: FinalClaim verification
        _phaseFinalClaim(params, vs, finalVector, evaluations);

        require(ts.transcriptPos == transcript.length, "transcript not fully consumed");
        return true;
    }

    // =====================================================================
    // Phase 1: Initial commitment + OOD + RLC + sum
    // =====================================================================
    function _phaseInitial(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory transcript,
        GoldilocksExt3.Ext3[] memory evaluations,
        WhirParams memory params,
        VerifyState memory vs
    ) private pure {
        vs.prevRoot = SpongefishWhir.proverMessageHash(ts, transcript);

        // OOD challenge points
        GoldilocksExt3.Ext3[] memory oodPoints = new GoldilocksExt3.Ext3[](params.outDomainSamples);
        for (uint256 i = 0; i < params.outDomainSamples; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.verifierMessageField64x3(ts);
            oodPoints[i] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        // OOD answer matrix
        GoldilocksExt3.Ext3[] memory oodMatrix = new GoldilocksExt3.Ext3[](
            params.outDomainSamples * params.numVectors
        );
        for (uint256 i = 0; i < oodMatrix.length; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.proverMessageField64x3(ts, transcript);
            oodMatrix[i] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        // RLC
        GoldilocksExt3.Ext3[] memory vectorRlc = SpongefishWhir.geometricChallenge(ts, params.numVectors);
        vs.numLinearForms = evaluations.length / params.numVectors;
        uint256 totalConstraints = params.outDomainSamples + vs.numLinearForms;
        vs.initialConstraintRlc = SpongefishWhir.geometricChallenge(ts, totalConstraints);

        // Store initial OOD round_constraints entry (entry 0)
        GoldilocksExt3.Ext3[] memory oodRlcCoeffs = new GoldilocksExt3.Ext3[](params.outDomainSamples);
        for (uint256 i = 0; i < params.outDomainSamples; i++) {
            oodRlcCoeffs[i] = vs.initialConstraintRlc[vs.numLinearForms + i];
        }
        vs.roundConstraints[0] = RoundConstraintEntry({
            rlcCoeffs: oodRlcCoeffs,
            univariatePoints: oodPoints,
            numVariables: params.initialNumVariables
        });

        // Compute "the sum"
        vs.theSum = GoldilocksExt3.zero();
        for (uint256 i = 0; i < vs.numLinearForms; i++) {
            GoldilocksExt3.Ext3 memory dotVal = GoldilocksExt3.zero();
            for (uint256 j = 0; j < params.numVectors; j++) {
                dotVal = dotVal.add(evaluations[i * params.numVectors + j].mul(vectorRlc[j]));
            }
            vs.theSum = vs.theSum.add(dotVal.mul(vs.initialConstraintRlc[i]));
        }
        for (uint256 i = 0; i < params.outDomainSamples; i++) {
            GoldilocksExt3.Ext3 memory dotVal = GoldilocksExt3.zero();
            for (uint256 j = 0; j < params.numVectors; j++) {
                dotVal = dotVal.add(oodMatrix[i * params.numVectors + j].mul(vectorRlc[j]));
            }
            vs.theSum = vs.theSum.add(dotVal.mul(vs.initialConstraintRlc[vs.numLinearForms + i]));
        }
    }

    // =====================================================================
    // Phase 2/5: Sumcheck
    // =====================================================================
    function _phaseSumcheck(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory transcript,
        uint256 numRounds,
        VerifyState memory vs
    ) private pure {
        for (uint256 i = 0; i < numRounds; i++) {
            (uint64 c0a, uint64 c0b, uint64 c0c) = SpongefishWhir.proverMessageField64x3(ts, transcript);
            (uint64 c2a, uint64 c2b, uint64 c2c) = SpongefishWhir.proverMessageField64x3(ts, transcript);
            GoldilocksExt3.Ext3 memory c0 = GoldilocksExt3.Ext3(c0a, c0b, c0c);
            GoldilocksExt3.Ext3 memory c2 = GoldilocksExt3.Ext3(c2a, c2b, c2c);
            GoldilocksExt3.Ext3 memory c1 = vs.theSum.sub(c0.double_()).sub(c2);

            (uint64 ra, uint64 rb, uint64 rc) = SpongefishWhir.verifierMessageField64x3(ts);
            GoldilocksExt3.Ext3 memory r = GoldilocksExt3.Ext3(ra, rb, rc);
            vs.allFoldingRandomness[vs.foldIdx++] = r;

            vs.theSum = c2.mul(r).add(c1).mul(r).add(c0);
        }
    }

    // =====================================================================
    // Phase 3: Intermediate rounds
    // =====================================================================
    function _phaseIntermediateRounds(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory transcript,
        bytes memory hints,
        WhirParams memory params,
        VerifyState memory vs
    ) private pure {
        for (uint256 round = 0; round < params.numRounds; round++) {
            _doIntermediateRound(ts, transcript, hints, params, vs, round);
        }
    }

    function _doIntermediateRound(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory transcript,
        bytes memory hints,
        WhirParams memory params,
        VerifyState memory vs,
        uint256 round
    ) private pure {
        // Receive new commitment
        bytes32 roundRoot = SpongefishWhir.proverMessageHash(ts, transcript);

        // OOD for this round
        GoldilocksExt3.Ext3[] memory roundOodPoints = new GoldilocksExt3.Ext3[](params.roundOutDomainSamples);
        for (uint256 i = 0; i < params.roundOutDomainSamples; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.verifierMessageField64x3(ts);
            roundOodPoints[i] = GoldilocksExt3.Ext3(c0, c1, c2);
            SpongefishWhir.proverMessageField64x3(ts, transcript); // read OOD value (absorbed, not stored)
        }

        // Open previous commitment with Merkle verification
        uint256 openCL;
        uint256 openMD;
        uint256 openRowBytes;
        uint64 openDomainGen;
        uint256 openNumCosets;
        uint256 openCosetSize;
        if (round == 0) {
            openCL = params.initialCodewordLength;
            openMD = params.initialMerkleDepth;
            openRowBytes = params.initialInterleavingDepth * params.numVectors * 8;
            openDomainGen = params.initialDomainGenerator;
            openNumCosets = params.initialNumCosets;
            openCosetSize = params.initialCosetSize;
        } else {
            openCL = params.roundCodewordLength;
            openMD = params.roundMerkleDepth;
            openRowBytes = params.roundInterleavingDepth * 24;
            openDomainGen = params.roundDomainGenerator;
            openNumCosets = params.roundNumCosets;
            openCosetSize = params.roundCosetSize;
        }

        uint256 openInDomainSamples = (round == 0)
            ? params.inDomainSamples
            : params.roundInDomainSamples;

        uint256[] memory rawIndices = _challengeIndicesUnsorted(ts, openCL, openInDomainSamples);

        // Read rows + Merkle verify
        SpongefishWhir.proverHint(ts, hints, 8);
        bytes32[] memory rawLeafHashes = new bytes32[](rawIndices.length);
        for (uint256 i = 0; i < rawIndices.length; i++) {
            bytes memory rowData = SpongefishWhir.proverHint(ts, hints, openRowBytes);
            rawLeafHashes[i] = keccak256(rowData);
        }

        (uint256[] memory sortedIndices, bytes32[] memory sortedHashes) =
            _sortAndDedupWithHashes(rawIndices, rawLeafHashes);

        ts.hintPos = SpongefishMerkle.verify(
            vs.prevRoot, openMD, sortedIndices, sortedHashes, hints, ts.hintPos
        );

        // Constraint RLC for this round
        uint256 constraintCount = params.roundOutDomainSamples + rawIndices.length;
        GoldilocksExt3.Ext3[] memory roundRlc = SpongefishWhir.geometricChallenge(ts, constraintCount);

        // Build evaluation points: OOD points ++ in-domain points
        // In-domain points are domain elements: g^(transpose_permute(index))
        GoldilocksExt3.Ext3[] memory allEvalPoints = new GoldilocksExt3.Ext3[](constraintCount);
        for (uint256 i = 0; i < params.roundOutDomainSamples; i++) {
            allEvalPoints[i] = roundOodPoints[i];
        }
        for (uint256 i = 0; i < rawIndices.length; i++) {
            // transpose_permute(index, num_cosets, coset_size)
            uint256 idx = rawIndices[i];
            uint256 row = idx / openCosetSize;
            uint256 col = idx % openCosetSize;
            uint256 permuted = row + col * openNumCosets;
            // g^permuted mod GL_P
            uint64 domainPt = _glPow(openDomainGen, permuted);
            allEvalPoints[params.roundOutDomainSamples + i] = GoldilocksExt3.fromBase(domainPt);
        }

        // Store round constraint (entry 1 + round)
        // In the Rust subtraction loop: round_constraints[1+round] uses
        // round_configs[round].initial_num_variables() for ALL intermediate rounds
        uint256 numVars = params.roundInitialNumVariables;
        vs.roundConstraints[1 + round] = RoundConstraintEntry({
            rlcCoeffs: roundRlc,
            univariatePoints: allEvalPoints,
            numVariables: numVars
        });

        // Sumcheck
        _phaseSumcheck(ts, transcript, params.roundSumcheckRounds, vs);

        vs.prevRoot = roundRoot;
    }

    // =====================================================================
    // Phase 4: Final vector + Merkle
    // =====================================================================
    function _phaseFinalVectorAndMerkle(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory transcript,
        bytes memory hints,
        WhirParams memory params,
        VerifyState memory vs
    ) private pure returns (GoldilocksExt3.Ext3[] memory finalVector) {
        finalVector = new GoldilocksExt3.Ext3[](params.finalSize);
        for (uint256 i = 0; i < params.finalSize; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.proverMessageField64x3(ts, transcript);
            finalVector[i] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        uint256 finalCL;
        uint256 finalMD;
        uint256 finalRowBytes;
        if (params.numRounds == 0) {
            finalCL = params.initialCodewordLength;
            finalMD = params.initialMerkleDepth;
            finalRowBytes = params.initialInterleavingDepth * params.numVectors * 8;
        } else {
            finalCL = params.roundCodewordLength;
            finalMD = params.roundMerkleDepth;
            finalRowBytes = params.roundInterleavingDepth * 24;
        }

        uint256 finalInDomainSamples = (params.numRounds == 0)
            ? params.inDomainSamples
            : params.roundInDomainSamples;
        uint256[] memory rawFinalIndices = _challengeIndicesUnsorted(ts, finalCL, finalInDomainSamples);

        SpongefishWhir.proverHint(ts, hints, 8);
        bytes32[] memory rawFinalHashes = new bytes32[](rawFinalIndices.length);
        for (uint256 i = 0; i < rawFinalIndices.length; i++) {
            bytes memory rowData = SpongefishWhir.proverHint(ts, hints, finalRowBytes);
            rawFinalHashes[i] = keccak256(rowData);
        }

        (uint256[] memory sortedFinalIndices, bytes32[] memory sortedFinalHashes) =
            _sortAndDedupWithHashes(rawFinalIndices, rawFinalHashes);

        ts.hintPos = SpongefishMerkle.verify(
            vs.prevRoot, finalMD, sortedFinalIndices, sortedFinalHashes, hints, ts.hintPos
        );
    }

    // =====================================================================
    // Phase 6: FinalClaim verification
    // =====================================================================
    function _phaseFinalClaim(
        WhirParams memory params,
        VerifyState memory vs,
        GoldilocksExt3.Ext3[] memory finalVector,
        GoldilocksExt3.Ext3[] memory evaluations
    ) private pure {
        // poly_eval = dot(eq_weights(final_sumcheck_r), finalVector)
        GoldilocksExt3.Ext3[] memory finalSumcheckR = new GoldilocksExt3.Ext3[](params.finalSumcheckRounds);
        for (uint256 i = 0; i < params.finalSumcheckRounds; i++) {
            finalSumcheckR[i] = vs.allFoldingRandomness[vs.foldIdx - params.finalSumcheckRounds + i];
        }
        GoldilocksExt3.Ext3[] memory eqW = WhirLinearAlgebra.eqWeights(finalSumcheckR);
        GoldilocksExt3.Ext3 memory polyEval = WhirLinearAlgebra.dotProduct(eqW, finalVector);
        require(!GoldilocksExt3.isZero(polyEval), "polyEval is zero");

        // linear_form_rlc = theSum / polyEval
        GoldilocksExt3.Ext3 memory linearFormRlc = vs.theSum.mul(GoldilocksExt3.inv(polyEval));

        // Subtract ALL round constraints (matching Rust's round_constraints loop)
        for (uint256 rc = 0; rc < vs.roundConstraints.length; rc++) {
            RoundConstraintEntry memory entry = vs.roundConstraints[rc];
            if (entry.rlcCoeffs.length == 0) continue;

            uint256 nv = entry.numVariables;
            uint256 start = vs.totalFoldingLen > nv ? vs.totalFoldingLen - nv : 0;
            GoldilocksExt3.Ext3[] memory evalSlice = new GoldilocksExt3.Ext3[](vs.totalFoldingLen - start);
            for (uint256 i = 0; i < evalSlice.length; i++) {
                evalSlice[i] = vs.allFoldingRandomness[start + i];
            }

            for (uint256 i = 0; i < entry.rlcCoeffs.length; i++) {
                GoldilocksExt3.Ext3 memory mleVal = WhirLinearAlgebra.mleEvaluateUnivariate(
                    entry.univariatePoints[i], evalSlice
                );
                GoldilocksExt3.Ext3 memory term = mleVal.mul(entry.rlcCoeffs[i]);
                GoldilocksExt3.Ext3 memory result = linearFormRlc.sub(term);
                linearFormRlc.c0 = result.c0;
                linearFormRlc.c1 = result.c1;
                linearFormRlc.c2 = result.c2;
            }
        }

        // Verify external linear forms
        // linear_form = MultilinearExtension at canonical point (1, 2, ..., numVariables)
        // FinalClaim.verify: sum(rlc_coeff[i] * eq(canonical, evaluation_point)) == linear_form_rlc
        GoldilocksExt3.Ext3[] memory canonicalPoint = new GoldilocksExt3.Ext3[](params.numVariables);
        for (uint256 i = 0; i < params.numVariables; i++) {
            canonicalPoint[i] = GoldilocksExt3.fromBase(uint64(i + 1));
        }

        GoldilocksExt3.Ext3 memory expectedRlc = GoldilocksExt3.zero();
        for (uint256 i = 0; i < vs.numLinearForms; i++) {
            GoldilocksExt3.Ext3 memory eqVal = WhirLinearAlgebra.mleEvaluateEq(
                canonicalPoint, vs.allFoldingRandomness
            );
            GoldilocksExt3.Ext3 memory result = expectedRlc.add(eqVal.mul(vs.initialConstraintRlc[i]));
            expectedRlc.c0 = result.c0;
            expectedRlc.c1 = result.c1;
            expectedRlc.c2 = result.c2;
        }

        require(GoldilocksExt3.eq(linearFormRlc, expectedRlc), "FinalClaim: linear form mismatch");
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    function _challengeIndicesUnsorted(
        SpongefishWhir.TranscriptState memory ts,
        uint256 numLeaves,
        uint256 count
    ) private pure returns (uint256[] memory indices) {
        if (count == 0) return new uint256[](0);
        if (numLeaves == 1) {
            indices = new uint256[](count);
            return indices;
        }

        uint256 sizeBytes = _ceilDiv(_log2(numLeaves), 8);
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
    ) private pure returns (uint256[] memory sortedIndices, bytes32[] memory sortedHashes) {
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

    /// @dev Goldilocks modular exponentiation: base^exp mod GL_P
    function _glPow(uint64 base, uint256 exp) private pure returns (uint64) {
        uint256 result = 1;
        uint256 b = uint256(base);
        uint256 p = uint256(GL_P);
        while (exp > 0) {
            if (exp & 1 == 1) result = mulmod(result, b, p);
            exp >>= 1;
            b = mulmod(b, b, p);
        }
        return uint64(result);
    }

    function _ceilDiv(uint256 a, uint256 b) private pure returns (uint256) {
        return (a + b - 1) / b;
    }

    function _log2(uint256 x) private pure returns (uint256 n) {
        while (x > 1) { x >>= 1; n++; }
    }
}
