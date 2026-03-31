// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SpongefishWhir} from "./SpongefishWhir.sol";
import {SpongefishMerkle} from "./SpongefishMerkle.sol";
import {GoldilocksExt3} from "./GoldilocksExt3.sol";
import {WhirLinearAlgebra} from "./WhirLinearAlgebra.sol";
import {Keccak256Chain} from "./Keccak256Chain.sol";

/// @title SpongefishWhirVerify
/// @notice Full WHIR verification matching WizardOfMenlo/whir verifier.rs
///
///   Implements the complete WHIR polynomial commitment verification:
///   1. receive_commitment (root + OOD)
///   2. OOD constraint matrix + RLC coefficients
///   3. Sumcheck (initial, intermediate, final)
///   4. Merkle verification at each round
///   5. FinalClaim verification (theSum == polyEval * linear_form_rlc)
library SpongefishWhirVerify {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;
    using Keccak256Chain for Keccak256Chain.Sponge;
    using SpongefishWhir for SpongefishWhir.TranscriptState;

    uint64 constant GL_P = 0xFFFFFFFF00000001;

    /// @notice WHIR proof configuration parameters.
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
        // Merkle and domain parameters
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
    }

    /// @notice Intermediate state passed between verification phases.
    struct VerifyState {
        GoldilocksExt3.Ext3 theSum;
        GoldilocksExt3.Ext3[] allFoldingRandomness;
        uint256 foldIdx;
        uint256 totalFoldingLen;
        bytes32 prevRoot;
        // Initial OOD info (for FinalClaim)
        GoldilocksExt3.Ext3[] initialOodPoints;
        uint64[] initialOodRlcCoeffs;
        uint64[] initialConstraintRlc;
        uint256 numLinearForms;
    }

    /// @notice Verify a WHIR polynomial commitment proof.
    function verifyWhirProof(
        bytes memory protocolId,
        bytes memory sessionId,
        bytes memory transcript,
        bytes memory hints,
        GoldilocksExt3.Ext3[] memory evaluations,
        WhirParams memory params
    ) internal pure returns (bool) {
        SpongefishWhir.TranscriptState memory ts = SpongefishWhir.initTranscript(protocolId, sessionId);

        VerifyState memory vs;
        vs.totalFoldingLen = params.initialSumcheckRounds
            + params.numRounds * params.roundSumcheckRounds
            + params.finalSumcheckRounds;
        vs.allFoldingRandomness = new GoldilocksExt3.Ext3[](vs.totalFoldingLen);

        // Phase 1: Initial commitment + OOD + RLC + compute "the sum"
        _phaseInitial(ts, transcript, evaluations, params, vs);

        // Phase 2: Initial sumcheck
        _phaseSumcheck(ts, transcript, params.initialSumcheckRounds, vs);

        // Phase 3: Intermediate rounds (commitment + Merkle open + sumcheck)
        _phaseIntermediateRounds(ts, transcript, hints, params, vs);

        // Phase 4: Final vector + final Merkle open
        GoldilocksExt3.Ext3[] memory finalVector = _phaseFinalVectorAndMerkle(ts, transcript, hints, params, vs);

        // Phase 5: Final sumcheck
        _phaseSumcheck(ts, transcript, params.finalSumcheckRounds, vs);

        // Phase 6: FinalClaim verification
        _phaseFinalClaim(params, vs, finalVector, evaluations);

        // All transcript bytes must be consumed
        require(ts.transcriptPos == transcript.length, "transcript not fully consumed");
        return true;
    }

    // -----------------------------------------------------------------------
    // Phase 1: Initial commitment + OOD + RLC + sum
    // -----------------------------------------------------------------------
    function _phaseInitial(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory transcript,
        GoldilocksExt3.Ext3[] memory evaluations,
        WhirParams memory params,
        VerifyState memory vs
    ) private pure {
        // Receive initial Merkle root
        vs.prevRoot = SpongefishWhir.proverMessageHash(ts, transcript);

        // Squeeze OOD challenge points
        vs.initialOodPoints = new GoldilocksExt3.Ext3[](params.outDomainSamples);
        for (uint256 i = 0; i < params.outDomainSamples; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.verifierMessageField64x3(ts);
            vs.initialOodPoints[i] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        // Read OOD answer matrix
        GoldilocksExt3.Ext3[] memory oodMatrix = new GoldilocksExt3.Ext3[](
            params.outDomainSamples * params.numVectors
        );
        for (uint256 i = 0; i < oodMatrix.length; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.proverMessageField64x3(ts, transcript);
            oodMatrix[i] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        // RLC coefficients
        uint64[] memory vectorRlc = SpongefishWhir.geometricChallenge(ts, params.numVectors);
        vs.numLinearForms = evaluations.length / params.numVectors;
        uint256 totalConstraints = params.outDomainSamples + vs.numLinearForms;
        vs.initialConstraintRlc = SpongefishWhir.geometricChallenge(ts, totalConstraints);

        // Store OOD RLC coefficients for FinalClaim
        vs.initialOodRlcCoeffs = new uint64[](params.outDomainSamples);
        for (uint256 i = 0; i < params.outDomainSamples; i++) {
            vs.initialOodRlcCoeffs[i] = vs.initialConstraintRlc[vs.numLinearForms + i];
        }

        // Compute "the sum"
        vs.theSum = GoldilocksExt3.zero();

        // Sum from linear forms
        for (uint256 i = 0; i < vs.numLinearForms; i++) {
            GoldilocksExt3.Ext3 memory dotVal = GoldilocksExt3.zero();
            for (uint256 j = 0; j < params.numVectors; j++) {
                dotVal = dotVal.add(evaluations[i * params.numVectors + j].mulScalar(vectorRlc[j]));
            }
            vs.theSum = vs.theSum.add(dotVal.mulScalar(vs.initialConstraintRlc[i]));
        }

        // Sum from OOD constraints
        for (uint256 i = 0; i < params.outDomainSamples; i++) {
            GoldilocksExt3.Ext3 memory dotVal = GoldilocksExt3.zero();
            for (uint256 j = 0; j < params.numVectors; j++) {
                dotVal = dotVal.add(oodMatrix[i * params.numVectors + j].mulScalar(vectorRlc[j]));
            }
            vs.theSum = vs.theSum.add(dotVal.mulScalar(vs.initialConstraintRlc[vs.numLinearForms + i]));
        }
    }

    // -----------------------------------------------------------------------
    // Phase 2/5: Sumcheck
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // Phase 3: Intermediate rounds
    // -----------------------------------------------------------------------
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
        for (uint256 i = 0; i < params.roundOutDomainSamples; i++) {
            SpongefishWhir.verifierMessageField64x3(ts); // squeeze OOD point
            SpongefishWhir.proverMessageField64x3(ts, transcript); // read OOD value
        }

        // Open previous commitment with Merkle verification
        uint256 openCL;
        uint256 openMD;
        uint256 openNumCols;
        if (round == 0) {
            openCL = params.initialCodewordLength;
            openMD = params.initialMerkleDepth;
            openNumCols = params.initialInterleavingDepth * params.numVectors;
        } else {
            openCL = params.roundCodewordLength;
            openMD = params.roundMerkleDepth;
            openNumCols = params.roundInterleavingDepth;
        }

        // For round 0: opening the initial commitment → use initial in_domain_samples
        // For round > 0: opening a round commitment → use round in_domain_samples
        uint256 openInDomainSamples = (round == 0)
            ? params.inDomainSamples
            : params.roundInDomainSamples;

        // Generate challenge indices (UNSORTED — matching Rust's deduplicate_in_domain=false)
        uint256[] memory rawIndices = _challengeIndicesUnsorted(ts, openCL, openInDomainSamples);

        // Read ark-serialized submatrix: 8-byte LE length prefix + element data.
        // Rows are in the UNSORTED order of rawIndices.
        SpongefishWhir.proverHint(ts, hints, 8); // skip Vec<T> length prefix

        // Read rows and compute leaf hashes (in UNSORTED order matching hints)
        bytes32[] memory rawLeafHashes = new bytes32[](rawIndices.length);
        for (uint256 i = 0; i < rawIndices.length; i++) {
            bytes memory rowData = SpongefishWhir.proverHint(ts, hints, openNumCols * 8);
            rawLeafHashes[i] = keccak256(rowData);
        }

        // Sort (index, hash) pairs and dedup for Merkle verification
        (uint256[] memory sortedIndices, bytes32[] memory sortedHashes) =
            _sortAndDedupWithHashes(rawIndices, rawLeafHashes);

        // Verify Merkle proof
        ts.hintPos = SpongefishMerkle.verify(
            vs.prevRoot, openMD, sortedIndices, sortedHashes, hints, ts.hintPos
        );

        // Constraint RLC
        SpongefishWhir.geometricChallenge(ts, params.roundOutDomainSamples + sortedIndices.length);

        // Sumcheck
        _phaseSumcheck(ts, transcript, params.roundSumcheckRounds, vs);

        vs.prevRoot = roundRoot;
    }

    // -----------------------------------------------------------------------
    // Phase 4: Final vector + Merkle
    // -----------------------------------------------------------------------
    function _phaseFinalVectorAndMerkle(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory transcript,
        bytes memory hints,
        WhirParams memory params,
        VerifyState memory vs
    ) private pure returns (GoldilocksExt3.Ext3[] memory finalVector) {
        // Read final vector
        finalVector = new GoldilocksExt3.Ext3[](params.finalSize);
        for (uint256 i = 0; i < params.finalSize; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.proverMessageField64x3(ts, transcript);
            finalVector[i] = GoldilocksExt3.Ext3(c0, c1, c2);
        }

        // Final Merkle open
        uint256 finalCL;
        uint256 finalMD;
        uint256 finalNumCols;
        if (params.numRounds == 0) {
            finalCL = params.initialCodewordLength;
            finalMD = params.initialMerkleDepth;
            finalNumCols = params.initialInterleavingDepth * params.numVectors;
        } else {
            finalCL = params.roundCodewordLength;
            finalMD = params.roundMerkleDepth;
            finalNumCols = params.roundInterleavingDepth;
        }

        // For final open: use inDomainSamples if opening initial, roundInDomainSamples if opening round
        uint256 finalInDomainSamples = (params.numRounds == 0)
            ? params.inDomainSamples
            : params.roundInDomainSamples;
        uint256[] memory rawFinalIndices = _challengeIndicesUnsorted(ts, finalCL, finalInDomainSamples);

        // Skip ark Vec length prefix
        SpongefishWhir.proverHint(ts, hints, 8);
        bytes32[] memory rawFinalHashes = new bytes32[](rawFinalIndices.length);
        for (uint256 i = 0; i < rawFinalIndices.length; i++) {
            bytes memory rowData = SpongefishWhir.proverHint(ts, hints, finalNumCols * 8);
            rawFinalHashes[i] = keccak256(rowData);
        }

        (uint256[] memory sortedFinalIndices, bytes32[] memory sortedFinalHashes) =
            _sortAndDedupWithHashes(rawFinalIndices, rawFinalHashes);

        ts.hintPos = SpongefishMerkle.verify(
            vs.prevRoot, finalMD, sortedFinalIndices, sortedFinalHashes, hints, ts.hintPos
        );
    }

    // -----------------------------------------------------------------------
    // Phase 6: FinalClaim verification
    // -----------------------------------------------------------------------
    function _phaseFinalClaim(
        WhirParams memory params,
        VerifyState memory vs,
        GoldilocksExt3.Ext3[] memory finalVector,
        GoldilocksExt3.Ext3[] memory evaluations
    ) private pure {
        // Compute poly_eval = dot(eq_weights(final_sumcheck_r), finalVector)
        GoldilocksExt3.Ext3[] memory finalSumcheckR = new GoldilocksExt3.Ext3[](params.finalSumcheckRounds);
        for (uint256 i = 0; i < params.finalSumcheckRounds; i++) {
            finalSumcheckR[i] = vs.allFoldingRandomness[vs.foldIdx - params.finalSumcheckRounds + i];
        }
        GoldilocksExt3.Ext3[] memory eqW = WhirLinearAlgebra.eqWeights(finalSumcheckR);
        GoldilocksExt3.Ext3 memory polyEval = WhirLinearAlgebra.dotProduct(eqW, finalVector);
        require(!GoldilocksExt3.isZero(polyEval), "polyEval is zero");

        // linear_form_rlc = theSum / polyEval
        GoldilocksExt3.Ext3 memory linearFormRlc = vs.theSum.mul(GoldilocksExt3.inv(polyEval));

        // Subtract initial OOD constraints
        _subtractOodConstraints(
            linearFormRlc,
            vs.initialOodRlcCoeffs,
            vs.initialOodPoints,
            vs.allFoldingRandomness,
            vs.totalFoldingLen,
            _initialNumVars(params)
        );

        // Verify external linear forms
        // For single linear form = MultilinearExtension at canonical point (1, 2, ..., n):
        //   expectedRlc = constraintRlc[0] * eq(canonical, evaluation_point)
        _verifyExternalLinearForms(
            linearFormRlc,
            vs.initialConstraintRlc,
            vs.numLinearForms,
            vs.allFoldingRandomness,
            params.numVariables
        );
    }

    function _subtractOodConstraints(
        GoldilocksExt3.Ext3 memory linearFormRlc,
        uint64[] memory rlcCoeffs,
        GoldilocksExt3.Ext3[] memory oodPoints,
        GoldilocksExt3.Ext3[] memory allFoldingR,
        uint256 totalFoldLen,
        uint256 roundNumVars
    ) private pure {
        uint256 start = totalFoldLen > roundNumVars ? totalFoldLen - roundNumVars : 0;
        GoldilocksExt3.Ext3[] memory evalSuffix = new GoldilocksExt3.Ext3[](totalFoldLen - start);
        for (uint256 i = 0; i < evalSuffix.length; i++) {
            evalSuffix[i] = allFoldingR[start + i];
        }

        for (uint256 i = 0; i < oodPoints.length; i++) {
            GoldilocksExt3.Ext3 memory mleVal = WhirLinearAlgebra.mleEvaluateUnivariate(
                oodPoints[i], evalSuffix
            );
            // linearFormRlc -= rlcCoeffs[i] * mleVal
            GoldilocksExt3.Ext3 memory term = mleVal.mulScalar(rlcCoeffs[i]);
            linearFormRlc.c0 = uint64(addmod(uint256(linearFormRlc.c0), uint256(GL_P) - uint256(term.c0), uint256(GL_P)));
            linearFormRlc.c1 = uint64(addmod(uint256(linearFormRlc.c1), uint256(GL_P) - uint256(term.c1), uint256(GL_P)));
            linearFormRlc.c2 = uint64(addmod(uint256(linearFormRlc.c2), uint256(GL_P) - uint256(term.c2), uint256(GL_P)));
        }
    }

    function _verifyExternalLinearForms(
        GoldilocksExt3.Ext3 memory linearFormRlc,
        uint64[] memory constraintRlc,
        uint256 numLinearForms,
        GoldilocksExt3.Ext3[] memory allFoldingR,
        uint256 numVariables
    ) private pure {
        // Build canonical point (1, 2, ..., n)
        GoldilocksExt3.Ext3[] memory canonicalPoint = new GoldilocksExt3.Ext3[](numVariables);
        for (uint256 i = 0; i < numVariables; i++) {
            canonicalPoint[i] = GoldilocksExt3.fromBase(uint64(i + 1));
        }

        GoldilocksExt3.Ext3 memory expectedRlc = GoldilocksExt3.zero();
        for (uint256 i = 0; i < numLinearForms; i++) {
            GoldilocksExt3.Ext3 memory eqVal = WhirLinearAlgebra.mleEvaluateEq(
                canonicalPoint, allFoldingR
            );
            expectedRlc = expectedRlc.add(eqVal.mulScalar(constraintRlc[i]));
        }

        require(GoldilocksExt3.eq(linearFormRlc, expectedRlc), "FinalClaim: linear form mismatch");
    }

    /// @dev Generate challenge indices WITHOUT sorting/deduplication.
    ///      Matches Rust challenge_indices(transcript, num_leaves, count, deduplicate=false).
    function _challengeIndicesUnsorted(
        SpongefishWhir.TranscriptState memory ts,
        uint256 numLeaves,
        uint256 count
    ) private pure returns (uint256[] memory indices) {
        if (count == 0) return new uint256[](0);
        if (numLeaves == 1) {
            indices = new uint256[](count);
            return indices; // all zeros
        }

        uint256 sizeBytes = _ceilDiv(_log2(numLeaves), 8);
        bytes memory entropy = ts.sponge.squeeze(count * sizeBytes);

        indices = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 val = 0;
            for (uint256 j = 0; j < sizeBytes; j++) {
                val = (val << 8) | uint256(uint8(entropy[i * sizeBytes + j]));
            }
            indices[i] = val % numLeaves;
        }
    }

    /// @dev Sort (index, hash) pairs by index and deduplicate.
    ///      When duplicate indices have the same hash, keep one copy.
    function _sortAndDedupWithHashes(
        uint256[] memory indices,
        bytes32[] memory hashes
    ) private pure returns (uint256[] memory sortedIndices, bytes32[] memory sortedHashes) {
        uint256 n = indices.length;
        // Insertion sort by index, carrying hashes along
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

        // Dedup
        if (n <= 1) {
            return (indices, hashes);
        }
        uint256 write = 1;
        for (uint256 i = 1; i < n; i++) {
            if (indices[i] != indices[i - 1]) {
                indices[write] = indices[i];
                hashes[write] = hashes[i];
                write++;
            }
        }
        assembly {
            mstore(indices, write)
            mstore(hashes, write)
        }
        return (indices, hashes);
    }

    /// @dev Ceiling division.
    function _ceilDiv(uint256 a, uint256 b) private pure returns (uint256) {
        return (a + b - 1) / b;
    }

    /// @dev log2 for powers of 2.
    function _log2(uint256 x) private pure returns (uint256 n) {
        while (x > 1) { x >>= 1; n++; }
    }

    function _initialNumVars(WhirParams memory params) private pure returns (uint256) {
        // initial_num_variables = log2(initial_size)
        // initial_size = codeword_length * interleaving_depth (= vector_size)
        uint256 initialSize = params.initialCodewordLength * params.initialInterleavingDepth;
        uint256 n = 0;
        while (initialSize > 1) { initialSize >>= 1; n++; }
        return n;
    }
}
