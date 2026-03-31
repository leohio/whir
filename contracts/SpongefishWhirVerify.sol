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
        _phaseFinalClaim(params, vs, finalVector);

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

        // OOD for this round: ALL points squeezed first, then ALL answers absorbed
        // (matches Rust irs_commit::receive_commitment order)
        GoldilocksExt3.Ext3[] memory roundOodPoints = new GoldilocksExt3.Ext3[](params.roundOutDomainSamples);
        for (uint256 i = 0; i < params.roundOutDomainSamples; i++) {
            (uint64 c0, uint64 c1, uint64 c2) = SpongefishWhir.verifierMessageField64x3(ts);
            roundOodPoints[i] = GoldilocksExt3.Ext3(c0, c1, c2);
        }
        GoldilocksExt3.Ext3[] memory roundOodAnswers = new GoldilocksExt3.Ext3[](params.roundOutDomainSamples);
        for (uint256 i = 0; i < params.roundOutDomainSamples; i++) {
            (uint64 a0, uint64 a1, uint64 a2) = SpongefishWhir.proverMessageField64x3(ts, transcript);
            roundOodAnswers[i] = GoldilocksExt3.Ext3(a0, a1, a2);
        }

        // Open previous commitment with Merkle verification
        _openAndVerifyCommitment(ts, hints, params, vs, round, roundOodAnswers, roundOodPoints);

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

        ts.hintPos += 8; // skip Vec<T> length prefix (zero-copy)
        bytes32[] memory rawFinalHashes = new bytes32[](rawFinalIndices.length);
        for (uint256 i = 0; i < rawFinalIndices.length; i++) {
            rawFinalHashes[i] = _keccak256At(hints, ts.hintPos, finalRowBytes);
            ts.hintPos += finalRowBytes;
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
        GoldilocksExt3.Ext3[] memory finalVector
    ) private pure {
        // poly_eval = dot(eq_weights(final_sumcheck_r), finalVector)
        // Use in-place fold: v'[i] = v[2i]*(1-r) + v[2i+1]*r, repeated for each randomness
        uint256 foldStart = vs.foldIdx - params.finalSumcheckRounds;
        GoldilocksExt3.Ext3 memory polyEval = _foldEval(finalVector, vs.allFoldingRandomness, foldStart, params.finalSumcheckRounds);
        require(!GoldilocksExt3.isZero(polyEval), "polyEval is zero");

        // linear_form_rlc = theSum / polyEval
        GoldilocksExt3.Ext3 memory linearFormRlc = vs.theSum.mul(GoldilocksExt3.inv(polyEval));

        // Subtract ALL round constraints (matching Rust's round_constraints loop)
        for (uint256 rc = 0; rc < vs.roundConstraints.length; rc++) {
            RoundConstraintEntry memory entry = vs.roundConstraints[rc];
            if (entry.rlcCoeffs.length == 0) continue;

            uint256 nv = entry.numVariables;
            uint256 start = vs.totalFoldingLen > nv ? vs.totalFoldingLen - nv : 0;

            for (uint256 i = 0; i < entry.rlcCoeffs.length; i++) {
                GoldilocksExt3.Ext3 memory mleVal = WhirLinearAlgebra.mleEvaluateUnivariateFrom(
                    entry.univariatePoints[i], vs.allFoldingRandomness, start
                );
                GoldilocksExt3.Ext3 memory term = mleVal.mul(entry.rlcCoeffs[i]);
                GoldilocksExt3.Ext3 memory result = linearFormRlc.sub(term);
                linearFormRlc.c0 = result.c0;
                linearFormRlc.c1 = result.c1;
                linearFormRlc.c2 = result.c2;
            }
        }

        GoldilocksExt3.Ext3 memory initialLinearFormRlcSum = GoldilocksExt3.zero();
        for (uint256 i = 0; i < vs.numLinearForms; i++) {
            GoldilocksExt3.Ext3 memory result = initialLinearFormRlcSum.add(vs.initialConstraintRlc[i]);
            initialLinearFormRlcSum.c0 = result.c0;
            initialLinearFormRlcSum.c1 = result.c1;
            initialLinearFormRlcSum.c2 = result.c2;
        }
        GoldilocksExt3.Ext3 memory expectedRlc = WhirLinearAlgebra.mleEvaluateEqCanonical(
            params.numVariables, vs.allFoldingRandomness
        ).mul(initialLinearFormRlcSum);

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
            entropy[i] = bytes1(ts.sponge.squeezeByte());
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
    ) private pure returns (uint256[] memory, bytes32[] memory) {
        uint256 n = indices.length;
        if (n > 1) _quicksortWithHashes(indices, hashes, 0, n - 1);
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

    function _quicksortWithHashes(
        uint256[] memory idx,
        bytes32[] memory hsh,
        uint256 lo,
        uint256 hi
    ) private pure {
        if (lo >= hi) return;
        uint256 pivot = idx[(lo + hi) / 2];
        uint256 i = lo;
        uint256 j = hi;
        while (i <= j) {
            while (idx[i] < pivot) i++;
            while (idx[j] > pivot) { if (j == 0) break; j--; }
            if (i <= j) {
                (idx[i], idx[j]) = (idx[j], idx[i]);
                (hsh[i], hsh[j]) = (hsh[j], hsh[i]);
                i++;
                if (j == 0) break;
                j--;
            }
        }
        if (lo < j) _quicksortWithHashes(idx, hsh, lo, j);
        if (i < hi) _quicksortWithHashes(idx, hsh, i, hi);
    }

    /// @dev keccak256 of a slice within a bytes buffer (zero-copy, no allocation).
    function _keccak256At(bytes memory buf, uint256 offset, uint256 len) private pure returns (bytes32 result) {
        assembly {
            result := keccak256(add(add(buf, 0x20), offset), len)
        }
    }

    /// @dev Read a u64 LE from a bytes buffer at a given offset (zero-copy).
    ///      Uses efficient byte-swap: load BE word, extract top 8 bytes, reverse.
    function _readU64LEAt(bytes memory buf, uint256 baseOff, uint256 fieldOff) private pure returns (uint64 val) {
        assembly {
            let ptr := add(add(buf, 0x20), add(baseOff, fieldOff))
            let w := shr(192, mload(ptr)) // top 8 bytes as BE u64

            // Byte-swap 64-bit BE → LE using parallel swap
            // Swap bytes in pairs of 1, then 2, then 4
            w := or(and(shr(8, w), 0x00FF00FF00FF00FF), and(shl(8, w), 0xFF00FF00FF00FF00))
            w := or(and(shr(16, w), 0x0000FFFF0000FFFF), and(shl(16, w), 0xFFFF0000FFFF0000))
            w := or(shr(32, w), shl(32, w))
            val := and(w, 0xFFFFFFFFFFFFFFFF)
        }
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

    struct OpenParams {
        uint256 cl;
        uint256 md;
        uint256 rowBytes;
        uint64 domainGen;
        uint256 numCosets;
        uint256 cosetSize;
        uint256 inDomainSamples;
        uint256 numCols;
        bool isBaseField;
    }

    function _getOpenParams(WhirParams memory params, uint256 round) private pure returns (OpenParams memory o) {
        if (round == 0) {
            o.cl = params.initialCodewordLength;
            o.md = params.initialMerkleDepth;
            o.rowBytes = params.initialInterleavingDepth * params.numVectors * 8;
            o.domainGen = params.initialDomainGenerator;
            o.numCosets = params.initialNumCosets;
            o.cosetSize = params.initialCosetSize;
            o.inDomainSamples = params.inDomainSamples;
            o.numCols = params.initialInterleavingDepth * params.numVectors;
            o.isBaseField = true;
        } else {
            o.cl = params.roundCodewordLength;
            o.md = params.roundMerkleDepth;
            o.rowBytes = params.roundInterleavingDepth * 24;
            o.domainGen = params.roundDomainGenerator;
            o.numCosets = params.roundNumCosets;
            o.cosetSize = params.roundCosetSize;
            o.inDomainSamples = params.roundInDomainSamples;
            o.numCols = params.roundInterleavingDepth;
            o.isBaseField = false;
        }
    }

    function _openAndVerifyCommitment(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory hints,
        WhirParams memory params,
        VerifyState memory vs,
        uint256 round,
        GoldilocksExt3.Ext3[] memory roundOodAnswers,
        GoldilocksExt3.Ext3[] memory roundOodPoints
    ) private pure {
        OpenParams memory o = _getOpenParams(params, round);

        uint256[] memory rawIndices = _challengeIndicesUnsorted(ts, o.cl, o.inDomainSamples);
        uint256 rawCount = rawIndices.length;

        ts.hintPos += 8; // skip Vec<T> length prefix (zero-copy)

        bytes32[] memory rawLeafHashes = new bytes32[](rawCount);
        uint256[] memory rowOffsets = new uint256[](rawCount);

        for (uint256 i = 0; i < rawCount; i++) {
            uint256 rowOff = ts.hintPos;
            rowOffsets[i] = rowOff;
            rawLeafHashes[i] = _keccak256At(hints, rowOff, o.rowBytes);
            ts.hintPos += o.rowBytes;
        }

        GoldilocksExt3.Ext3[] memory inDomainEvalPoints = _computeEvalPoints(
            rawIndices, rawCount, o.domainGen, o.numCosets, o.cosetSize
        );

        (uint256[] memory sortedIndices, bytes32[] memory sortedHashes) =
            _sortAndDedupWithHashes(rawIndices, rawLeafHashes);

        ts.hintPos = SpongefishMerkle.verify(
            vs.prevRoot, o.md, sortedIndices, sortedHashes, hints, ts.hintPos
        );

        _addConstraintValues(ts, hints, params, vs, round, rawCount, roundOodAnswers,
            roundOodPoints, rowOffsets, inDomainEvalPoints, o.numCols, o.isBaseField);
    }

    function _computeEvalPoints(
        uint256[] memory rawIndices,
        uint256 rawCount,
        uint64 domainGen,
        uint256 numCosets,
        uint256 cosetSize
    ) private pure returns (GoldilocksExt3.Ext3[] memory pts) {
        pts = new GoldilocksExt3.Ext3[](rawCount);
        for (uint256 i = 0; i < rawCount; i++) {
            uint256 idx = rawIndices[i];
            uint256 row_ = idx / cosetSize;
            uint256 col_ = idx % cosetSize;
            uint256 permuted = row_ + col_ * numCosets;
            pts[i] = GoldilocksExt3.fromBase(_glPow(domainGen, permuted));
        }
    }

    function _addConstraintValues(
        SpongefishWhir.TranscriptState memory ts,
        bytes memory hints,
        WhirParams memory params,
        VerifyState memory vs,
        uint256 round,
        uint256 rawCount,
        GoldilocksExt3.Ext3[] memory roundOodAnswers,
        GoldilocksExt3.Ext3[] memory roundOodPoints,
        uint256[] memory rowOffsets,
        GoldilocksExt3.Ext3[] memory inDomainEvalPoints,
        uint256 numCols,
        bool isBaseField
    ) private pure {
        // eq_weights from last folding randomness (read directly, no copy)
        uint256 ff = (round == 0) ? params.initialSumcheckRounds : params.roundSumcheckRounds;
        uint256 eqBase = vs.foldIdx - ff;
        GoldilocksExt3.Ext3[] memory eqW = WhirLinearAlgebra.eqWeightsFrom(vs.allFoldingRandomness, eqBase, ff);

        // Constraint RLC
        uint256 constraintCount = params.roundOutDomainSamples + rawCount;
        GoldilocksExt3.Ext3[] memory roundRlc = SpongefishWhir.geometricChallenge(ts, constraintCount);

        // Add OOD constraint values
        for (uint256 i = 0; i < params.roundOutDomainSamples; i++) {
            vs.theSum = vs.theSum.add(roundOodAnswers[i].mul(roundRlc[i]));
        }

        // Add in-domain constraint values (streaming: decode + dot in one pass)
        for (uint256 i = 0; i < rawCount; i++) {
            GoldilocksExt3.Ext3 memory val = _dotEqWithRow(eqW, hints, rowOffsets[i], numCols, isBaseField);
            vs.theSum = vs.theSum.add(val.mul(roundRlc[params.roundOutDomainSamples + i]));
        }

        // Build evaluation points for FinalClaim
        GoldilocksExt3.Ext3[] memory allEvalPoints = new GoldilocksExt3.Ext3[](constraintCount);
        for (uint256 i = 0; i < params.roundOutDomainSamples; i++) {
            allEvalPoints[i] = roundOodPoints[i];
        }
        for (uint256 i = 0; i < rawCount; i++) {
            allEvalPoints[params.roundOutDomainSamples + i] = inDomainEvalPoints[i];
        }

        vs.roundConstraints[1 + round] = RoundConstraintEntry({
            rlcCoeffs: roundRlc,
            univariatePoints: allEvalPoints,
            numVariables: params.roundInitialNumVariables
        });
    }

    /// @dev Evaluate dot(eq_weights(r), vector) by in-place folding (no eqWeights alloc).
    ///      Fold in REVERSE order: last randomness first (matching eqWeights bit convention).
    ///      Mutates `vec` in place. Full assembly.
    function _foldEval(
        GoldilocksExt3.Ext3[] memory vec,
        GoldilocksExt3.Ext3[] memory randomness,
        uint256 rStart,
        uint256 numRounds
    ) private pure returns (GoldilocksExt3.Ext3 memory result) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let size := mload(vec)
            let vecData := add(vec, 0x20)   // pointer to array of Ext3 pointers
            let rData := add(randomness, 0x20)

            for { let round := numRounds } gt(round, 0) { round := sub(round, 1) } {
                let rPtr := mload(add(rData, mul(add(rStart, sub(round, 1)), 0x20)))
                let rr0 := mload(rPtr)
                let rr1 := mload(add(rPtr, 0x20))
                let rr2 := mload(add(rPtr, 0x40))
                // oneMinusR
                let omr0 := addmod(1, sub(p, rr0), p)
                let omr1 := sub(p, rr1)  // 0 - r1 mod p
                let omr2 := sub(p, rr2)

                let half := shr(1, size)
                for { let i := 0 } lt(i, half) { i := add(i, 1) } {
                    let evenPtr := mload(add(vecData, mul(mul(i, 2), 0x20)))
                    let oddPtr := mload(add(vecData, mul(add(mul(i, 2), 1), 0x20)))

                    let e0 := mload(evenPtr)
                    let e1 := mload(add(evenPtr, 0x20))
                    let e2 := mload(add(evenPtr, 0x40))
                    let o0 := mload(oddPtr)
                    let o1 := mload(add(oddPtr, 0x20))
                    let o2 := mload(add(oddPtr, 0x40))

                    // even * oneMinusR (Ext3 mul)
                    let t1a := addmod(mulmod(e1, omr2, p), mulmod(e2, omr1, p), p)
                    let em0 := addmod(mulmod(e0, omr0, p), mulmod(2, t1a, p), p)
                    let em1 := addmod(addmod(mulmod(e0, omr1, p), mulmod(e1, omr0, p), p), mulmod(2, mulmod(e2, omr2, p), p), p)
                    let em2 := addmod(addmod(mulmod(e0, omr2, p), mulmod(e1, omr1, p), p), mulmod(e2, omr0, p), p)

                    // odd * r (Ext3 mul)
                    let t1b := addmod(mulmod(o1, rr2, p), mulmod(o2, rr1, p), p)
                    let om0 := addmod(mulmod(o0, rr0, p), mulmod(2, t1b, p), p)
                    let om1 := addmod(addmod(mulmod(o0, rr1, p), mulmod(o1, rr0, p), p), mulmod(2, mulmod(o2, rr2, p), p), p)
                    let om2 := addmod(addmod(mulmod(o0, rr2, p), mulmod(o1, rr1, p), p), mulmod(o2, rr0, p), p)

                    // Store result into vec[i]'s memory (reuse evenPtr)
                    let destPtr := mload(add(vecData, mul(i, 0x20)))
                    mstore(destPtr, addmod(em0, om0, p))
                    mstore(add(destPtr, 0x20), addmod(em1, om1, p))
                    mstore(add(destPtr, 0x40), addmod(em2, om2, p))
                }
                size := half
            }

            // result = vec[0]
            let v0Ptr := mload(vecData)
            mstore(result, mload(v0Ptr))
            mstore(add(result, 0x20), mload(add(v0Ptr, 0x20)))
            mstore(add(result, 0x40), mload(add(v0Ptr, 0x40)))
        }
    }

    /// @dev Compute dot(eqW, row) by reading row fields directly from hints (no row alloc).
    ///      Full assembly: reads LE u64 fields from hints, accumulates mul+add on stack.
    function _dotEqWithRow(
        GoldilocksExt3.Ext3[] memory eqW,
        bytes memory hints,
        uint256 rowOff,
        uint256 numCols,
        bool isBaseField
    ) private pure returns (GoldilocksExt3.Ext3 memory acc) {
        assembly {
            let p := 0xFFFFFFFF00000001
            let r0 := 0
            let r1 := 0
            let r2 := 0
            let eqPtr := add(eqW, 0x20) // pointer to first element pointer
            let base := add(add(hints, 0x20), rowOff)

            // Helper: byte-swap 64-bit BE→LE inline (repeated via copy)
            // We use a function-like macro via code duplication

            for { let j := 0 } lt(j, numCols) { j := add(j, 1) } {
                let eqElem := mload(add(eqPtr, mul(j, 0x20)))
                let w0 := mload(eqElem)
                let w1 := mload(add(eqElem, 0x20))
                let w2 := mload(add(eqElem, 0x40))

                // Read field element(s) from hints
                let b0 := 0
                let b1 := 0
                let b2 := 0

                switch isBaseField
                case 1 {
                    // Base field: 1 u64 LE → (val, 0, 0)
                    let raw := shr(192, mload(add(base, mul(j, 8))))
                    raw := or(and(shr(8, raw), 0x00FF00FF00FF00FF), and(shl(8, raw), 0xFF00FF00FF00FF00))
                    raw := or(and(shr(16, raw), 0x0000FFFF0000FFFF), and(shl(16, raw), 0xFFFF0000FFFF0000))
                    raw := or(shr(32, raw), shl(32, raw))
                    b0 := and(raw, 0xFFFFFFFFFFFFFFFF)
                    // b1, b2 stay 0

                    // mulScalar: result = (w0*b0, w1*b0, w2*b0) mod p
                    r0 := addmod(r0, mulmod(w0, b0, p), p)
                    r1 := addmod(r1, mulmod(w1, b0, p), p)
                    r2 := addmod(r2, mulmod(w2, b0, p), p)
                }
                default {
                    // Ext3: 3 u64 LE
                    let off := mul(j, 24)

                    let raw0 := shr(192, mload(add(base, off)))
                    raw0 := or(and(shr(8, raw0), 0x00FF00FF00FF00FF), and(shl(8, raw0), 0xFF00FF00FF00FF00))
                    raw0 := or(and(shr(16, raw0), 0x0000FFFF0000FFFF), and(shl(16, raw0), 0xFFFF0000FFFF0000))
                    raw0 := or(shr(32, raw0), shl(32, raw0))
                    b0 := and(raw0, 0xFFFFFFFFFFFFFFFF)

                    let raw1 := shr(192, mload(add(base, add(off, 8))))
                    raw1 := or(and(shr(8, raw1), 0x00FF00FF00FF00FF), and(shl(8, raw1), 0xFF00FF00FF00FF00))
                    raw1 := or(and(shr(16, raw1), 0x0000FFFF0000FFFF), and(shl(16, raw1), 0xFFFF0000FFFF0000))
                    raw1 := or(shr(32, raw1), shl(32, raw1))
                    b1 := and(raw1, 0xFFFFFFFFFFFFFFFF)

                    let raw2 := shr(192, mload(add(base, add(off, 16))))
                    raw2 := or(and(shr(8, raw2), 0x00FF00FF00FF00FF), and(shl(8, raw2), 0xFF00FF00FF00FF00))
                    raw2 := or(and(shr(16, raw2), 0x0000FFFF0000FFFF), and(shl(16, raw2), 0xFFFF0000FFFF0000))
                    raw2 := or(shr(32, raw2), shl(32, raw2))
                    b2 := and(raw2, 0xFFFFFFFFFFFFFFFF)

                    // Ext3 mul: eqW[j] * col
                    // mc0 = w0*b0 + 2*(w1*b2 + w2*b1)
                    let t1 := addmod(mulmod(w1, b2, p), mulmod(w2, b1, p), p)
                    let mc0 := addmod(mulmod(w0, b0, p), mulmod(2, t1, p), p)
                    // mc1 = w0*b1 + w1*b0 + 2*w2*b2
                    let mc1 := addmod(addmod(mulmod(w0, b1, p), mulmod(w1, b0, p), p), mulmod(2, mulmod(w2, b2, p), p), p)
                    // mc2 = w0*b2 + w1*b1 + w2*b0
                    let mc2 := addmod(addmod(mulmod(w0, b2, p), mulmod(w1, b1, p), p), mulmod(w2, b0, p), p)

                    r0 := addmod(r0, mc0, p)
                    r1 := addmod(r1, mc1, p)
                    r2 := addmod(r2, mc2, p)
                }
            }

            mstore(acc, r0)
            mstore(add(acc, 0x20), r1)
            mstore(add(acc, 0x40), r2)
        }
    }

    function _ceilDiv(uint256 a, uint256 b) private pure returns (uint256) {
        return (a + b - 1) / b;
    }

    function _log2(uint256 x) private pure returns (uint256 n) {
        while (x > 1) { x >>= 1; n++; }
    }
}
