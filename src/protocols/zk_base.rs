//! Base Case Linear Opening Protocol
//!
//! It is ZK but it is not Succinct.
//!
//! <https://eprint.iacr.org/2026/391.pdf> § 7.

use ark_ff::FftField;
use ark_std::rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng, RngCore};
use spongefish::{Decoding, VerificationResult};

use crate::{
    algebra::{
        embedding::Identity,
        linear_form::{Covector, Evaluate},
    },
    hash::Hash,
    protocols::irs_commit,
    transcript::{
        Codec, DuplexSpongeInterface, ProverMessage, ProverState, VerifierMessage, VerifierState,
    },
    utils::zip_strict,
    verify,
};

pub struct Config<F: FftField> {
    pub commit: irs_commit::Config<Identity<F>>,
}

impl<F: FftField> Config<F> {
    pub fn prove<H, R>(
        &self,
        prover_state: &mut ProverState<H, R>,
        vector: &[F],
        vector_witness: &irs_commit::Witness<F>,
        covector: Covector<F>,
    ) where
        H: DuplexSpongeInterface,
        R: RngCore + CryptoRng,
        F: Codec<[H::U]>,
        u8: Decoding<[H::U]>,
        Hash: ProverMessage<[H::U]>,
        Standard: Distribution<F>,
    {
        // Create masking vectors.
        let mask = (0..vector.len())
            .map(|_| prover_state.rng().gen())
            .collect::<Vec<F>>();

        // Commit to the masking vectors.
        let mask_witness = self.commit.commit(prover_state, &[&mask]);

        // Compute and send linear form of mask (μ' in paper).
        let mask_sum = covector.evaluate(&Identity::new(), &mask);
        prover_state.prover_message(&mask_sum);

        // RLC the mask with the vector
        let mask_rlc = prover_state.verifier_message::<F>();
        let masked_vector = zip_strict(vector.iter(), mask.iter())
            .map(|(v, m)| *v + mask_rlc * *m)
            .collect::<Vec<F>>();

        // Send masked vector in full.
        for v in masked_vector.iter() {
            prover_state.prover_message(v);
        }

        // Send combined IRS randomness. (r^* in paper)
        // TODO: Implement IRS randomness.

        // Open the commitment and mask simultaneously.
        let _ = self
            .commit
            .open(prover_state, &[&vector_witness, &mask_witness]);
    }

    pub fn verify<H, R>(
        &self,
        verifier_state: &mut VerifierState<H>,
        vector_commitment: irs_commit::Commitment<F>,
        covector: Covector<F>,
        sum: F,
    ) -> VerificationResult<()>
    where
        H: DuplexSpongeInterface,
        F: Codec<[H::U]>,
        u8: Decoding<[H::U]>,
        Hash: ProverMessage<[H::U]>,
    {
        let mask_commitment = self.commit.receive_commitment(verifier_state)?;
        let mask_sum: F = verifier_state.prover_message()?;
        let mask_rlc: F = verifier_state.verifier_message();
        let masked_vector: Vec<F> = verifier_state.prover_messages_vec(self.commit.vector_size)?;
        // TODO: Implement IRS randomness.

        // Open the commitment and mask simultaneously.
        let evals = self
            .commit
            .verify(verifier_state, &[&vector_commitment, &mask_commitment])?;

        // Check linear form on the masked vector.
        let masked_sum = covector.evaluate(&Identity::new(), &masked_vector);
        verify!(masked_sum == sum + mask_rlc * mask_sum);

        // Spot check evaluations.
        for (point, value) in zip_strict(
            evals.evaluators(self.commit.vector_size),
            evals.values(&[F::ONE, mask_rlc]),
        ) {
            verify!(point.evaluate(&Identity::new(), &masked_vector) == value);
        }
        Ok(())
    }
}
