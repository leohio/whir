//! Generate a Solidity verifier test fixture using WHIR with Keccak256Chain transcript.
//!
//! Usage:
//!   cargo run --bin generate_solidity_fixture --release > fixture.json

use std::borrow::Cow;

use ark_ff::{FftField, Field, PrimeField, UniformRand};
use serde_json::json;
use sha3::{Digest, Keccak256};

use whir::{
    algebra::{
        embedding::Basefield,
        fields::{Field64, Field64_3},
        linear_form::{Evaluate, LinearForm, MultilinearExtension},
    },
    hash,
    parameters::ProtocolParameters,
    protocols::whir::Config,
    transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
};

fn main() {
    // ── Parameters ──────────────────────────────────────────────────────
    let num_variables = 11;
    let poly_size = 1usize << num_variables;
    let session_name = "test-fixture".to_string();

    let whir_params = ProtocolParameters {
        security_level: 100,
        pow_bits: 0,
        initial_folding_factor: 4,
        folding_factor: 4,
        unique_decoding: false,
        starting_log_inv_rate: 2,
        batch_size: 1,
        hash_id: hash::KECCAK,
    };

    // ── Config ──────────────────────────────────────────────────────────
    let config = Config::<Basefield<Field64_3>>::new(poly_size, &whir_params);
    eprintln!("{config}");

    // ── Polynomial ──────────────────────────────────────────────────────
    let mut rng = ark_std::test_rng();
    let polynomial: Vec<Field64> = (0..poly_size)
        .map(|_| Field64::rand(&mut rng))
        .collect();

    // ── Evaluation point & expected value ───────────────────────────────
    let point: Vec<Field64_3> = (1..=num_variables)
        .map(|i| Field64_3::from(i as u64))
        .collect();
    let linear_form = MultilinearExtension {
        point: point.clone(),
    };
    let eval: Field64_3 = linear_form.evaluate(config.embedding(), &polynomial);
    let evaluations = vec![eval];

    // ── Domain separator ────────────────────────────────────────────────
    let ds = DomainSeparator::protocol(&config)
        .session(&session_name)
        .instance(&Empty);

    // ── Commit ──────────────────────────────────────────────────────────
    let mut prover_state = ProverState::new_std(&ds);
    let witness = config.commit(&mut prover_state, &[&polynomial]);

    // ── Prove ───────────────────────────────────────────────────────────
    let prove_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension { point: point.clone() })];
    let _ = config.prove(
        &mut prover_state,
        vec![Cow::Borrowed(polynomial.as_slice())],
        vec![Cow::Owned(witness)],
        prove_lf,
        Cow::Borrowed(evaluations.as_slice()),
    );
    let proof = prover_state.proof();

    // ── Verify (sanity check) ───────────────────────────────────────────
    let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension { point: point.clone() })];
    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let commitment = config
        .receive_commitment(&mut verifier_state)
        .expect("receive_commitment failed");
    let final_claim = config
        .verify(&mut verifier_state, &[&commitment], &evaluations)
        .expect("verify failed");
    final_claim
        .verify(verify_lf.iter().map(|l| l.as_ref() as &dyn LinearForm<_>))
        .expect("final_claim verify failed");
    eprintln!("✓ Proof verified successfully");

    // ── Compute protocol_id & session_id ────────────────────────────────
    let mut config_bytes = Vec::new();
    ciborium::into_writer(&config, &mut config_bytes).expect("CBOR serialization failed");

    let protocol_id = {
        let first: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update([0x00]);
            h.update(&config_bytes);
            h.finalize().into()
        };
        let second: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update([0x01]);
            h.update(&config_bytes);
            h.finalize().into()
        };
        let mut id = [0u8; 64];
        id[..32].copy_from_slice(&first);
        id[32..].copy_from_slice(&second);
        id
    };

    let session_id = {
        let mut session_bytes = Vec::new();
        ciborium::into_writer(&session_name, &mut session_bytes)
            .expect("CBOR session serialization failed");
        let h: [u8; 32] = Keccak256::digest(&session_bytes).into();
        h
    };

    // ── Extract evaluations as c0/c1/c2 ────────────────────────────────
    let eval_json: Vec<_> = evaluations
        .iter()
        .map(|e| {
            let base: Vec<_> = e.to_base_prime_field_elements().collect();
            json!({
                "c0": base[0].into_bigint().0[0],
                "c1": base[1].into_bigint().0[0],
                "c2": base[2].into_bigint().0[0],
            })
        })
        .collect();

    // ── Extract WHIR params for Solidity ────────────────────────────────
    let gl_root = |n: usize| -> u64 {
        let g: Field64 =
            <Field64 as FftField>::get_root_of_unity(n as u64).expect("no root of unity");
        g.into_bigint().0[0]
    };

    let initial_cl = config.initial_committer.codeword_length;
    let initial_id = config.initial_committer.interleaving_depth;
    let (round_cl, round_id, round_in, round_out, round_sc) =
        if let Some(rc) = config.round_configs.first() {
            (
                rc.irs_committer.codeword_length,
                rc.irs_committer.interleaving_depth,
                rc.irs_committer.in_domain_samples,
                rc.irs_committer.out_domain_samples,
                rc.sumcheck.num_rounds,
            )
        } else {
            (0, 0, 0, 0, 0)
        };

    let final_cl = if config.round_configs.is_empty() {
        initial_cl
    } else {
        config.round_configs.last().unwrap().irs_committer.codeword_length
    };

    // Coset parameters for evaluation point computation
    let initial_mml = config.initial_committer.masked_message_length();
    let initial_coset_size = {
        let mut cs = initial_mml.next_power_of_two(); // simplified: power of 2
        while initial_cl % cs != 0 { cs *= 2; }
        cs
    };
    let initial_num_cosets = initial_cl / initial_coset_size;

    let (round_mml, round_coset_size, round_num_cosets) = if let Some(rc) = config.round_configs.first() {
        let mml = rc.irs_committer.masked_message_length();
        let mut cs = mml.next_power_of_two();
        while round_cl % cs != 0 { cs *= 2; }
        (mml, cs, round_cl / cs)
    } else {
        (0, 0, 0)
    };

    let whir_params_json = json!({
        "num_variables": num_variables,
        "folding_factor": whir_params.folding_factor,
        "num_vectors": config.initial_committer.num_vectors,
        "out_domain_samples": config.initial_committer.out_domain_samples,
        "in_domain_samples": config.initial_committer.in_domain_samples,
        "initial_sumcheck_rounds": config.initial_sumcheck.num_rounds,
        "num_rounds": config.round_configs.len(),
        "final_sumcheck_rounds": config.final_sumcheck.num_rounds,
        "final_size": config.final_sumcheck.initial_size,
        "round_in_domain_samples": round_in,
        "round_out_domain_samples": round_out,
        "round_sumcheck_rounds": round_sc,
        "initial_codeword_length": initial_cl,
        "initial_merkle_depth": initial_cl.ilog2(),
        "initial_domain_generator": gl_root(initial_cl),
        "round_codeword_length": round_cl,
        "round_merkle_depth": if round_cl > 0 { round_cl.ilog2() } else { 0 },
        "round_domain_generator": if round_cl > 0 { gl_root(round_cl) } else { 0 },
        "final_codeword_length": final_cl,
        "final_domain_generator": gl_root(final_cl),
        "initial_interleaving_depth": initial_id,
        "round_interleaving_depth": round_id,
        // New params for FinalClaim
        "initial_num_variables": config.initial_num_variables(),
        "round_initial_num_variables": config.round_configs.first()
            .map(|rc| rc.initial_num_variables()).unwrap_or(0),
        "initial_coset_size": initial_coset_size,
        "initial_num_cosets": initial_num_cosets,
        "round_coset_size": round_coset_size,
        "round_num_cosets": round_num_cosets,
    });

    // ── Build JSON ──────────────────────────────────────────────────────
    let fixture = json!({
        "protocol_id": format!("0x{}", hex::encode(protocol_id)),
        "session_id": format!("0x{}", hex::encode(session_id)),
        "instance": "0x",
        "transcript": format!("0x{}", hex::encode(&proof.narg_string)),
        "hints": format!("0x{}", hex::encode(&proof.hints)),
        "num_variables": num_variables,
        "evaluations": eval_json,
        "evaluation_point": (1..=num_variables).map(|i| i.to_string()).collect::<Vec<_>>(),
        "session_name": session_name,
        "whir_config": {
            "num_variables": num_variables,
            "folding_factor": whir_params.folding_factor,
            "security_level": whir_params.security_level,
            "starting_log_inv_rate": whir_params.starting_log_inv_rate,
        },
        "whir_params": whir_params_json,
    });

    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());

    // Compute FinalClaim and add debug values to fixture (on stderr)
    {
        let verify_lf3: Vec<Box<dyn LinearForm<Field64_3>>> =
            vec![Box::new(MultilinearExtension { point: point.clone() })];
        let mut vs2 = VerifierState::new_std(&ds, &proof);
        let commitment2 = config.receive_commitment(&mut vs2).unwrap();
        let fc = config.verify(&mut vs2, &[&commitment2], &evaluations).unwrap();

        let base_elems = |v: &Field64_3| -> Vec<u64> {
            v.to_base_prime_field_elements()
                .map(|e| e.into_bigint().0[0])
                .collect()
        };

        // Write debug values to stderr for fixture reference
        eprintln!("FinalClaim linear_form_rlc: {:?}", base_elems(&fc.linear_form_rlc));
        eprintln!("FinalClaim rlc_coefficients[0]: {:?}", base_elems(&fc.rlc_coefficients[0]));
        for (i, r) in fc.evaluation_point.iter().enumerate() {
            eprintln!("  eval_point[{}]: {:?}", i, base_elems(r));
        }
    }
}
