use std::time::Instant;

use ceno_sumcheck::structs::IOPProverState;
use ceno_transcript::BasicTranscript as CenoTranscript;
use either::Either;
use itertools::Itertools;
use log::info;

use ff_ext::{ExtensionField as _, GoldilocksExt2};
use icicle_core::field::Field;
use icicle_core::{
    bignum::BigNum,
    program::{PreDefinedProgram, ReturningValueProgramImpl},
    sumcheck::{Sumcheck, SumcheckConfig, SumcheckProofOps, SumcheckTranscriptConfig},
    traits::GenerateRandom,
};
use icicle_goldilocks::{field::ExtensionField, sumcheck::ExtensionSumcheckProof};
use icicle_runtime::memory::HostSlice;
use merlin::Transcript;
use multilinear_extensions::mle::MultilinearExtension;
use multilinear_extensions::monomial::Term;
use multilinear_extensions::virtual_polys::VirtualPolynomials;
use p3::field::{ExtensionField as _, FieldAlgebra};
use p3::goldilocks::Goldilocks;

const NUM_VARS: usize = 2;
const SAMPLES: usize = NUM_VARS.pow(2);

const START_SUMCHECK: &[u8] = b"Internal round";
const ROUND_POLY: &[u8] = b"Internal round";
const ROUND_CHALLENGE: &[u8] = b"Internal round";

pub trait TranscriptProtocol<F: Field> {
    fn challenge_scalar(&mut self, label: &'static [u8]) -> F;
    /// Append a `scalar` with the given `label`.
    fn append_data(&mut self, label: &'static [u8], scalar: &F);
}

impl<F: Field> TranscriptProtocol<F> for Transcript
where
    F: GenerateRandom,
{
    fn challenge_scalar(&mut self, label: &'static [u8]) -> F {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        F::from_bytes_le(&buf)
    }

    fn append_data(&mut self, label: &'static [u8], scalar: &F) {
        self.append_message(label, &scalar.to_bytes_le());
    }
}

fn verify_proof(proof: ExtensionSumcheckProof, claimed_sum: ExtensionField) {
    let mut verifier_previous_transcript = Transcript::new(b"my_sumcheck");
    <Transcript as TranscriptProtocol<ExtensionField>>::append_data(
        &mut verifier_previous_transcript,
        b"public",
        &claimed_sum,
    );
    //get seed based on previous state
    let verifier_seed_rng = <Transcript as TranscriptProtocol<ExtensionField>>::challenge_scalar(
        &mut verifier_previous_transcript,
        b"seeded",
    );

    //define verifier FS config
    let leaf_size = (ExtensionField::one())
        .to_bytes_le()
        .len()
        .try_into()
        .unwrap();
    let hasher = icicle_core::poseidon2::Poseidon2::new::<ExtensionField>(leaf_size, None).unwrap();
    let verifier_transcript_config = SumcheckTranscriptConfig::new(
        &hasher,
        START_SUMCHECK.to_vec(),
        ROUND_POLY.to_vec(),
        ROUND_CHALLENGE.to_vec(),
        true,
        verifier_seed_rng,
    );

    let sumcheck =
        <icicle_goldilocks::sumcheck::ExtensionSumcheckWrapper as Sumcheck>::new().unwrap();
    let proof_validty = sumcheck.verify(&proof, claimed_sum, &verifier_transcript_config);

    match proof_validty {
        Ok(true) => println!("Valid proof!"), // Verification succeeded
        Ok(false) => {
            eprintln!("Sumcheck proof not valid");
            assert!(false, "Sumcheck proof verification failed!");
        }
        Err(err) => {
            eprintln!("Error in verification {:?}", err);
            assert!(false, "Sumcheck proof verification encountered an error!");
        }
    }
}

fn icicle_slice_to_ceno(slice: &[ExtensionField]) -> MultilinearExtension<'static, GoldilocksExt2> {
    let converted_evals: Vec<_> = slice
        .iter()
        .copied()
        .map(goldilocks_from_ceno_to_icicle)
        .collect();

    MultilinearExtension::from_evaluation_vec_smart(NUM_VARS, converted_evals)
}

fn goldilocks_from_ceno_to_icicle(element: ExtensionField) -> Goldilocks {
    Goldilocks::from_canonical_u64(u64::from_le_bytes(
        element.to_bytes_le().try_into().unwrap(),
    ))
}

#[allow(unused)]
fn goldilocks_from_cen_to_icicle_ext(element: ExtensionField) -> GoldilocksExt2 {
    let limbs: [Goldilocks; 2] = element
        .limbs()
        .iter()
        .map(|limb| goldilocks_from_ceno_to_icicle(ExtensionField::from_u32(*limb)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    GoldilocksExt2::from_limbs(&limbs)
}

fn run_ceno_sumcheck(
    poly_a: MultilinearExtension<GoldilocksExt2>,
    poly_b: MultilinearExtension<GoldilocksExt2>,
    poly_c: MultilinearExtension<GoldilocksExt2>,
    poly_e: MultilinearExtension<GoldilocksExt2>,
) -> Vec<Vec<Goldilocks>> {
    let poly1 = vec![poly_a, poly_b, poly_e.clone()];

    let poly2 = vec![poly_c, poly_e];
    let mut prover_transcript = CenoTranscript::new(b"my_sumcheck");
    let virtual_poly_v2 = VirtualPolynomials::new_from_monimials(
        2,        // threads
        NUM_VARS, // vars
        vec![
            Term {
                scalar: Either::Right(GoldilocksExt2::ONE),
                product: poly1.iter().map(Either::Left).collect_vec(),
            },
            Term {
                scalar: Either::Right(GoldilocksExt2::ZERO - GoldilocksExt2::ONE),
                product: poly2.iter().map(Either::Left).collect_vec(),
            },
        ],
    );
    let (sumcheck_proof, _state) = IOPProverState::prove(virtual_poly_v2, &mut prover_transcript);

    let sumcheck_proof: Vec<Vec<Goldilocks>> = sumcheck_proof
        .proofs
        .into_iter()
        .map(|v| {
            v.evaluations
                .into_iter()
                .map(|e| e.as_base().unwrap_or_default())
                .collect()
        })
        .collect();
    info!("ceno proof {sumcheck_proof:x?}");

    vec![]
}

fn run_icicle_sumcheck(
    poly_a: Vec<ExtensionField>,
    poly_b: Vec<ExtensionField>,
    poly_c: Vec<ExtensionField>,
    poly_e: Vec<ExtensionField>,
) -> Vec<Vec<ExtensionField>> {
    //simulate previous state
    let mut prover_previous_transcript = Transcript::new(b"my_sumcheck");

    info!("Generate e,A,B,C of log size {:?}", SAMPLES.ilog2(),);
    let compute_sum_time = Instant::now();
    //compute claimed sum
    let temp: Vec<_> = poly_a
        .iter()
        .zip(poly_b.iter())
        .zip(poly_c.iter())
        .zip(poly_e.iter())
        .map(|(((a, b), c), e)| *a * *b * *e - *c * *e)
        .collect();

    let claimed_sum = temp.iter().fold(ExtensionField::zero(), |acc, &a| acc + a);
    info!(
        "Compute claimed sum time {:?}, sum {claimed_sum}",
        compute_sum_time.elapsed()
    );

    //add claimed sum to transcript to simulate previous state
    <Transcript as TranscriptProtocol<ExtensionField>>::append_data(
        &mut prover_previous_transcript,
        b"public",
        &claimed_sum,
    );
    //get seed based on previous state
    let seed_rng = <Transcript as TranscriptProtocol<ExtensionField>>::challenge_scalar(
        &mut prover_previous_transcript,
        b"seeded",
    );

    let leaf_size = (ExtensionField::one())
        .to_bytes_le()
        .len()
        .try_into()
        .unwrap();
    let hasher = icicle_core::poseidon2::Poseidon2::new::<ExtensionField>(leaf_size, None).unwrap();

    //define sumcheck config
    let sumcheck_config = SumcheckConfig::default();

    let mle_poly_hosts = vec![
        HostSlice::<ExtensionField>::from_slice(&poly_a),
        HostSlice::<ExtensionField>::from_slice(&poly_b),
        HostSlice::<ExtensionField>::from_slice(&poly_c),
        HostSlice::<ExtensionField>::from_slice(&poly_e),
    ];
    let sumcheck =
        <icicle_goldilocks::sumcheck::ExtensionSumcheckWrapper as Sumcheck>::new().unwrap();

    let transcript_config = SumcheckTranscriptConfig::new(
        &hasher,
        START_SUMCHECK.to_vec(),
        ROUND_POLY.to_vec(),
        ROUND_CHALLENGE.to_vec(),
        true,
        seed_rng,
    );
    //try different combine functions!
    let combine_function =
        <icicle_goldilocks::program::goldilocks::ReturningValueProgram as ReturningValueProgramImpl>::new_predefined(
            PreDefinedProgram::EQtimesABminusC,
        )
        .unwrap();
    let prover_time = Instant::now();
    let proof = sumcheck.prove(
        &mle_poly_hosts,
        SAMPLES.try_into().unwrap(),
        claimed_sum,
        combine_function,
        &transcript_config,
        &sumcheck_config,
    );
    info!("Prover time {:?}", prover_time.elapsed());

    let verify_time = Instant::now();
    let proof = proof.unwrap();
    let vecs = proof.get_round_polys().unwrap();
    verify_proof(proof, claimed_sum);
    info!("verify time {:?} {vecs:?}", verify_time.elapsed());

    vecs
}

fn main() {
    env_logger::init();
    let poly_a = ExtensionField::generate_random(SAMPLES);
    let poly_b = ExtensionField::generate_random(SAMPLES);
    let poly_c = ExtensionField::generate_random(SAMPLES);
    let poly_e = ExtensionField::generate_random(SAMPLES);

    let poly_a_a = icicle_slice_to_ceno(&poly_a);
    let poly_b_b = icicle_slice_to_ceno(&poly_b);
    let poly_c_c = icicle_slice_to_ceno(&poly_c);
    let poly_e_e = icicle_slice_to_ceno(&poly_e);

    info!("{:?} {:?}", poly_a_a, poly_a);

    run_icicle_sumcheck(poly_a, poly_b, poly_c, poly_e);
    run_ceno_sumcheck(poly_a_a, poly_b_b, poly_c_c, poly_e_e);

    return;
}
