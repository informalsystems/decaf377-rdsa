use decaf377_rdsa::*;

use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

#[test]
fn sign_and_verify_spendauth() {
    let mut rng = ChaChaRng::seed_from_u64(1234);

    let sk = SigningKey::<SpendAuth>::new(&mut rng);
    let pk = VerificationKey::from(&sk);

    let msg = b"hello world";
    let sig = sk.sign(&mut rng, msg);

    assert!(pk.verify(msg, &sig).is_ok(), "valid signature should verify");
}

#[test]
fn verify_wrong_message_fails() {
    let mut rng = ChaChaRng::seed_from_u64(5678);

    let sk = SigningKey::<SpendAuth>::new(&mut rng);
    let pk = VerificationKey::from(&sk);

    let sig = sk.sign(&mut rng, b"correct message");

    assert!(
        pk.verify(b"wrong message", &sig).is_err(),
        "signature should not verify for a different message"
    );
}

#[test]
fn verify_wrong_key_fails() {
    let mut rng = ChaChaRng::seed_from_u64(9999);

    let sk = SigningKey::<SpendAuth>::new(&mut rng);
    let other_sk = SigningKey::<SpendAuth>::new(&mut rng);
    let other_pk = VerificationKey::from(&other_sk);

    let msg = b"some message";
    let sig = sk.sign(&mut rng, msg);

    assert!(
        other_pk.verify(msg, &sig).is_err(),
        "signature should not verify under a different key"
    );
}
