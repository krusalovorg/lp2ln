//! One independent Noise XX reference vector from Cacophony, as shipped in
//! snow v0.10.0 (MIT or Apache-2.0), tests/vectors/cacophony.txt.
//! https://github.com/mcginty/snow/blob/v0.10.0/tests/vectors/cacophony.txt

use super::*;

fn h(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

#[test]
fn cacophony_xx_handshake_and_stateless_transport() {
    let a_static = h("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
    let b_static = h("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
    let a_ephemeral = h("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
    let b_ephemeral = h("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
    let prologue = h("4a6f686e2047616c74");
    let builder = |local, eph| {
        snow::Builder::new(NOISE_SUITE.parse().unwrap())
            .prologue(&prologue)
            .unwrap()
            .local_private_key(local)
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(eph)
    };
    let mut a = builder(&a_static, &a_ephemeral).build_initiator().unwrap();
    let mut b = builder(&b_static, &b_ephemeral).build_responder().unwrap();
    let mut output = [0; 256];
    let mut plaintext = [0; 256];
    let messages = [
        (
            "4c756477696720766f6e204d69736573",
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
        ),
        (
            "4d757272617920526f746862617264",
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad",
        ),
        (
            "462e20412e20486179656b",
            "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030",
        ),
        (
            "4361726c204d656e676572",
            "96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df",
        ),
        (
            "4a65616e2d426170746973746520536179",
            "3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5",
        ),
        (
            "457567656e2042f6686d20766f6e2042617765726b",
            "eb3f3515110702e047a6c9da4478b6ead94873c11c0f2d710ddb3f09fce024b3a58502ae3f",
        ),
    ];
    for (i, (payload, ciphertext)) in messages.iter().take(3).enumerate() {
        let (sender, receiver) = if i % 2 == 0 {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let count = sender.write_message(&h(payload), &mut output).unwrap();
        assert_eq!(&output[..count], &h(ciphertext));
        let got = receiver
            .read_message(&output[..count], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..got], &h(payload));
    }
    assert_eq!(
        a.get_handshake_hash(),
        &h("c8e5f64e846193be2a834104c2a009868d6c9f3bd3c186299888b488b2f1f58e")
    );
    assert_eq!(b.get_handshake_hash(), a.get_handshake_hash());

    let a = a.into_stateless_transport_mode().unwrap();
    let b = b.into_stateless_transport_mode().unwrap();
    for (i, (payload, ciphertext)) in messages.iter().skip(3).enumerate() {
        let (sender, receiver) = if i % 2 == 0 { (&b, &a) } else { (&a, &b) };
        let count = sender
            .write_message((i / 2) as u64, &h(payload), &mut output)
            .unwrap();
        assert_eq!(&output[..count], &h(ciphertext));
        let got = receiver
            .read_message((i / 2) as u64, &output[..count], &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..got], &h(payload));
    }
}

#[test]
fn identity_proof_binds_evidence_to_the_channel_role_and_version() {
    use crate::crypto::NodeKeypair;
    let a = NodeKeypair::generate();
    let b = NodeKeypair::generate();
    let a_offer = Offer::new(&a, b.peer_id(), FlowId([0x42; 16]), 3).unwrap();
    let b_offer = Offer::new(&b, a.peer_id(), FlowId([0x42; 16]), 3).unwrap();
    let proof = link_proof(&a, &a_offer, &b_offer, &[2; 32], Role::Initiator).unwrap();
    verify_link(
        a.peer_id(),
        &a_offer,
        &b_offer,
        &[2; 32],
        Role::Initiator,
        &proof,
    )
    .unwrap();
    assert!(
        verify_link(
            b.peer_id(),
            &a_offer,
            &b_offer,
            &[2; 32],
            Role::Initiator,
            &proof
        )
        .is_err()
    );
    assert!(
        verify_link(
            a.peer_id(),
            &a_offer,
            &b_offer,
            &[3; 32],
            Role::Initiator,
            &proof
        )
        .is_err()
    );
    assert!(
        verify_link(
            a.peer_id(),
            &a_offer,
            &b_offer,
            &[2; 32],
            Role::Responder,
            &proof
        )
        .is_err()
    );
    let mut downgraded = b_offer.clone();
    downgraded.capabilities = 0;
    assert!(
        verify_link(
            a.peer_id(),
            &a_offer,
            &downgraded,
            &[2; 32],
            Role::Initiator,
            &proof
        )
        .is_err()
    );
}

fn fresh_record_pair(epoch: u32) -> (RecordKeys, RecordKeys) {
    let a = snow::Builder::new(NOISE_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let b = snow::Builder::new(NOISE_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let mut initiator = snow::Builder::new(NOISE_SUITE.parse().unwrap())
        .local_private_key(&a.private)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut responder = snow::Builder::new(NOISE_SUITE.parse().unwrap())
        .local_private_key(&b.private)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut message = [0; 256];
    let mut output = [0; 256];
    for i in 0..3 {
        let (sender, receiver) = if i % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let n = sender.write_message(&[], &mut message).unwrap();
        assert_eq!(
            receiver.read_message(&message[..n], &mut output).unwrap(),
            0
        );
    }
    let create = |state, role| RecordKeys {
        state,
        role,
        epoch,
        id: FlowId([0x42; 16]),
        next: [0; 2],
        replay: std::array::from_fn(|_| ReplayWindow::default()),
    };
    (
        create(
            initiator.into_stateless_transport_mode().unwrap(),
            Role::Initiator,
        ),
        create(
            responder.into_stateless_transport_mode().unwrap(),
            Role::Responder,
        ),
    )
}

#[test]
fn authenticated_records_survive_reordering_and_reject_corruption_duplicates_and_reflection() {
    use rand::{SeedableRng, seq::SliceRandom};
    for seed in 0..24 {
        let (mut a, mut b) = fresh_record_pair(0);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let pending_control = a.seal(KIND_REKEY, 0, b"control").unwrap();
        let mut records: Vec<_> = (0..256_u16)
            .map(|id| (id, a.seal(KIND_DATA, 100, &id.to_be_bytes()).unwrap()))
            .collect();
        let mut forgery = records[255].1.clone();
        let last = forgery.len() - 1;
        forgery[last] ^= 0x40;
        assert!(matches!(
            b.open(KIND_DATA, &forgery),
            Err(RecordError::Invalid)
        ));
        assert!(matches!(
            a.open(KIND_DATA, &records[0].1),
            Err(RecordError::Invalid)
        ));
        let (_, mut unrelated) = fresh_record_pair(0);
        assert!(matches!(
            unrelated.open(KIND_DATA, &records[0].1),
            Err(RecordError::Invalid)
        ));
        for group in records.chunks_mut(64) {
            group.shuffle(&mut rng);
            for (id, wire) in group {
                assert_eq!(
                    b.open(KIND_DATA, wire).unwrap(),
                    (100, id.to_be_bytes().to_vec())
                );
                assert!(matches!(b.open(KIND_DATA, wire), Err(RecordError::Replay)));
            }
        }
        assert_eq!(
            b.open(KIND_REKEY, &pending_control).unwrap(),
            (0, b"control".to_vec())
        );
    }
}

#[test]
fn fresh_epoch_keeps_bounded_receive_overlap_rejecting_retired_records() {
    let (mut a, b) = fresh_record_pair(0);
    let delayed = a.seal(KIND_DATA, 100, b"old").unwrap();
    let delayed_after_retirement = a.seal(KIND_DATA, 100, b"old").unwrap();
    let mut receiver = Epochs::new(b);
    let (mut new_a, new_b) = fresh_record_pair(1);
    let now = Instant::now();
    receiver.install(new_b, now).unwrap();
    let fresh = new_a.seal(KIND_DATA, 200, b"new").unwrap();
    assert_eq!(receiver.open_data(&delayed, now).unwrap().1, b"old");
    assert_eq!(receiver.open_data(&fresh, now).unwrap().1, b"new");
    assert!(matches!(
        receiver.open_data(&delayed, now),
        Err(RecordError::Replay)
    ));
    assert!(matches!(
        receiver.open_data(&delayed_after_retirement, now + Duration::from_secs(3)),
        Err(RecordError::Epoch)
    ));
    let (_, rollback) = fresh_record_pair(0);
    assert!(receiver.install(rollback, now).is_err());
}

#[test]
fn noise_identity_certificate_requires_expected_role_binding_and_static_key() {
    let local = NodeKeypair::generate();
    let other = NodeKeypair::generate();
    let binding = b"logical-flow/epoch";
    let key = [42; 32];
    let cert = noise_certificate(&local, binding, Role::Responder, &key).unwrap();
    let verify = |peer: &str, role, key: &[u8], cert: &[u8]| {
        verify_noise_identity(peer, binding, role, Some(key), cert)
    };
    verify(local.peer_id(), Role::Responder, &key, &cert).unwrap();
    assert!(verify(other.peer_id(), Role::Responder, &key, &cert).is_err());
    assert!(verify(local.peer_id(), Role::Initiator, &key, &cert).is_err());
    assert!(verify(local.peer_id(), Role::Responder, &[99; 32], &cert).is_err());
    assert!(verify(local.peer_id(), Role::Responder, &key, &[0; 72]).is_err());
}
