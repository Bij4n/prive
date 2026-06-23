//! Property tests: invariants that must hold for any input.

use prive::otp::{Algorithm, Encoder, Totp};
use proptest::prelude::*;

fn algorithm() -> impl Strategy<Value = Algorithm> {
    prop_oneof![
        Just(Algorithm::Sha1),
        Just(Algorithm::Sha256),
        Just(Algorithm::Sha512)
    ]
}

proptest! {
    #[test]
    fn totp_codes_have_exactly_the_requested_digits(
        secret in prop::collection::vec(any::<u8>(), 1..64),
        digits in 4u32..=10,
        period in 1u64..=300,
        time in any::<u32>(),
        alg in algorithm(),
    ) {
        let t = Totp::new(secret, period, Encoder::Digits(digits), alg).unwrap();
        let code = t.code_at(u64::from(time));
        prop_assert_eq!(code.len(), digits as usize);
        prop_assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn a_code_holds_for_its_whole_period(
        secret in prop::collection::vec(any::<u8>(), 1..32),
        period in 1u64..=120,
        step in 0u64..1_000_000,
    ) {
        let t = Totp::new(secret, period, Encoder::Digits(6), Algorithm::Sha1).unwrap();
        let start = step * period;
        prop_assert_eq!(t.code_at(start), t.code_at(start + period - 1));
    }
}

proptest! {
    #[test]
    fn otpauth_parsing_never_panics(s in ".{0,200}") {
        let _ = prive::otp::parse_otpauth(&s);
        let _ = prive::otp::parse_otpauth(&format!("otpauth://totp/x?{s}"));
        let _ = prive::otp::decode_base32(&s);
    }

    #[test]
    fn base32_round_trips(bytes in prop::collection::vec(any::<u8>(), 1..64)) {
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &bytes);
        prop_assert_eq!(prive::otp::decode_base32(&encoded), Some(bytes.clone()));
        prop_assert_eq!(prive::otp::decode_base32(&encoded.to_lowercase()), Some(bytes));
    }
}

proptest! {
    #[test]
    fn generated_passwords_keep_every_promise(
        length in 4usize..200,
        upper in any::<bool>(),
        digits in any::<bool>(),
        symbols in any::<bool>(),
        avoid in any::<bool>(),
        // A few letters and symbols: never a whole class.
        exclude in "[a-f!#$%]{0,6}",
    ) {
        let g = prive::generate::password(&prive::generate::CharsetSpec {
            length, upper, digits, symbols, avoid_ambiguous: avoid,
            exclude: exclude.clone(),
            ..Default::default()
        }).unwrap();
        prop_assert!(!g.value.chars().any(|c| exclude.contains(c)), "{}", g.value);
        prop_assert_eq!(g.value.chars().count(), length);
        prop_assert!(g.value.chars().any(|c| c.is_ascii_lowercase()));
        prop_assert_eq!(g.value.chars().any(|c| c.is_ascii_uppercase()), upper);
        prop_assert_eq!(g.value.chars().any(|c| c.is_ascii_digit()), digits);
        prop_assert_eq!(g.value.chars().any(|c| !c.is_ascii_alphanumeric()), symbols);
        if avoid {
            prop_assert!(!g.value.chars().any(|c| "0O1lI|".contains(c)));
        }
        prop_assert!(g.entropy_bits > 0.0);
    }
}

fn entries(titles: &[String]) -> Vec<prive::entry::Entry> {
    titles
        .iter()
        .enumerate()
        .map(|(i, t)| prive::entry::Entry {
            uuid: format!("{i:08}"),
            group: if i % 2 == 0 {
                "Work".into()
            } else {
                String::new()
            },
            title: t.clone(),
            ..prive::entry::Entry::default()
        })
        .collect()
}

proptest! {
    #[test]
    fn selection_finds_every_unique_path(titles in prop::collection::hash_set("[a-zA-Z0-9][a-zA-Z0-9 ]{0,11}", 1..20)) {
        let titles: Vec<String> = titles.into_iter().collect();
        let all = entries(&titles);
        for e in &all {
            // Paths are unique here; titles may collide case-insensitively, paths may not.
            match prive::select::select(&all, &e.path()) {
                Ok(found) => prop_assert_eq!(&found.uuid, &e.uuid),
                Err(prive::error::Failure::Ambiguous { .. }) => {}
                Err(other) => prop_assert!(false, "{other}"),
            }
            let by_uuid = prive::select::select(&all, &format!("uuid:{}", e.uuid)).unwrap();
            prop_assert_eq!(&by_uuid.uuid, &e.uuid);
        }
    }

    #[test]
    fn selection_and_search_never_panic(titles in prop::collection::vec(".{0,16}", 0..10), q in ".{0,16}") {
        let all = entries(&titles);
        let _ = prive::select::select(&all, &q);
        let _ = prive::select::search(&all, &q);
    }
}

proptest! {
    #[test]
    fn seconds_left_is_within_the_period(period in 1u64..=600) {
        let t = Totp::new(vec![7; 20], period, Encoder::Digits(6), Algorithm::Sha1).unwrap();
        let (_, left) = t.now();
        prop_assert!(left >= 1 && left <= period);
    }

    #[test]
    fn steam_codes_are_five_steam_letters(time in any::<u32>()) {
        let t = Totp::new(vec![3; 20], 30, Encoder::Steam, Algorithm::Sha1).unwrap();
        let code = t.code_at(u64::from(time));
        prop_assert_eq!(code.len(), 5);
        prop_assert!(code.bytes().all(|b| b"23456789BCDFGHJKMNPQRTVWXY".contains(&b)));
    }
}

proptest! {
    #[test]
    fn csv_imports_never_panic(text in ".{0,400}") {
        let _ = prive::import::google::parse(&text);
        let _ = prive::import::apple::parse(&text);
        let _ = prive::import::google::parse(&format!("name,url,username,password,note\n{text}"));
        let _ = prive::import::apple::parse(&format!("Title,URL,Username,Password,Notes,OTPAuth\n{text}"));
    }
}

proptest! {
    /// What the agent sends is what the client gets back, for any entry contents.
    #[test]
    fn entries_cross_the_agent_wire_unchanged(
        title in ".{0,20}", user in ".{0,20}", pw in ".{0,40}", notes in ".{0,80}",
        tags in prop::collection::vec("[a-z]{1,8}", 0..4),
        file in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        use prive::agent::proto::WireEntry;
        use prive::entry::{Attachment, Entry};
        use zeroize::Zeroizing;
        let e = Entry {
            uuid: "u".into(),
            title: title.clone(),
            username: user.clone(),
            password: Zeroizing::new(pw.clone()),
            notes: notes.clone(),
            tags: tags.clone(),
            attachments: vec![Attachment { name: "f".into(), data: Zeroizing::new(file.clone()) }],
            ..Entry::default()
        };
        let json = serde_json::to_string(&WireEntry::from(&e)).unwrap();
        let back = Entry::from(serde_json::from_str::<WireEntry>(&json).unwrap());
        prop_assert_eq!(back.title, title);
        prop_assert_eq!(back.username, user);
        prop_assert_eq!(back.password.as_str(), pw.as_str());
        prop_assert_eq!(back.notes, notes);
        prop_assert_eq!(back.tags, tags);
        prop_assert_eq!(&back.attachments[0].data[..], &file[..]);
    }
}

proptest! {
    /// Any text, with any references in it, resolves without panicking and without looping.
    #[test]
    fn references_always_resolve_or_stay(
        value in "(\\{REF:[TUPANI@:A-Za-z0-9]{0,12}\\}|[a-z {}:@]){0,12}",
        titles in prop::collection::vec("[A-Za-z]{1,6}", 1..5),
    ) {
        let entries: Vec<prive::entry::Entry> = titles
            .iter()
            .enumerate()
            .map(|(i, t)| prive::entry::Entry {
                uuid: format!("{i:032x}"),
                title: t.clone(),
                // Each password refers to the next entry's, the last back to the first.
                password: zeroize::Zeroizing::new(format!("{{REF:P@T:{}}}", titles[(i + 1) % titles.len()])),
                ..prive::entry::Entry::default()
            })
            .collect();
        let _ = prive::refs::resolve(&entries, &value);
        for e in &entries {
            let _ = prive::refs::resolve(&entries, &e.password);
        }
    }
}

/// Entries with distinct UUIDs and arbitrary titles and passwords, for diff.
fn diff_side(
    keys: &std::collections::BTreeSet<u16>,
    seed: &[(String, String)],
) -> Vec<prive::entry::Entry> {
    keys.iter()
        .zip(seed.iter().cycle())
        .map(|(k, (title, pw))| prive::entry::Entry {
            uuid: format!("{k:032x}"),
            title: title.clone(),
            password: zeroize::Zeroizing::new(pw.clone()),
            ..Default::default()
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]
    #[test]
    fn a_copy_has_no_differences_with_itself(
        keys in prop::collection::btree_set(any::<u16>(), 0..30),
        seed in prop::collection::vec((".{0,8}", ".{0,8}"), 1..5),
    ) {
        let a = diff_side(&keys, &seed);
        prop_assert!(prive::diff::compare(&a, &a.clone()).is_empty());
    }

    #[test]
    fn swapping_the_copies_swaps_the_sides(
        here in prop::collection::btree_set(any::<u16>(), 0..30),
        there in prop::collection::btree_set(any::<u16>(), 0..30),
        seed in prop::collection::vec((".{0,8}", ".{0,8}"), 1..5),
        other in prop::collection::vec((".{0,8}", ".{0,8}"), 1..5),
    ) {
        use prive::diff::Kind;
        let (a, b) = (diff_side(&here, &seed), diff_side(&there, &other));
        let count = |d: &[prive::diff::Difference], k: Kind| d.iter().filter(|x| x.kind == k).count();
        let ab = prive::diff::compare(&a, &b);
        let ba = prive::diff::compare(&b, &a);
        prop_assert_eq!(count(&ab, Kind::OnlyHere), count(&ba, Kind::OnlyThere));
        prop_assert_eq!(count(&ab, Kind::OnlyThere), count(&ba, Kind::OnlyHere));
        prop_assert_eq!(count(&ab, Kind::Changed), count(&ba, Kind::Changed));
        prop_assert_eq!(count(&ab, Kind::OnlyHere), here.difference(&there).count());
    }
}
