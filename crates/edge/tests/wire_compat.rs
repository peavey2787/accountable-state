//! The peer wire format is a compatibility contract: tags never change meaning, and what an older
//! or newer peer might send is refused cleanly, never mistaken for something else.
use gv_edge::live::PipeMsg;

#[test]
fn message_tags_keep_their_meaning() {
    assert_eq!(PipeMsg::AnchorReq.encode().unwrap(), vec![12]);
    assert_eq!(PipeMsg::Anchor(None).encode().unwrap(), vec![13]);
    assert!(matches!(PipeMsg::decode(&[12]), Ok(PipeMsg::AnchorReq)));
    assert!(matches!(PipeMsg::decode(&[13]), Ok(PipeMsg::Anchor(None))));
}

#[test]
fn unknown_empty_and_truncated_messages_are_refused_without_panicking() {
    assert!(PipeMsg::decode(&[]).is_err());
    assert!(PipeMsg::decode(&[0]).is_err());
    for newer in [16u8, 99, 255] {
        assert!(
            PipeMsg::decode(&[newer, 1, 2, 3]).is_err(),
            "tag {newer} is from a protocol this build does not speak"
        );
    }
    for tag in 1..=15u8 {
        let _ = PipeMsg::decode(&[tag]);
        let _ = PipeMsg::decode(&[tag, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }
}
