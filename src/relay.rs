//! Pure relay logic shared by the async tasks: untagging, kind counters, and
//! the rate limiter. Nothing here touches the OS, so it is unit-testable on
//! any host.
use crate::proto::{
    Counter,
    parse::{self, Vlan},
};

/// Strip the management VLAN tag before injection. `classify` has already
/// guaranteed exactly one of the two representations, so this cannot
/// misparse.
pub fn untag(frame: &[u8], vlan: Vlan) -> Vec<u8> {
    if vlan.present {
        // Offload already lifted the tag into metadata; bytes are untagged.
        frame.to_vec()
    } else {
        // Remove the inline 4-byte tag (TPID+TCI at 12..16); the RRB
        // EtherType that followed it becomes the frame's EtherType.
        let mut out = Vec::with_capacity(frame.len() - parse::VLAN_TAG_LEN);
        out.extend_from_slice(&frame[..parse::ETH_TYPE_OFFSET]);
        out.extend_from_slice(&frame[parse::ETH_TYPE_OFFSET + parse::VLAN_TAG_LEN..]);
        out
    }
}

/// Map an RRB message type to its counter slot.
pub fn kind_counter(kind: u8) -> Counter {
    match kind {
        parse::KIND_PULL => Counter::Pull,
        parse::KIND_RESPONSE => Counter::Response,
        parse::KIND_PUSH => Counter::Push,
        parse::KIND_SEQ_REQUEST => Counter::SeqRequest,
        _ => Counter::SeqResponse,
    }
}

/// Human-readable name of an RRB message type, for logs.
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        parse::KIND_PULL => "pull",
        parse::KIND_RESPONSE => "response",
        parse::KIND_PUSH => "push",
        parse::KIND_SEQ_REQUEST => "seq_request",
        parse::KIND_SEQ_RESPONSE => "seq_response",
        _ => "unknown",
    }
}

/// "xx:xx:xx:xx:xx:xx", lowercase hex.
pub fn mac_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Fixed-window (not token bucket) rate limiter. Pure over a seconds counter
/// so it is trivially testable; the daemon feeds it monotonic seconds.
pub struct Limiter {
    window: u64,
    used: u64,
    per_second: u32,
}

impl Limiter {
    pub fn new(per_second: u32) -> Self {
        Self {
            window: u64::MAX, // forces a reset on the first admit
            used: 0,
            per_second,
        }
    }

    pub fn admit(&mut self, now_secs: u64) -> Result<(), Counter> {
        if self.window != now_secs {
            self.window = now_secs;
            self.used = 0;
        }
        if self.used >= u64::from(self.per_second) {
            return Err(Counter::RateLimited);
        }
        self.used += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::parse::TPID_8021Q;

    #[test]
    fn untag_removes_inline_tag() {
        // dst, src, TPID, TCI(VID 1), EtherType RRB, body
        let tagged = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x81, 0x00, 0x00, 0x01, 0x88, 0xb7, 0xaa, 0xbb,
        ];
        let out = untag(
            &tagged,
            Vlan::default(), // not present: tag is inline
        );
        let mut expected = vec![];
        expected.extend_from_slice(&tagged[..12]);
        expected.extend_from_slice(&tagged[16..]);
        assert_eq!(out, expected);
        assert_eq!(&out[12..14], &[0x88, 0xb7]); // EtherType is now RRB
    }

    #[test]
    fn untag_passthrough_when_tag_in_metadata() {
        let frame = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x88, 0xb7, 0xaa];
        let vlan = Vlan {
            present: true,
            proto: TPID_8021Q,
            tci: 1,
        };
        assert_eq!(untag(&frame, vlan), frame);
    }

    #[test]
    fn limiter_windows() {
        let mut l = Limiter::new(2);
        // window 1: two admits, third is rate-limited
        assert!(l.admit(1).is_ok());
        assert!(l.admit(1).is_ok());
        assert_eq!(l.admit(1), Err(Counter::RateLimited));
        // window 2: fresh allowance
        assert!(l.admit(2).is_ok());
        assert!(l.admit(2).is_ok());
        assert_eq!(l.admit(2), Err(Counter::RateLimited));
        // window 3: allowance resets again, forever
        assert!(l.admit(3).is_ok());
    }
}
