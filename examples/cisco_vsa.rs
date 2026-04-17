/// Demonstrates building RADIUS packets that include Cisco Vendor-Specific
/// Attributes (VSAs) using the high-level dict helpers, then verifies that an
/// encode → wire bytes → decode roundtrip preserves every value.
use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::dict::{cisco, rfc2865};

fn main() {
    let secret = b"testing123";

    // ── Access-Request with string Cisco VSAs ────────────────────────────
    let mut request = Packet::new(Code::AccessRequest, secret);

    // Standard RFC 2865 attribute.
    rfc2865::add_user_name(&mut request, "alice");

    // Cisco-AVPair (vendor 9, sub-type 1): multiple values are allowed.
    cisco::add_cisco_av_pair(&mut request, "shell:priv-lvl=15");
    cisco::add_cisco_av_pair(&mut request, "audit:event=login");

    // Cisco-NAS-Port (vendor 9, sub-type 2): string port identifier.
    cisco::add_cisco_nas_port(&mut request, "GigabitEthernet0/1");

    // Encode to wire format and decode back.
    let wire = request.encode().unwrap();
    let decoded = Packet::decode(&wire, secret).unwrap();

    let user = rfc2865::lookup_user_name(&decoded).unwrap().unwrap();
    println!("User-Name:          {user}");

    let first_av_pair = cisco::lookup_cisco_av_pair(&decoded).unwrap().unwrap();
    println!("Cisco-AVPair (1st): {first_av_pair}");

    let all_av_pairs = cisco::lookup_all_cisco_av_pair(&decoded).unwrap();
    println!("Cisco-AVPair (all): {all_av_pairs:?}");

    let nas_port = cisco::lookup_cisco_nas_port(&decoded).unwrap().unwrap();
    println!("Cisco-NAS-Port:     {nas_port}");

    assert_eq!(user, "alice");
    assert_eq!(first_av_pair, "shell:priv-lvl=15");
    assert_eq!(all_av_pairs, vec!["shell:priv-lvl=15", "audit:event=login"]);
    assert_eq!(nas_port, "GigabitEthernet0/1");

    // ── Accounting-Request with integer and value-typed Cisco VSAs ────────
    let mut acct = Packet::new(Code::AccountingRequest, secret);
    rfc2865::add_user_name(&mut acct, "alice");

    // Cisco-Multilink-ID (sub-type 187): plain u32 counter.
    cisco::add_cisco_multilink_id(&mut acct, 7);

    // Cisco-Disconnect-Cause (sub-type 195): named constant (Session-Timeout = 100).
    cisco::add_cisco_disconnect_cause(&mut acct, cisco::CISCO_DISCONNECT_CAUSE_SESSION_TIMEOUT);

    let wire2 = acct.encode().unwrap();
    let decoded2 = Packet::decode(&wire2, secret).unwrap();

    let multilink = cisco::lookup_cisco_multilink_id(&decoded2)
        .unwrap()
        .unwrap();
    println!("Cisco-Multilink-ID:     {multilink}");

    let cause = cisco::lookup_cisco_disconnect_cause(&decoded2)
        .unwrap()
        .unwrap();
    println!(
        "Cisco-Disconnect-Cause: {} (Session-Timeout = {})",
        cause,
        cisco::CISCO_DISCONNECT_CAUSE_SESSION_TIMEOUT,
    );

    assert_eq!(multilink, 7);
    assert_eq!(cause, cisco::CISCO_DISCONNECT_CAUSE_SESSION_TIMEOUT);

    println!("All assertions passed.");
}
