use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufWriter, Write};
use std::path::Path;
use std::str::FromStr;
use std::{io, process};

use heck::{ToPascalCase, ToShoutySnakeCase, ToSnakeCase};
use regex::Regex;

const ATTRIBUTE_KIND: &str = "ATTRIBUTE";
const VALUE_KIND: &str = "VALUE";
const VENDOR_KIND: &str = "VENDOR";
const BEGIN_VENDOR_KIND: &str = "BEGIN-VENDOR";
const END_VENDOR_KIND: &str = "END-VENDOR";

const RADIUS_VALUE_TYPE: &str = "u32";

const USER_PASSWORD_TYPE_OPT: &str = "encrypt=1";
const TUNNEL_PASSWORD_TYPE_OPT: &str = "encrypt=2";
const HAS_TAG_TYPE_OPT: &str = "has_tag";
const CONCAT_TYPE_OPT: &str = "concat";

#[derive(Debug)]
enum EncryptionType {
    UserPassword,
    TunnelPassword,
}

#[derive(Debug)]
struct RadiusAttribute {
    name: String,
    /// For standard attributes, the RADIUS AVP type (1–255).
    /// For VSA sub-attributes, the vendor-type byte.
    typ: u8,
    value_type: RadiusAttributeValueType,
    fixed_octets_length: Option<usize>,
    concat_octets: bool,
    has_tag: bool,
    /// Set when this attribute is inside a BEGIN-VENDOR / END-VENDOR block.
    vendor_id: Option<u32>,
    /// Comment lines from the dictionary that immediately precede this attribute.
    comment: Vec<String>,
}

#[derive(Debug)]
struct RadiusValue {
    name: String,
    value: u16,
    /// Comment lines from the dictionary that immediately precede this value.
    comment: Vec<String>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
enum RadiusAttributeValueType {
    String,
    UserPassword,
    TunnelPassword,
    Octets,
    IpAddr,
    Ipv4Prefix,
    Ipv6Addr,
    Ipv6Prefix,
    IfId,
    Date,
    Integer,
    Short,
    VSA,
}

impl FromStr for RadiusAttributeValueType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "string" => Ok(RadiusAttributeValueType::String),
            "octets" | "abinary" | "byte" | "tlv" => Ok(RadiusAttributeValueType::Octets),
            "ipaddr" => Ok(RadiusAttributeValueType::IpAddr),
            "ipv4prefix" => Ok(RadiusAttributeValueType::Ipv4Prefix),
            "ipv6addr" => Ok(RadiusAttributeValueType::Ipv6Addr),
            "ipv6prefix" => Ok(RadiusAttributeValueType::Ipv6Prefix),
            "ifid" => Ok(RadiusAttributeValueType::IfId),
            "date" => Ok(RadiusAttributeValueType::Date),
            "integer" | "uint32" => Ok(RadiusAttributeValueType::Integer),
            "short" => Ok(RadiusAttributeValueType::Short),
            "vsa" => Ok(RadiusAttributeValueType::VSA),
            _ => Err(()),
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

/// Generate RADIUS dictionary modules into `out_dir` from the given dict files.
///
/// Also writes `out_dir/mod.rs` declaring every generated module as `pub mod`.
/// Works correctly when `dict_file_paths` is sorted (cross-module value references
/// are emitted in declaration order).
///
/// # Panics
///
/// Panics if `out_dir` cannot be created, if any dict file cannot be parsed,
/// or if writing any output file fails.
pub fn generate(out_dir: &Path, dict_file_paths: &[&Path]) {
    std::fs::create_dir_all(out_dir).unwrap_or_else(|e| {
        panic!(
            "failed to create output directory {}: {e}",
            out_dir.display()
        )
    });

    let mut rfc_names: Vec<String> = Vec::new();
    let mut attribute_name_to_rfc_name: HashMap<String, String> = HashMap::new();

    for dict_file_path in dict_file_paths {
        let (radius_attributes, radius_attribute_to_values_map) =
            parse_dict_file(dict_file_path).unwrap();

        let value_defined_attributes_set = radius_attribute_to_values_map
            .keys()
            .collect::<HashSet<&String>>();

        // Only import dict modules that are actually referenced (cross-module value types)
        let needed_rfc_names: Vec<String> = rfc_names
            .iter()
            .filter(|name| {
                radius_attribute_to_values_map.keys().any(|attr| {
                    attribute_name_to_rfc_name
                        .get(attr)
                        .is_some_and(|r| r == *name)
                })
            })
            .cloned()
            .collect();

        let rfc_name = dict_file_path.extension().unwrap().to_str().unwrap();
        let mut w = BufWriter::new(File::create(out_dir.join(format!("{rfc_name}.rs"))).unwrap());

        generate_header(&mut w, &needed_rfc_names, rfc_name, &radius_attributes);
        generate_attributes_code(&mut w, &radius_attributes, &value_defined_attributes_set);
        generate_values_code(
            &mut w,
            &radius_attribute_to_values_map,
            &attribute_name_to_rfc_name,
        );

        for attr in &radius_attributes {
            attribute_name_to_rfc_name.insert(attr.name.clone(), rfc_name.to_owned());
        }
        rfc_names.push(rfc_name.to_owned());
    }

    // Write mod.rs
    let mut mod_w = BufWriter::new(File::create(out_dir.join("mod.rs")).unwrap());
    mod_w
        .write_all(b"// Code generated by machine generator; DO NOT EDIT.\n\n//! Generated RADIUS dictionary modules.\n\n")
        .unwrap();
    for name in &rfc_names {
        mod_w
            .write_all(format!("pub mod {name};\n").as_bytes())
            .unwrap();
    }

    // Format all generated files
    let mut files_to_fmt: Vec<_> = rfc_names
        .iter()
        .map(|name| out_dir.join(format!("{name}.rs")))
        .collect();
    files_to_fmt.push(out_dir.join("mod.rs"));

    let status = process::Command::new("rustfmt")
        .arg("--edition=2021")
        .args(&files_to_fmt)
        .status()
        .unwrap_or_else(|e| panic!("failed to run rustfmt: {e}"));
    if !status.success() {
        process::exit(status.code().unwrap_or(1));
    }
}

fn generate_header(
    w: &mut BufWriter<File>,
    rfc_names: &[String],
    rfc_name: &str,
    attrs: &[RadiusAttribute],
) {
    let needs_ipv4 = attrs
        .iter()
        .any(|a| matches!(a.value_type, RadiusAttributeValueType::IpAddr));
    let needs_ipv6 = attrs
        .iter()
        .any(|a| matches!(a.value_type, RadiusAttributeValueType::Ipv6Addr));
    let needs_system_time = attrs
        .iter()
        .any(|a| matches!(a.value_type, RadiusAttributeValueType::Date));

    // Standard attributes: not inside a vendor block and not the raw VSA container type.
    let has_standard_attrs = attrs
        .iter()
        .any(|a| a.vendor_id.is_none() && !matches!(a.value_type, RadiusAttributeValueType::VSA));
    // VSA sub-attributes: inside a BEGIN-VENDOR / END-VENDOR block.
    let has_vsa_attrs = attrs.iter().any(|a| a.vendor_id.is_some());

    let needs_avp_error_standard = attrs.iter().any(|a| {
        a.vendor_id.is_none()
            && match &a.value_type {
                RadiusAttributeValueType::VSA => false,
                RadiusAttributeValueType::Octets => a.fixed_octets_length.is_some(),
                _ => true,
            }
    });
    let needs_avp_error_vsa = attrs.iter().any(|a| {
        a.vendor_id.is_some()
            && match &a.value_type {
                RadiusAttributeValueType::VSA => false,
                RadiusAttributeValueType::Octets => a.fixed_octets_length.is_some(),
                _ => true,
            }
    });
    let needs_avp_error = needs_avp_error_standard || needs_avp_error_vsa;

    let needs_tag = attrs
        .iter()
        .any(|a| a.has_tag || matches!(a.value_type, RadiusAttributeValueType::TunnelPassword));

    let net_import = match (needs_ipv4, needs_ipv6) {
        (true, true) => "use std::net::{Ipv4Addr, Ipv6Addr};\n\n",
        (true, false) => "use std::net::Ipv4Addr;\n\n",
        (false, true) => "use std::net::Ipv6Addr;\n\n",
        (false, false) => "",
    };
    let time_import = if needs_system_time {
        "use std::time::SystemTime;\n\n"
    } else {
        ""
    };
    // Determine which avp items to import.
    // AVPType is only needed for standard (non-vendor) attribute constants.
    let avp_import = match (
        has_standard_attrs || has_vsa_attrs,
        has_standard_attrs,
        needs_avp_error,
    ) {
        (false, _, _) => "",
        (true, true, true) => "use crate::core::avp::{AVP, AVPType, AVPError};\n",
        (true, true, false) => "use crate::core::avp::{AVP, AVPType};\n",
        (true, false, true) => "use crate::core::avp::{AVP, AVPError};\n",
        (true, false, false) => "use crate::core::avp::AVP;\n",
    };
    let packet_import = if has_standard_attrs || has_vsa_attrs {
        "use crate::core::packet::Packet;\n"
    } else {
        ""
    };
    let tag_import = if needs_tag {
        "use crate::core::tag::Tag;\n"
    } else {
        ""
    };

    let code = format!(
        "// Code generated by machine generator; DO NOT EDIT.
// Clippy: `#[must_use]` on functions returning `Option`/`Result` is intentional even though
// those types are already `#[must_use]`; the attribute surfaces better IDE messages.
#![allow(clippy::double_must_use)]

//! Utility for {rfc_name} packet.

{net_import}{time_import}{avp_import}{packet_import}{tag_import}
",
    );

    w.write_all(code.as_bytes()).unwrap();

    for rfc_name in rfc_names {
        w.write_all(format!("use crate::dict::{rfc_name};\n").as_bytes())
            .unwrap();
    }
}

fn generate_values_code(
    w: &mut BufWriter<File>,
    attr_to_values_map: &BTreeMap<String, Vec<RadiusValue>>,
    attr_name_to_rfc_name: &HashMap<String, String>,
) {
    for (attr, values) in attr_to_values_map {
        generate_values_for_attribute_code(w, attr, values, attr_name_to_rfc_name.get(attr));
    }
}

/// Emit dictionary comment lines as Rust inline comments (`//`).
///
/// Each raw dictionary line (starting with `#`) is stripped of its leading `#` and
/// emitted as a `//` line so the context is visible to source readers.
fn emit_comment(w: &mut BufWriter<File>, comments: &[String]) {
    for line in comments {
        let stripped = line.strip_prefix('#').unwrap_or("").trim_end();
        writeln!(w, "//{stripped}").unwrap();
    }
}

fn generate_values_for_attribute_code(
    w: &mut BufWriter<File>,
    attr: &str,
    values: &[RadiusValue],
    maybe_rfc_name: Option<&String>,
) {
    let type_name = attr.to_pascal_case();

    if maybe_rfc_name.is_none() {
        w.write_all(format!("\npub type {type_name} = {RADIUS_VALUE_TYPE};\n").as_bytes())
            .unwrap();
    }

    for v in values {
        emit_comment(w, &v.comment);
        if let Some(rfc_name) = maybe_rfc_name {
            w.write_all(
                format!(
                "pub const {type_name_prefix}_{value_name}: {rfc_name}::{type_name} = {value};\n",
                type_name_prefix = type_name.to_shouty_snake_case(),
                value_name = v.name.to_shouty_snake_case(),
                rfc_name = rfc_name,
                type_name = type_name,
                value = v.value,
            )
                .as_bytes(),
            )
            .unwrap();
        } else {
            w.write_all(
                format!(
                    "pub const {type_name_prefix}_{value_name}: {type_name} = {value};\n",
                    type_name_prefix = type_name.to_shouty_snake_case(),
                    value_name = v.name.to_shouty_snake_case(),
                    type_name = type_name,
                    value = v.value,
                )
                .as_bytes(),
            )
            .unwrap();
        }
    }
    w.write_all(b"\n").unwrap();
}

fn generate_attributes_code(
    w: &mut BufWriter<File>,
    attrs: &[RadiusAttribute],
    value_defined_attributes_set: &HashSet<&String>,
) {
    for attr in attrs {
        generate_attribute_code(w, attr, value_defined_attributes_set);
    }
}

#[allow(clippy::too_many_lines)]
fn generate_attribute_code(
    w: &mut BufWriter<File>,
    attr: &RadiusAttribute,
    value_defined_attributes_set: &HashSet<&String>,
) {
    let attr_name = attr.name.clone();
    let method_identifier = attr_name.to_snake_case();
    emit_comment(w, &attr.comment);

    if let Some(vendor_id) = attr.vendor_id {
        // VSA sub-attribute: use a VENDOR_TYPE constant (u8) and VSA-aware generators.
        let type_identifier = format!("{}_VENDOR_TYPE", attr_name.to_shouty_snake_case());
        generate_common_attribute_code(w, &attr_name, &type_identifier, attr.typ, Some(vendor_id));
        match attr.value_type {
            RadiusAttributeValueType::String => {
                generate_vsa_string_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::UserPassword => {
                generate_vsa_user_password_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::TunnelPassword => {
                // Tagged tunnel-password in VSA context is uncommon; treat as plain octets.
                generate_vsa_octets_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::Octets => {
                if let Some(fixed_len) = attr.fixed_octets_length {
                    generate_vsa_fixed_length_octets_attribute_code(
                        w,
                        &method_identifier,
                        &type_identifier,
                        vendor_id,
                        fixed_len,
                    );
                } else {
                    generate_vsa_octets_attribute_code(
                        w,
                        &method_identifier,
                        &type_identifier,
                        vendor_id,
                    );
                }
            }
            RadiusAttributeValueType::IpAddr => {
                generate_vsa_ipaddr_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::Ipv4Prefix => {
                generate_vsa_ipv4_prefix_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::Ipv6Addr => {
                generate_vsa_ipv6addr_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::Ipv6Prefix => {
                generate_vsa_ipv6_prefix_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::IfId => {
                generate_vsa_fixed_length_octets_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                    8,
                );
            }
            RadiusAttributeValueType::Date => {
                generate_vsa_date_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::Integer => {
                if value_defined_attributes_set.contains(&attr_name) {
                    generate_vsa_value_defined_integer_attribute_code(
                        w,
                        &method_identifier,
                        &type_identifier,
                        vendor_id,
                        &attr_name.to_pascal_case(),
                    );
                } else {
                    generate_vsa_integer_attribute_code(
                        w,
                        &method_identifier,
                        &type_identifier,
                        vendor_id,
                    );
                }
            }
            RadiusAttributeValueType::Short => {
                generate_vsa_short_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    vendor_id,
                );
            }
            RadiusAttributeValueType::VSA => {
                // A vendor sub-attribute of type VSA is unusual; skip.
            }
        }
        return;
    }

    // Standard (non-vendor) attribute path — unchanged from before.
    let type_identifier = format!("{}_TYPE", attr_name.to_shouty_snake_case());
    let type_value = attr.typ;

    generate_common_attribute_code(w, &attr_name, &type_identifier, type_value, None);
    match attr.value_type {
        RadiusAttributeValueType::String => {
            if attr.has_tag {
                generate_tagged_string_attribute_code(w, &method_identifier, &type_identifier);
            } else {
                generate_string_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::UserPassword => {
            if attr.has_tag {
                unimplemented!("tagged-user-password");
            } else {
                generate_user_password_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::TunnelPassword => {
            if attr.has_tag {
                generate_tunnel_password_attribute_code(w, &method_identifier, &type_identifier);
            } else {
                unimplemented!("tunnel-password");
            }
        }
        RadiusAttributeValueType::Octets => {
            if attr.has_tag {
                unimplemented!("tagged-octets");
            } else if let Some(fixed_octets_length) = attr.fixed_octets_length {
                generate_fixed_length_octets_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    fixed_octets_length,
                );
            } else if attr.concat_octets {
                generate_concat_octets_attribute_code(w, &method_identifier, &type_identifier);
            } else {
                generate_octets_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::IpAddr => {
            if attr.has_tag {
                unimplemented!("tagged-ip-addr");
            } else {
                generate_ipaddr_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::Ipv4Prefix => {
            if attr.has_tag {
                unimplemented!("tagged-ip-addr");
            } else {
                generate_ipv4_prefix_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::Ipv6Addr => {
            if attr.has_tag {
                unimplemented!("tagged-ip-v6-addr");
            } else {
                generate_ipv6addr_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::Ipv6Prefix => {
            if attr.has_tag {
                unimplemented!("tagged-ipv6-prefix");
            } else {
                generate_ipv6_prefix_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::IfId => {
            if attr.has_tag {
                unimplemented!("tagged-ifid");
            } else {
                generate_fixed_length_octets_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    8,
                );
            }
        }
        RadiusAttributeValueType::Date => {
            if attr.has_tag {
                unimplemented!("tagged-date");
            } else {
                generate_date_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::Integer => {
            if value_defined_attributes_set.contains(&attr_name) {
                if attr.has_tag {
                    generate_tagged_value_defined_integer_attribute_code(
                        w,
                        &method_identifier,
                        &type_identifier,
                        &attr_name.to_pascal_case(),
                    );
                } else {
                    generate_value_defined_integer_attribute_code(
                        w,
                        &method_identifier,
                        &type_identifier,
                        &attr_name.to_pascal_case(),
                    );
                }
            } else if attr.has_tag {
                generate_tagged_integer_attribute_code(w, &method_identifier, &type_identifier);
            } else {
                generate_integer_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::Short => {
            if attr.has_tag {
                unimplemented!("tagged-short");
            } else {
                generate_short_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::VSA => generate_vsa_attribute_code(),
    }
}

fn generate_common_attribute_code(
    w: &mut BufWriter<File>,
    attr_name: &str,
    type_identifier: &str,
    type_value: u8,
    vendor_id: Option<u32>,
) {
    let method_identifier = attr_name.to_snake_case();
    let code = if let Some(vid) = vendor_id {
        format!(
            "
pub const {type_identifier}: u8 = {type_value};
/// Delete all of `{method_identifier}` values from a packet.
pub fn delete_{method_identifier}(packet: &mut Packet) {{
    packet.delete_vsa({vid}_u32, {type_identifier});
}}
",
        )
    } else {
        format!(
            "
pub const {type_identifier}: AVPType = {type_value};
/// Delete all of `{method_identifier}` values from a packet.
pub fn delete_{method_identifier}(packet: &mut Packet) {{
    packet.delete({type_identifier});
}}
",
        )
    };
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_string_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` string value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &str) {{
    let avp = AVP::from_string_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` string value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<String, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_string)
}}
/// Lookup all of the `{method_identifier}` string value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<String>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_string()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_tagged_string_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` tagged string value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, tag: Option<&Tag>, value: &str) {{
    let avp = AVP::from_tagged_string_in(packet.avp_buf(), {type_identifier}, tag, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` tagged string value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<(String, Option<Tag>), AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_tagged_string)
}}
/// Lookup all of the `{method_identifier}` tagged string value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<(String, Option<Tag>)>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_tagged_string()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_user_password_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` user-password value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if encoding the user-password value fails.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    let secret = packet.secret().to_owned();
    let authenticator = packet.authenticator().to_owned();
    let avp = AVP::from_user_password_in(packet.avp_buf(), {type_identifier}, value, &secret, &authenticator)?;
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` user-password value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Vec<u8>, AVPError>> {{
    packet.lookup({type_identifier}).map(|v| v.encode_user_password(packet.secret(), packet.authenticator()))
}}
/// Lookup all of the `{method_identifier}` user-password value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Vec<u8>>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_user_password(packet.secret(), packet.authenticator())?);
    }}
    Ok(vec)
}}
");
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_tunnel_password_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` tunnel-password value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if encoding the tunnel-password value fails.
pub fn add_{method_identifier}(packet: &mut Packet, tag: Option<&Tag>, value: &[u8]) -> Result<(), AVPError> {{
    let secret = packet.secret().to_owned();
    let authenticator = packet.authenticator().to_owned();
    let avp = AVP::from_tunnel_password_in(packet.avp_buf(), {type_identifier}, tag, value, &secret, &authenticator)?;
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` tunnel-password value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<(Vec<u8>, Tag), AVPError>> {{
    packet.lookup({type_identifier}).map(|v| v.encode_tunnel_password(packet.secret(), packet.authenticator()))
}}
/// Lookup all of the `{method_identifier}` tunnel-password value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<(Vec<u8>, Tag)>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_tunnel_password(packet.secret(), packet.authenticator())?);
    }}
    Ok(vec)
}}
");
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_octets_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` octets value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) {{
    let avp = AVP::from_bytes_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` octets value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Box<[u8]>> {{
    packet.lookup({type_identifier}).map(AVP::encode_bytes)
}}
/// Lookup all of the `{method_identifier}` octets value from a packet.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Vec<Box<[u8]>> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_bytes());
    }}
    vec
}}
");
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_concat_octets_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) {{
    for chunk in value.chunks(253) {{
        let avp = AVP::from_bytes_in(packet.avp_buf(), {type_identifier}, chunk);
        packet.add(avp);
    }}
}}
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Vec<u8>> {{
    let avps = packet.lookup_all({type_identifier});
    if avps.is_empty() {{
        None
    }} else {{
        Some(avps.into_iter().fold(Vec::new(), |mut acc, v| {{
            acc.extend_from_slice(&v.encode_bytes());
            acc
        }}))
    }}
}}
"
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_fixed_length_octets_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    fixed_octets_length: usize,
) {
    let code = format!(
        "/// Add `{method_identifier}` fixed-length octets value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if `value` is not exactly `{fixed_octets_length}` bytes.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    if value.len() != {fixed_octets_length} {{
        return Err(AVPError::InvalidAttributeLengthError(\"{fixed_octets_length} bytes\".to_owned(), value.len()));
    }}
    let avp = AVP::from_bytes_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` fixed-length octets value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Box<[u8]>> {{
    packet.lookup({type_identifier}).map(AVP::encode_bytes)
}}
/// Lookup all of the `{method_identifier}` fixed-length octets value from a packet.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Vec<Box<[u8]>> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_bytes());
    }}
    vec
}}
"
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_ipaddr_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipaddr value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &Ipv4Addr) {{
    let avp = AVP::from_ipv4_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` ipaddr value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Ipv4Addr, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_ipv4)
}}
/// Lookup all of the `{method_identifier}` ipaddr value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Ipv4Addr>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_ipv4()?);
    }}
    Ok(vec)
}}
"
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_ipv4_prefix_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipv4 prefix value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if `value` is not exactly 4 bytes.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    let avp = AVP::from_ipv4_prefix_in(packet.avp_buf(), {type_identifier}, value)?;
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` ipv4 prefix value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Box<[u8]>, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_ipv4_prefix)
}}
/// Lookup all of the `{method_identifier}` ipv4 prefix value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Box<[u8]>>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_ipv4_prefix()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_ipv6addr_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipv6addr value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &Ipv6Addr) {{
    let avp = AVP::from_ipv6_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` ipv6addr value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Ipv6Addr, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_ipv6)
}}
/// Lookup all of the `{method_identifier}` ipv6addr value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Ipv6Addr>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_ipv6()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_ipv6_prefix_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipv6 prefix value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if `value` exceeds 16 bytes.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    let avp = AVP::from_ipv6_prefix_in(packet.avp_buf(), {type_identifier}, value)?;
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` ipv6 prefix value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Box<[u8]>, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_ipv6_prefix)
}}
/// Lookup all of the `{method_identifier}` ipv6 prefix value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Box<[u8]>>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_ipv6_prefix()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_date_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` date value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &SystemTime) {{
    let avp = AVP::from_date_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` date value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<SystemTime, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_date)
}}
/// Lookup all of the `{method_identifier}` date value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<SystemTime>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_date()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` integer value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: u32) {{
    let avp = AVP::from_u32_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<u32, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_u32)
}}
/// Lookup all of the `{method_identifier}` integer value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<u32>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_u32()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_tagged_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` tagged integer value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, tag: Option<&Tag>, value: u32) {{
    let avp = AVP::from_tagged_u32_in(packet.avp_buf(), {type_identifier}, tag, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` tagged integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<(u32, Tag), AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_tagged_u32)
}}
/// Lookup all of the `{method_identifier}` tagged integer value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<(u32, Tag)>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_tagged_u32()?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_value_defined_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    value_type: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` value-defined integer value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: {value_type}) {{
    let avp = AVP::from_u32_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` value-defined integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<{value_type}, AVPError>> {{
    packet.lookup({type_identifier}).map(|v| Ok(v.encode_u32()? as {value_type}))
}}
/// Lookup all of the `{method_identifier}` value-defined integer value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<{value_type}>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_u32()? as {value_type});
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_tagged_value_defined_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    value_type: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` tagged value-defined integer value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, tag: Option<&Tag>, value: {value_type}) {{
    let avp = AVP::from_tagged_u32_in(packet.avp_buf(), {type_identifier}, tag, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` tagged value-defined integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<({value_type}, Tag), AVPError>> {{
    packet.lookup({type_identifier}).map(|v| {{
        let (v, t) = v.encode_tagged_u32()?;
        Ok((v as {value_type}, t))
    }})
}}
/// Lookup all of the `{method_identifier}` tagged value-defined integer value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<({value_type}, Tag)>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        let (v, t) = avp.encode_tagged_u32()?;
        vec.push((v as {value_type}, t));
    }}
    Ok(vec)
}}
"
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_short_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` short integer value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: u16) {{
    let avp = AVP::from_u16_in(packet.avp_buf(), {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` short integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<u16, AVPError>> {{
    packet.lookup({type_identifier}).map(AVP::encode_u16)
}}
/// Lookup all of the `{method_identifier}` short integer value from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<u16>, AVPError> {{
    let avps = packet.lookup_all({type_identifier});
    let mut vec = Vec::with_capacity(avps.len());
    for avp in avps {{
        vec.push(avp.encode_u16()?);
    }}
    Ok(vec)
}}
"
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_attribute_code() {
    // NOP — the RFC 2865 type-26 "Vendor-Specific" container attribute has no generated methods.
}

// ── VSA sub-attribute generators ─────────────────────────────────────────────
// These emit add/lookup/lookup_all functions that encode/decode using
// AVP::from_vsa / Packet::lookup_vsa / Packet::lookup_all_vsa.

fn generate_vsa_string_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` string value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &str) {{
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, value.as_bytes());
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` string value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<String, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_string())
}}
/// Lookup all of the `{method_identifier}` string values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<String>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_string_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_user_password_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` user-password value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if encoding the user-password value fails.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    let secret = packet.secret().to_owned();
    let auth = packet.authenticator().to_owned();
    let encoded = AVP::from_user_password(0, value, &secret, &auth)?;;
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &encoded.encode_bytes());
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` user-password value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Vec<u8>, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| {{
            AVP::from_bytes(0, &payload)
                .encode_user_password(packet.secret(), packet.authenticator())
        }})
}}
/// Lookup all of the `{method_identifier}` user-password values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Vec<u8>>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_user_password_value(
            &payload,
            packet.secret(),
            packet.authenticator(),
        )?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_octets_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` octets value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) {{
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, value);
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` octets value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Box<[u8]>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|b| Box::from(b.as_ref()))
}}
/// Lookup all of the `{method_identifier}` octets values from a packet.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Vec<Box<[u8]>> {{
    packet
        .lookup_all_vsa({vendor_id}_u32, {type_identifier})
        .into_iter()
        .map(|b| Box::from(b.as_ref()))
        .collect()
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_fixed_length_octets_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
    fixed_octets_length: usize,
) {
    let code = format!(
        "/// Add `{method_identifier}` fixed-length octets value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if `value` is not exactly `{fixed_octets_length}` bytes.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    if value.len() != {fixed_octets_length} {{
        return Err(AVPError::InvalidAttributeLengthError(\"{fixed_octets_length} bytes\".to_owned(), value.len()));
    }}
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, value);
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` fixed-length octets value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Box<[u8]>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|b| Box::from(b.as_ref()))
}}
/// Lookup all of the `{method_identifier}` fixed-length octets values from a packet.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Vec<Box<[u8]>> {{
    packet
        .lookup_all_vsa({vendor_id}_u32, {type_identifier})
        .into_iter()
        .map(|b| Box::from(b.as_ref()))
        .collect()
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_ipaddr_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipaddr value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &Ipv4Addr) {{
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &value.octets());
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` ipaddr value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Ipv4Addr, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_ipv4())
}}
/// Lookup all of the `{method_identifier}` ipaddr values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Ipv4Addr>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_ipv4_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_ipv4_prefix_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipv4 prefix value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if `value` is not exactly 4 bytes.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    let tmp = AVP::from_ipv4_prefix(0, value)?;
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &tmp.encode_bytes());
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` ipv4 prefix value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Box<[u8]>, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_ipv4_prefix())
}}
/// Lookup all of the `{method_identifier}` ipv4 prefix values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Box<[u8]>>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_ipv4_prefix_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_ipv6addr_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipv6addr value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &Ipv6Addr) {{
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &value.octets());
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` ipv6addr value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Ipv6Addr, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_ipv6())
}}
/// Lookup all of the `{method_identifier}` ipv6addr values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Ipv6Addr>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_ipv6_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_ipv6_prefix_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` ipv6 prefix value to a packet.
///
/// # Errors
///
/// Returns an `AVPError` if `value` exceeds 16 bytes.
pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    let tmp = AVP::from_ipv6_prefix(0, value)?;
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &tmp.encode_bytes());
    packet.add(avp);
    Ok(())
}}
/// Lookup a `{method_identifier}` ipv6 prefix value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Box<[u8]>, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_ipv6_prefix())
}}
/// Lookup all of the `{method_identifier}` ipv6 prefix values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Box<[u8]>>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_ipv6_prefix_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_date_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` date value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: &SystemTime) {{
    let tmp = AVP::from_date(0, value);
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &tmp.encode_bytes());
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` date value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<SystemTime, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_date())
}}
/// Lookup all of the `{method_identifier}` date values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<SystemTime>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_date_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` integer value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: u32) {{
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &u32::to_be_bytes(value));
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<u32, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_u32())
}}
/// Lookup all of the `{method_identifier}` integer values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<u32>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_u32_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_value_defined_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
    value_type: &str,
) {
    let code = format!(
        "/// Add `{method_identifier}` integer value to a packet.
#[allow(clippy::unnecessary_cast)]
pub fn add_{method_identifier}(packet: &mut Packet, value: {value_type}) {{
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &u32::to_be_bytes(value as u32));
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<{value_type}, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_u32().map(|v| v as {value_type}))
}}
/// Lookup all of the `{method_identifier}` integer values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<{value_type}>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_u32_value(&payload)? as {value_type});
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_short_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    vendor_id: u32,
) {
    let code = format!(
        "/// Add `{method_identifier}` short integer value to a packet.
pub fn add_{method_identifier}(packet: &mut Packet, value: u16) {{
    let avp = AVP::from_vsa_in(packet.avp_buf(), {vendor_id}_u32, {type_identifier}, &u16::to_be_bytes(value));
    packet.add(avp);
}}
/// Lookup a `{method_identifier}` short integer value from a packet.
///
/// It returns the first looked up value. If there is no associated value with `{method_identifier}`, it returns `None`.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<u16, AVPError>> {{
    packet
        .lookup_vsa({vendor_id}_u32, {type_identifier})
        .map(|payload| AVP::from_bytes(0, &payload).encode_u16())
}}
/// Lookup all of the `{method_identifier}` short integer values from a packet.
///
/// # Errors
///
/// Returns an `AVPError` if decoding fails.
#[must_use]
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<u16>, AVPError> {{
    let payloads = packet.lookup_all_vsa({vendor_id}_u32, {type_identifier});
    let mut vec = Vec::with_capacity(payloads.len());
    for payload in payloads {{
        vec.push(AVP::encode_u16_value(&payload)?);
    }}
    Ok(vec)
}}
",
    );
    w.write_all(code.as_bytes()).unwrap();
}

type DictParsed = (Vec<RadiusAttribute>, BTreeMap<String, Vec<RadiusValue>>);

#[allow(clippy::too_many_lines)]
fn parse_dict_file(dict_file_path: &Path) -> Result<DictParsed, String> {
    let blank_re = Regex::new(r"^\s*$").unwrap();
    let comment_re = Regex::new(r"^#").unwrap();
    let ws_re = Regex::new(r"\s+").unwrap();
    let trailing_comment_re = Regex::new(r"\s*?#.+?$").unwrap();
    let fixed_length_octets_re = Regex::new(r"^octets\[(\d+)]$").unwrap();

    let mut radius_attributes: Vec<RadiusAttribute> = Vec::new();
    // Key is (vendor_id, attr_type) to allow same type numbers across different vendors.
    let mut seen_attribute_types: HashSet<(Option<u32>, u8)> = HashSet::new();
    let mut radius_attribute_to_values: BTreeMap<String, Vec<RadiusValue>> = BTreeMap::new();

    // Vendor tracking: name → numeric id, and the currently-active vendor block.
    let mut vendor_id_map: HashMap<String, u32> = HashMap::new();
    let mut current_vendor_id: Option<u32> = None;

    // Comment tracking: accumulate comment lines between data lines.
    // Blank lines clear the buffer, so file-level header comments (copyright etc.) that are
    // separated from the first attribute by a blank line are naturally discarded.
    let mut pending_comments: Vec<String> = Vec::new();

    let lines = read_lines(dict_file_path).unwrap();
    for line_result in lines {
        let line = line_result.unwrap();

        if blank_re.is_match(line.as_str()) {
            // Blank lines reset the pending comment buffer so that section headers
            // separated from the next item by a blank line are not attached.
            pending_comments.clear();
            continue;
        }

        if comment_re.is_match(line.as_str()) {
            pending_comments.push(line);
            continue;
        }

        let items = ws_re.split(line.as_str()).collect::<Vec<&str>>();

        if items.is_empty() {
            continue;
        }

        let kind = items[0];

        // Handle vendor control lines before the generic length check.
        match kind {
            VENDOR_KIND => {
                // VENDOR  vendor-name  number  [format=t,l]
                if items.len() >= 3 {
                    if let Ok(vid) = items[2].parse::<u32>() {
                        vendor_id_map.insert(items[1].to_string(), vid);
                    }
                }
                continue;
            }
            BEGIN_VENDOR_KIND => {
                // BEGIN-VENDOR  vendor-name
                if items.len() >= 2 {
                    current_vendor_id = vendor_id_map.get(items[1]).copied();
                }
                continue;
            }
            END_VENDOR_KIND => {
                current_vendor_id = None;
                continue;
            }
            _ => {}
        }

        if items.len() < 4 {
            return Err("the number of items is lacked in a line".to_owned());
        }

        match kind {
            ATTRIBUTE_KIND => {
                let mut encryption_type: Option<EncryptionType> = None;
                let mut has_tag = false;
                let mut concat_octets = false;
                if items.len() >= 5 {
                    for type_opt in items[4].split(',') {
                        if type_opt == USER_PASSWORD_TYPE_OPT {
                            encryption_type = Some(EncryptionType::UserPassword);
                        } else if type_opt == TUNNEL_PASSWORD_TYPE_OPT {
                            encryption_type = Some(EncryptionType::TunnelPassword);
                        } else if type_opt == HAS_TAG_TYPE_OPT {
                            has_tag = true;
                        } else if type_opt == CONCAT_TYPE_OPT {
                            concat_octets = true;
                        }
                    }
                }

                let (typ, fixed_octets_length) =
                    if let Ok(t) = RadiusAttributeValueType::from_str(items[3]) {
                        if t == RadiusAttributeValueType::String {
                            match encryption_type {
                                Some(EncryptionType::UserPassword) => {
                                    (RadiusAttributeValueType::UserPassword, None)
                                }
                                Some(EncryptionType::TunnelPassword) => {
                                    (RadiusAttributeValueType::TunnelPassword, None)
                                }
                                None => (t, None),
                            }
                        } else {
                            (t, None)
                        }
                    } else {
                        let maybe_cap = fixed_length_octets_re.captures(items[3]);
                        if let Some(cap) = maybe_cap {
                            (
                                RadiusAttributeValueType::Octets,
                                Some(cap.get(1).unwrap().as_str().parse::<usize>().unwrap()),
                            )
                        } else {
                            return Err(format!("invalid type has come => {}", items[3]));
                        }
                    };

                let parsed_typ: u8 = match items[2].parse() {
                    Ok(t) => t,
                    Err(_) => continue, // skip sub-attributes with dotted type IDs (e.g. "153.2")
                };
                if !seen_attribute_types.insert((current_vendor_id, parsed_typ)) {
                    continue; // skip duplicate attribute type numbers within the same scope
                }

                radius_attributes.push(RadiusAttribute {
                    name: items[1].to_string(),
                    typ: parsed_typ,
                    value_type: typ,
                    fixed_octets_length,
                    concat_octets,
                    has_tag,
                    vendor_id: current_vendor_id,
                    comment: std::mem::take(&mut pending_comments),
                });
            }
            VALUE_KIND => {
                let attribute_name = items[1].to_string();
                let name = items[2].to_string();

                let value = trailing_comment_re.replace(items[3], "").to_string();
                let parsed_value = if let Some(hex) = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                {
                    u16::from_str_radix(hex, 16).unwrap()
                } else {
                    value.parse().unwrap()
                };
                let radius_value = RadiusValue {
                    name,
                    value: parsed_value,
                    comment: std::mem::take(&mut pending_comments),
                };

                match radius_attribute_to_values.get_mut(&attribute_name) {
                    None => {
                        radius_attribute_to_values
                            .insert(attribute_name.clone(), vec![radius_value]);
                    }
                    Some(vec) => {
                        vec.push(radius_value);
                    }
                }
            }
            _ => return Err(format!("unexpected kind has come => {kind}")),
        }
    }

    Ok((radius_attributes, radius_attribute_to_values))
}
