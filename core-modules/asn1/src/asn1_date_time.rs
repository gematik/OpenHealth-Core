/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use regex::Regex;
use std::sync::OnceLock;
use crate::asn1_tag::{asn1_type};

use crate::asn1_decoder::ParserScope;
use crate::asn1_encoder::WriterScope;

/// Raw representation of an ASN.1 UTC_TIME.
/// If `offset` is `None` this indicates that the time is in UTC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1UtcTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: Option<i32>,
    pub offset: Option<Asn1Offset>, // corresponds to Asn1Offset.UtcOffset?
}

/// Raw representation of an ASN.1 GENERALIZED_TIME.
/// If `offset` is `None` this indicates that the time is in UTC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1GeneralizedTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: Option<i32>,
    pub second: Option<i32>,
    pub fraction_of_second: Option<i32>,
    pub offset: Option<Asn1Offset>,
}

/// Raw representation of an ASN.1 time offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Offset {
    /// UTC offset in hours and minutes.
    UtcOffset { hours: i32, minutes: i32 },
    /// Generalized offset in hours and minutes.
    GeneralizedOffset { hours: i32, minutes: i32 },
}

fn utc_time_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})")
            .expect("valid regex")
    })
}

fn generalized_time_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d{1,3})?(Z|[+-]\d{2}\d{2})?",
        )
            .expect("valid regex")
    })
}

/// Parses the offset string into an `Asn1Offset`.
///
/// The offset string can either be empty (no offset/UTC), 'Z' for UTC,
/// or '+/-HHMM' for a specific time zone offset.
fn parse_time_zone_or_offset(offset: &str) -> Option<Asn1Offset> {
    if offset.is_empty() || offset.as_bytes()[0] == b'Z' {
        None
    } else {
        let sign = if offset.as_bytes()[0] == b'-' { -1 } else { 1 };
        let hours: i32 = offset[1..3].parse().unwrap();
        let minutes: i32 = offset[3..5].parse().unwrap();
        Some(Asn1Offset::UtcOffset {
            hours: hours * sign,
            minutes,
        })
    }
}

/// Returns the `Asn1Offset` as a string.
fn format_offset(offset: &Option<Asn1Offset>) -> String {
    if offset.is_none() {
        "Z".to_string()
    } else {
        let (hours, minutes) = match offset.as_ref().unwrap() {
            Asn1Offset::UtcOffset { hours, minutes } => (*hours, *minutes),
            Asn1Offset::GeneralizedOffset { hours, minutes } => (*hours, *minutes),
        };
        let sign = if hours < 0 || minutes < 0 { "-" } else { "+" };
        format!(
            "{}{:02}{:02}",
            sign,
            hours.abs(),
            minutes.abs()
        )
    }
}

impl<'a> ParserScope<'a> {
    /// Parses a UTC time string into an `Asn1UtcTime`.
    fn parse_utc_time(&mut self, value: &str) -> Asn1UtcTime {
        let re = utc_time_regex();
        let caps = re.captures(value).unwrap_or_else(|| {
            self.fail(|| format!("Wrong utc time format: `{}`", value));
        });

        let yy = &caps[1];
        let mm = &caps[2];
        let dd = &caps[3];
        let hh = &caps[4];
        let min = &caps[5];
        let ss = caps.get(6).map(|m| m.as_str()).unwrap_or("");
        let offset = &caps[7];

        Asn1UtcTime {
            year: yy.parse::<i32>().unwrap(),
            month: mm.parse::<i32>().unwrap(),
            day: dd.parse::<i32>().unwrap(),
            hour: hh.parse::<i32>().unwrap(),
            minute: min.parse::<i32>().unwrap(),
            second: if ss.is_empty() { None } else { Some(ss.parse::<i32>().unwrap()) },
            offset: parse_time_zone_or_offset(offset),
        }
    }

    /// Parses a GENERALIZED_TIME string.
    fn parse_generalized_time(&mut self, value: &str) -> Asn1GeneralizedTime {
        let re = generalized_time_regex();
        let caps = re.captures(value).unwrap_or_else(|| {
            self.fail(|| format!("Wrong generalized time format: `{}`", value));
        });

        let yyyy = &caps[1];
        let mm = &caps[2];
        let dd = &caps[3];
        let hh = &caps[4];
        let min = caps.get(5).map(|m| m.as_str()).unwrap_or("");
        let ss = caps.get(6).map(|m| m.as_str()).unwrap_or("");
        let fff = caps.get(7).map(|m| m.as_str()).unwrap_or("");
        let offset = caps.get(8).map(|m| m.as_str()).unwrap_or("");

        Asn1GeneralizedTime {
            year: yyyy.parse::<i32>().unwrap(),
            month: mm.parse::<i32>().unwrap(),
            day: dd.parse::<i32>().unwrap(),
            hour: hh.parse::<i32>().unwrap(),
            minute: if min.is_empty() { None } else { Some(min.parse::<i32>().unwrap()) },
            second: if ss.is_empty() { None } else { Some(ss.parse::<i32>().unwrap()) },
            fraction_of_second: if fff.is_empty() {
                None
            } else {
                // drop the leading '.'
                Some(fff[1..].parse::<i32>().unwrap())
            },
            offset: parse_time_zone_or_offset(offset),
        }
    }

    /// Read ASN.1 `UTC_TIME`.
    pub fn read_utc_time(&mut self) -> Asn1UtcTime {
        self.advance_with_tag(asn1_type::UTC_TIME, 0x00, |s| {
            let len = s.remaining_length();
            let bytes = s.read_bytes(len);
            let value = String::from_utf8(bytes).unwrap();
            s.parse_utc_time(&value)
        })
    }

    /// Read ASN.1 `GENERALIZED_TIME`.
    pub fn read_generalized_time(&mut self) -> Asn1GeneralizedTime {
        self.advance_with_tag(asn1_type::GENERALIZED_TIME, 0x00, |s| {
            let len = s.remaining_length();
            let bytes = s.read_bytes(len);
            let value = String::from_utf8(bytes).unwrap();
            s.parse_generalized_time(&value)
        })
    }
}

// --- WriterScope-Methoden ---

impl WriterScope {
    /// Write ASN.1 `UTC_TIME`.
    pub fn write_utc_time(&mut self, value: &Asn1UtcTime) {
        self.write_tagged_object(asn1_type::UTC_TIME, 0x00, |w| {
            let mut s = String::new();
            // year % 100, zero-padded to 2
            use core::fmt::Write as _;
            let _ = write!(s, "{:02}", (value.year.rem_euclid(100)) as i32);
            let _ = write!(s, "{:02}{:02}{:02}{:02}",
                           value.month, value.day, value.hour, value.minute);
            if let Some(sec) = value.second {
                let _ = write!(s, "{:02}", sec);
            }
            s.push_str(&format_offset(&value.offset));
            w.write_bytes(s.as_bytes());
        });
    }

    /// Write ASN.1 `GENERALIZED_TIME`.
    pub fn write_generalized_time(&mut self, value: &Asn1GeneralizedTime) {
        self.write_tagged_object(asn1_type::GENERALIZED_TIME, 0x00, |w| {
            use core::fmt::Write as _;
            let mut s = String::new();
            let _ = write!(s, "{:04}{:02}{:02}{:02}",
                           value.year, value.month, value.day, value.hour);
            if let Some(min) = value.minute {
                let _ = write!(s, "{:02}", min);
            }
            if let Some(sec) = value.second {
                let _ = write!(s, "{:02}", sec);
            }
            if let Some(frac) = value.fraction_of_second {
                let _ = write!(s, ".{}", frac);
            }
            s.push_str(&format_offset(&value.offset));
            w.write_bytes(s.as_bytes());
        });
    }
}