// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

use regex::Regex;
use std::sync::OnceLock;
use crate::asn1_tag::UniversalTag;
use crate::asn1_decoder::Asn1DecoderError;
use crate::asn1_decoder::Result as DecoderResult;
use crate::asn1_decoder::ParserScope;
use crate::asn1_encoder::WriterScope;
use crate::asn1_encoder::Result as EncoderResult;

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
    pub offset: Option<Asn1Offset>,
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
fn parse_time_zone_or_offset(offset: &str) -> DecoderResult<Option<Asn1Offset>> {
    if offset.is_empty() || offset.as_bytes()[0] == b'Z' {
        Ok(None)
    } else {
        let sign = if offset.as_bytes()[0] == b'-' { -1 } else { 1 };
        let hours: i32 = offset[1..3]
            .parse()
            .map_err(|_| Asn1DecoderError::new(format!("Invalid hour in offset: `{}`", offset)))?;
        let minutes: i32 = offset[3..5]
            .parse()
            .map_err(|_| Asn1DecoderError::new(format!("Invalid minute in offset: `{}`", offset)))?;
        Ok(Some(Asn1Offset::UtcOffset { hours: hours * sign, minutes }))
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
    fn parse_utc_time(&mut self, value: &str) -> DecoderResult<Asn1UtcTime> {
        let re = utc_time_regex();
        let Some(caps) = re.captures(value) else {
            return Err(Asn1DecoderError::new(format!("Wrong utc time format: `{}`", value)));
        };

        let yy = &caps[1];
        let mm = &caps[2];
        let dd = &caps[3];
        let hh = &caps[4];
        let min = &caps[5];
        let ss = caps.get(6).map(|m| m.as_str()).unwrap_or("");
        let offset = &caps[7];

        let year = yy.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid year in UTC_TIME: `{}`", yy)))?;
        let month = mm.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid month in UTC_TIME: `{}`", mm)))?;
        let day = dd.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid day in UTC_TIME: `{}`", dd)))?;
        let hour = hh.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid hour in UTC_TIME: `{}`", hh)))?;
        let minute = min.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid minute in UTC_TIME: `{}`", min)))?;
        let second = if ss.is_empty() { None } else { Some(ss.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid second in UTC_TIME: `{}`", ss)))?) };

        Ok(Asn1UtcTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            offset: parse_time_zone_or_offset(offset)?,
        })
    }

    /// Parses a GENERALIZED_TIME string.
    fn parse_generalized_time(&mut self, value: &str) -> DecoderResult<Asn1GeneralizedTime> {
        let re = generalized_time_regex();
        let Some(caps) = re.captures(value) else {
            return Err(Asn1DecoderError::new(format!("Wrong generalized time format: `{}`", value)));
        };

        let yyyy = &caps[1];
        let mm = &caps[2];
        let dd = &caps[3];
        let hh = &caps[4];
        let min = caps.get(5).map(|m| m.as_str()).unwrap_or("");
        let ss = caps.get(6).map(|m| m.as_str()).unwrap_or("");
        let fff = caps.get(7).map(|m| m.as_str()).unwrap_or("");
        let offset = caps.get(8).map(|m| m.as_str()).unwrap_or("");

        let year = yyyy.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid year in GENERALIZED_TIME: `{}`", yyyy)))?;
        let month = mm.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid month in GENERALIZED_TIME: `{}`", mm)))?;
        let day = dd.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid day in GENERALIZED_TIME: `{}`", dd)))?;
        let hour = hh.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid hour in GENERALIZED_TIME: `{}`", hh)))?;
        let minute = if min.is_empty() { None } else { Some(min.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid minute in GENERALIZED_TIME: `{}`", min)))?) };
        let second = if ss.is_empty() { None } else { Some(ss.parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid second in GENERALIZED_TIME: `{}`", ss)))?) };
        let fraction_of_second = if fff.is_empty() {
            None
        } else {
            // drop the leading '.'
            Some(fff[1..].parse::<i32>().map_err(|_| Asn1DecoderError::new(format!("Invalid fraction in GENERALIZED_TIME: `{}`", fff)))?)
        };

        Ok(Asn1GeneralizedTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction_of_second,
            offset: parse_time_zone_or_offset(offset)?,
        })
    }

    /// Read ASN.1 `UTC_TIME`.
    pub fn read_utc_time(&mut self) -> DecoderResult<Asn1UtcTime> {
        self.advance_with_tag(UniversalTag::UtcTime, 0x00, |s| {
            let len = s.remaining_length();
            let bytes = s.read_bytes(len)?;
            let value = String::from_utf8(bytes)
                .map_err(|_| Asn1DecoderError::new("Malformed UTC_TIME (non-UTF8)".to_string()))?;
            s.parse_utc_time(&value)
        })
    }

    /// Read ASN.1 `GENERALIZED_TIME`.
    pub fn read_generalized_time(&mut self) -> DecoderResult<Asn1GeneralizedTime> {
        self.advance_with_tag(UniversalTag::GeneralizedTime, 0x00, |s| {
            let len = s.remaining_length();
            let bytes = s.read_bytes(len)?;
            let value = String::from_utf8(bytes)
                .map_err(|_| Asn1DecoderError::new("Malformed GENERALIZED_TIME (non-UTF8)".to_string()))?;
            s.parse_generalized_time(&value)
        })
    }
}

impl WriterScope {
    /// Write ASN.1 `UTC_TIME`.
    pub fn write_utc_time(&mut self, value: &Asn1UtcTime) -> EncoderResult<()> {
        self.write_tagged_object(UniversalTag::UtcTime, 0x00, |w| {
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
            Ok(())
        })
    }

    /// Write ASN.1 `GENERALIZED_TIME`.
    pub fn write_generalized_time(&mut self, value: &Asn1GeneralizedTime) -> EncoderResult<()> {
        self.write_tagged_object(UniversalTag::GeneralizedTime, 0x00, |w| {
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
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_decoder::Asn1Decoder;
    
    #[inline]
    fn tag(t: impl Into<u8>) -> u8 { t.into() }

    #[test]
    fn write_utc_time_basic_z() {
        let value = Asn1UtcTime {
            year: 2025,
            month: 1,
            day: 1,
            hour: 12,
            minute: 0,
            second: None,
            offset: None, // Z
        };
        let out = crate::asn1_encoder::Asn1Encoder::write(|w| {
            w.write_utc_time(&value)?;
            Ok(())
        }).unwrap();

        // Expect tag = UTC_TIME, length = payload length, payload = "2501011200Z"
        let expected_payload = b"2501011200Z".to_vec();
        assert_eq!(out[0], tag(UniversalTag::UtcTime));
        assert_eq!(out[1] as usize, expected_payload.len());
        assert_eq!(&out[2..], &expected_payload[..]);
    }

    #[test]
    fn write_utc_time_with_offset_and_seconds() {
        let value = Asn1UtcTime {
            year: 1999,
            month: 12,
            day: 31,
            hour: 23,
            minute: 59,
            second: Some(58),
            offset: Some(Asn1Offset::UtcOffset { hours: 2, minutes: 30 }),
        };
        let out = crate::asn1_encoder::Asn1Encoder::write(|w| {
            w.write_utc_time(&value)?;
            Ok(())
        }).unwrap();

        // 1999 % 100 = 99
        let expected_payload = b"991231235958+0230".to_vec();
        assert_eq!(out[0], tag(UniversalTag::UtcTime));
        assert_eq!(out[1] as usize, expected_payload.len());
        assert_eq!(&out[2..], &expected_payload[..]);
    }

    #[test]
    fn read_utc_time_basic_z() {
        // Build DER: tag, len, payload
        let payload = b"2501011200Z";
        let mut der = Vec::with_capacity(2 + payload.len());
        der.push(tag(UniversalTag::UtcTime));
        der.push(payload.len() as u8);
        der.extend_from_slice(payload);

        let dec = Asn1Decoder::new(&der);
        let v = dec.read(|s| s.read_utc_time()).unwrap();
        assert_eq!(v.year, 2025 % 100); // note: raw UTC_TIME stores YY; parser keeps YY in `year`
        assert_eq!(v.month, 1);
        assert_eq!(v.day, 1);
        assert_eq!(v.hour, 12);
        assert_eq!(v.minute, 0);
        assert_eq!(v.second, None);
        assert_eq!(v.offset, None);
    }

    #[test]
    fn read_utc_time_malformed() {
        // invalid: missing minutes
        let payload = b"25010112Z"; // too short
        let mut der = Vec::with_capacity(2 + payload.len());
        der.push(tag(UniversalTag::UtcTime));
        der.push(payload.len() as u8);
        der.extend_from_slice(payload);

        let dec = Asn1Decoder::new(&der);
        let res = dec.read(|s| s.read_utc_time());
        assert!(res.is_err());
    }

    #[test]
    fn write_generalized_time_full() {
        let value = Asn1GeneralizedTime {
            year: 2024,
            month: 6,
            day: 15,
            hour: 8,
            minute: Some(9),
            second: Some(10),
            fraction_of_second: Some(123),
            offset: Some(Asn1Offset::GeneralizedOffset { hours: -1, minutes: 30 }),
        };
        let out = crate::asn1_encoder::Asn1Encoder::write(|w| {
            w.write_generalized_time(&value)?;
            Ok(())
        }).unwrap();

        let expected_payload = b"20240615080910.123-0130".to_vec();
        assert_eq!(out[0], tag(UniversalTag::GeneralizedTime));
        assert_eq!(out[1] as usize, expected_payload.len());
        assert_eq!(&out[2..], &expected_payload[..]);
    }

    #[test]
    fn read_generalized_time_missing_parts_is_err() {
        // invalid: only year+month
        let payload = b"202406Z";
        let mut der = Vec::with_capacity(2 + payload.len());
        der.push(tag(UniversalTag::GeneralizedTime));
        der.push(payload.len() as u8);
        der.extend_from_slice(payload);

        let dec = Asn1Decoder::new(&der);
        let res = dec.read(|s| s.read_generalized_time());
        assert!(res.is_err());
    }
}