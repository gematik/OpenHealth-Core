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

use crate::decoder::ParserScope;
use crate::encoder::WriterScope;
use crate::error::{Asn1DecoderError, Asn1DecoderResult, Asn1EncoderError};
use crate::tag::UniversalTag;
use regex::Regex;
use std::sync::OnceLock;

/// Raw representation of an ASN.1 UTC_TIME.
/// If `offset` is `None` this indicates that the time is in UTC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1UtcTime {
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: Option<i32>,
    offset: Option<Asn1Offset>,
}

/// Raw representation of an ASN.1 GENERALIZED_TIME.
/// If `offset` is `None` this indicates that the time is in UTC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asn1GeneralizedTime {
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: Option<i32>,
    second: Option<i32>,
    fraction_of_second: Option<i32>,
    offset: Option<Asn1Offset>,
}

/// Raw representation of an ASN.1 time offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Offset {
    /// UTC offset in hours and minutes.
    UtcOffset { hours: i32, minutes: i32 },
    /// Generalized offset in hours and minutes.
    GeneralizedOffset { hours: i32, minutes: i32 },
}

/// Tagged ASN.1 time value (UTC or Generalized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Time {
    Utc(Asn1UtcTime),
    Generalized(Asn1GeneralizedTime),
}

impl Asn1Time {
    pub fn utc(
        year: i32,
        month: i32,
        day: i32,
        hour: i32,
        minute: i32,
        second: Option<i32>,
        offset: Option<Asn1Offset>,
    ) -> Asn1DecoderResult<Self> {
        Asn1UtcTime::new(year, month, day, hour, minute, second, offset).map(Asn1Time::Utc)
    }

    #[allow(clippy::too_many_arguments)] // ASN.1 GENERALIZED TIME requires separate components for optional fields
    pub fn generalized(
        year: i32,
        month: i32,
        day: i32,
        hour: i32,
        minute: Option<i32>,
        second: Option<i32>,
        fraction_of_second: Option<i32>,
        offset: Option<Asn1Offset>,
    ) -> Asn1DecoderResult<Self> {
        Asn1GeneralizedTime::new(year, month, day, hour, minute, second, fraction_of_second, offset)
            .map(Asn1Time::Generalized)
    }

    pub fn as_utc(&self) -> Option<&Asn1UtcTime> {
        match self {
            Asn1Time::Utc(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_generalized(&self) -> Option<&Asn1GeneralizedTime> {
        match self {
            Asn1Time::Generalized(v) => Some(v),
            _ => None,
        }
    }
}

impl Asn1Offset {
    pub fn utc_offset(hours: i32, minutes: i32) -> Asn1DecoderResult<Self> {
        Self::validate(hours, minutes)?;
        Ok(Asn1Offset::UtcOffset { hours, minutes })
    }

    pub fn generalized_offset(hours: i32, minutes: i32) -> Asn1DecoderResult<Self> {
        Self::validate(hours, minutes)?;
        Ok(Asn1Offset::GeneralizedOffset { hours, minutes })
    }

    fn validate(hours: i32, minutes: i32) -> Asn1DecoderResult<()> {
        if !(0..=59).contains(&minutes.abs()) {
            return Err(Asn1DecoderError::invalid_time_value("offset minute", minutes.to_string()));
        }
        if !(-23..=23).contains(&hours) {
            return Err(Asn1DecoderError::invalid_time_value("offset hour", hours.to_string()));
        }
        Ok(())
    }
}

impl Asn1UtcTime {
    pub fn new(
        year: i32,
        month: i32,
        day: i32,
        hour: i32,
        minute: i32,
        second: Option<i32>,
        offset: Option<Asn1Offset>,
    ) -> Asn1DecoderResult<Self> {
        Self::validate_basic_components(year, month, day, hour)?;
        if !(0..=59).contains(&minute) {
            return Err(Asn1DecoderError::invalid_time_value("UTC_TIME minute", minute.to_string()));
        }
        if let Some(sec) = second {
            if !(0..=60).contains(&sec) {
                return Err(Asn1DecoderError::invalid_time_value("UTC_TIME second", sec.to_string()));
            }
        }
        Ok(Self { year, month, day, hour, minute, second, offset })
    }

    fn validate_basic_components(year: i32, month: i32, day: i32, hour: i32) -> Asn1DecoderResult<()> {
        if !(0..=9999).contains(&year) {
            return Err(Asn1DecoderError::invalid_time_value("UTC_TIME year", year.to_string()));
        }
        if !(1..=12).contains(&month) {
            return Err(Asn1DecoderError::invalid_time_value("UTC_TIME month", month.to_string()));
        }
        if !(1..=31).contains(&day) {
            return Err(Asn1DecoderError::invalid_time_value("UTC_TIME day", day.to_string()));
        }
        if !(0..=23).contains(&hour) {
            return Err(Asn1DecoderError::invalid_time_value("UTC_TIME hour", hour.to_string()));
        }
        Ok(())
    }

    pub fn components(&self) -> (i32, i32, i32, i32, i32, Option<i32>) {
        (self.year, self.month, self.day, self.hour, self.minute, self.second)
    }

    pub fn offset(&self) -> &Option<Asn1Offset> {
        &self.offset
    }

    pub fn validate_for_encoding(&self) -> Result<(), Asn1EncoderError> {
        Self::new(self.year, self.month, self.day, self.hour, self.minute, self.second, self.offset.clone())
            .map_err(|e| Asn1EncoderError::custom(e.to_string()))
            .map(|_| ())
    }

    pub fn year(&self) -> i32 {
        self.year
    }
    pub fn month(&self) -> i32 {
        self.month
    }
    pub fn day(&self) -> i32 {
        self.day
    }
    pub fn hour(&self) -> i32 {
        self.hour
    }
    pub fn minute(&self) -> i32 {
        self.minute
    }
    pub fn second(&self) -> Option<i32> {
        self.second
    }
}

impl Asn1GeneralizedTime {
    #[allow(clippy::too_many_arguments)] // ASN.1 GENERALIZED TIME requires separate components for optional fields
    pub fn new(
        year: i32,
        month: i32,
        day: i32,
        hour: i32,
        minute: Option<i32>,
        second: Option<i32>,
        fraction_of_second: Option<i32>,
        offset: Option<Asn1Offset>,
    ) -> Asn1DecoderResult<Self> {
        Self::validate_basic_components(year, month, day, hour)?;
        if let Some(min) = minute {
            if !(0..=59).contains(&min) {
                return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME minute", min.to_string()));
            }
        }
        if let Some(sec) = second {
            if !(0..=60).contains(&sec) {
                return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME second", sec.to_string()));
            }
        }
        if let Some(frac) = fraction_of_second {
            if !(0..=999).contains(&frac) {
                return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME fraction", frac.to_string()));
            }
        }
        Ok(Self { year, month, day, hour, minute, second, fraction_of_second, offset })
    }

    fn validate_basic_components(year: i32, month: i32, day: i32, hour: i32) -> Asn1DecoderResult<()> {
        if !(0..=9999).contains(&year) {
            return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME year", year.to_string()));
        }
        if !(1..=12).contains(&month) {
            return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME month", month.to_string()));
        }
        if !(1..=31).contains(&day) {
            return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME day", day.to_string()));
        }
        if !(0..=23).contains(&hour) {
            return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME hour", hour.to_string()));
        }
        Ok(())
    }

    pub fn components(&self) -> (i32, i32, i32, i32, Option<i32>, Option<i32>, Option<i32>) {
        (self.year, self.month, self.day, self.hour, self.minute, self.second, self.fraction_of_second)
    }

    pub fn offset(&self) -> &Option<Asn1Offset> {
        &self.offset
    }

    pub fn validate_for_encoding(&self) -> Result<(), Asn1EncoderError> {
        Self::new(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.fraction_of_second,
            self.offset.clone(),
        )
        .map_err(|e| Asn1EncoderError::custom(e.to_string()))
        .map(|_| ())
    }

    pub fn year(&self) -> i32 {
        self.year
    }
    pub fn month(&self) -> i32 {
        self.month
    }
    pub fn day(&self) -> i32 {
        self.day
    }
    pub fn hour(&self) -> i32 {
        self.hour
    }
    pub fn minute(&self) -> Option<i32> {
        self.minute
    }
    pub fn second(&self) -> Option<i32> {
        self.second
    }
    pub fn fraction_of_second(&self) -> Option<i32> {
        self.fraction_of_second
    }
}

fn utc_time_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})").expect("valid regex")
    })
}

fn generalized_time_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d{1,3})?(Z|[+-]\d{2}\d{2})?").expect("valid regex")
    })
}

/// Parses the offset string into an `Asn1Offset`.
///
/// The offset string can either be empty (no offset/UTC), 'Z' for UTC,
/// or '+/-HHMM' for a specific time zone offset.
fn parse_time_zone_or_offset(offset: &str, generalized: bool) -> Asn1DecoderResult<Option<Asn1Offset>> {
    if offset.is_empty() || offset.as_bytes()[0] == b'Z' {
        Ok(None)
    } else {
        let sign = if offset.as_bytes()[0] == b'-' { -1 } else { 1 };
        let hours: i32 =
            offset[1..3].parse().map_err(|_| Asn1DecoderError::invalid_time_value("offset hour", offset))?;
        let minutes: i32 =
            offset[3..5].parse().map_err(|_| Asn1DecoderError::invalid_time_value("offset minute", offset))?;
        let hours = hours * sign;
        if generalized {
            Ok(Some(Asn1Offset::generalized_offset(hours, minutes)?))
        } else {
            Ok(Some(Asn1Offset::utc_offset(hours, minutes)?))
        }
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
        format!("{}{:02}{:02}", sign, hours.abs(), minutes.abs())
    }
}

impl<'a> ParserScope<'a> {
    /// Parses a UTC time string into an `Asn1UtcTime`.
    fn parse_utc_time(&mut self, value: &str) -> Asn1DecoderResult<Asn1UtcTime> {
        let re = utc_time_regex();
        let Some(caps) = re.captures(value) else {
            return Err(Asn1DecoderError::invalid_time_value("UTC_TIME format", value));
        };

        let yy = &caps[1];
        let mm = &caps[2];
        let dd = &caps[3];
        let hh = &caps[4];
        let min = &caps[5];
        let ss = caps.get(6).map(|m| m.as_str()).unwrap_or("");
        let offset = &caps[7];

        let year = yy.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("UTC_TIME year", yy))?;
        let month = mm.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("UTC_TIME month", mm))?;
        let day = dd.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("UTC_TIME day", dd))?;
        let hour = hh.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("UTC_TIME hour", hh))?;
        let minute = min.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("UTC_TIME minute", min))?;
        let second = if ss.is_empty() {
            None
        } else {
            Some(ss.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("UTC_TIME second", ss))?)
        };

        Asn1UtcTime::new(year, month, day, hour, minute, second, parse_time_zone_or_offset(offset, false)?)
    }

    /// Parses a GENERALIZED_TIME string.
    fn parse_generalized_time(&mut self, value: &str) -> Asn1DecoderResult<Asn1GeneralizedTime> {
        let re = generalized_time_regex();
        let Some(caps) = re.captures(value) else {
            return Err(Asn1DecoderError::invalid_time_value("GENERALIZED_TIME format", value));
        };

        let yyyy = &caps[1];
        let mm = &caps[2];
        let dd = &caps[3];
        let hh = &caps[4];
        let min = caps.get(5).map(|m| m.as_str()).unwrap_or("");
        let ss = caps.get(6).map(|m| m.as_str()).unwrap_or("");
        let fff = caps.get(7).map(|m| m.as_str()).unwrap_or("");
        let offset = caps.get(8).map(|m| m.as_str()).unwrap_or("");

        let year =
            yyyy.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("GENERALIZED_TIME year", yyyy))?;
        let month =
            mm.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("GENERALIZED_TIME month", mm))?;
        let day = dd.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("GENERALIZED_TIME day", dd))?;
        let hour = hh.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("GENERALIZED_TIME hour", hh))?;
        let minute = if min.is_empty() {
            None
        } else {
            Some(min.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("GENERALIZED_TIME minute", min))?)
        };
        let second = if ss.is_empty() {
            None
        } else {
            Some(ss.parse::<i32>().map_err(|_| Asn1DecoderError::invalid_time_value("GENERALIZED_TIME second", ss))?)
        };
        let fraction_of_second = if fff.is_empty() {
            None
        } else {
            // drop the leading '.'
            Some(
                fff[1..]
                    .parse::<i32>()
                    .map_err(|_| Asn1DecoderError::invalid_time_value("GENERALIZED_TIME fraction", fff))?,
            )
        };

        Asn1GeneralizedTime::new(
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction_of_second,
            parse_time_zone_or_offset(offset, true)?,
        )
    }

    /// Read ASN.1 `UTC_TIME`.
    pub fn read_utc_time(&mut self) -> Asn1DecoderResult<Asn1Time> {
        self.advance_with_tag(UniversalTag::UtcTime.primitive(), |s| {
            let len = s.remaining_length();
            let bytes = s.read_bytes(len)?;
            let value = String::from_utf8(bytes).map_err(|_| Asn1DecoderError::MalformedUtcTimeEncoding)?;
            s.parse_utc_time(&value).map(Asn1Time::Utc)
        })
    }

    /// Read ASN.1 `GENERALIZED_TIME`.
    pub fn read_generalized_time(&mut self) -> Asn1DecoderResult<Asn1Time> {
        self.advance_with_tag(UniversalTag::GeneralizedTime.primitive(), |s| {
            let len = s.remaining_length();
            let bytes = s.read_bytes(len)?;
            let value = String::from_utf8(bytes).map_err(|_| Asn1DecoderError::MalformedGeneralizedTimeEncoding)?;
            s.parse_generalized_time(&value).map(Asn1Time::Generalized)
        })
    }
}

impl WriterScope {
    /// Write ASN.1 `UTC_TIME`.
    pub fn write_utc_time(&mut self, value: &Asn1Time) -> Result<(), Asn1EncoderError> {
        let Some(utc) = value.as_utc() else {
            return Err(Asn1EncoderError::custom("expected UTC time"));
        };
        utc.validate_for_encoding()?;
        self.write_tagged_object(UniversalTag::UtcTime.primitive(), |w| -> Result<(), Asn1EncoderError> {
            let mut s = String::new();
            // year % 100, zero-padded to 2
            use core::fmt::Write as _;
            let (year, month, day, hour, minute, second) = utc.components();
            let _ = write!(s, "{:02}", year.rem_euclid(100));
            let _ = write!(s, "{:02}{:02}{:02}{:02}", month, day, hour, minute);
            if let Some(sec) = second {
                let _ = write!(s, "{:02}", sec);
            }
            s.push_str(&format_offset(utc.offset()));
            w.write_bytes(s.as_bytes());
            Ok(())
        })
    }

    /// Write ASN.1 `GENERALIZED_TIME`.
    pub fn write_generalized_time(&mut self, value: &Asn1Time) -> Result<(), Asn1EncoderError> {
        let Some(gen) = value.as_generalized() else {
            return Err(Asn1EncoderError::custom("expected GENERALIZED TIME"));
        };
        gen.validate_for_encoding()?;
        self.write_tagged_object(UniversalTag::GeneralizedTime.primitive(), |w| -> Result<(), Asn1EncoderError> {
            use core::fmt::Write as _;
            let mut s = String::new();
            let (year, month, day, hour, minute, second, fraction_of_second) = gen.components();
            let _ = write!(s, "{:04}{:02}{:02}{:02}", year, month, day, hour);
            if let Some(min) = minute {
                let _ = write!(s, "{:02}", min);
            }
            if let Some(sec) = second {
                let _ = write!(s, "{:02}", sec);
            }
            if let Some(frac) = fraction_of_second {
                let _ = write!(s, ".{}", frac);
            }
            s.push_str(&format_offset(gen.offset()));
            w.write_bytes(s.as_bytes());
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::Asn1Decoder;

    #[inline]
    fn tag(t: impl Into<u8>) -> u8 {
        t.into()
    }

    #[test]
    fn write_utc_time_basic_z() {
        let value = Asn1Time::Utc(Asn1UtcTime::new(2025, 1, 1, 12, 0, None, None).unwrap());
        let out = crate::encoder::Asn1Encoder::write(|w| -> Result<(), Asn1EncoderError> {
            w.write_utc_time(&value)?;
            Ok(())
        })
        .unwrap();

        // Expect tag = UTC_TIME, length = payload length, payload = "2501011200Z"
        let expected_payload = b"2501011200Z".to_vec();
        assert_eq!(out[0], tag(UniversalTag::UtcTime));
        assert_eq!(out[1] as usize, expected_payload.len());
        assert_eq!(&out[2..], &expected_payload[..]);
    }

    #[test]
    fn write_utc_time_with_offset_and_seconds() {
        let value = Asn1Time::Utc(
            Asn1UtcTime::new(1999, 12, 31, 23, 59, Some(58), Some(Asn1Offset::utc_offset(2, 30).unwrap())).unwrap(),
        );
        let out = crate::encoder::Asn1Encoder::write(|w| -> Result<(), Asn1EncoderError> {
            w.write_utc_time(&value)?;
            Ok(())
        })
        .unwrap();

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
        let Asn1Time::Utc(v) = v else { panic!("expected UTC time") };
        assert_eq!(v.year(), 2025 % 100); // note: raw UTC_TIME stores YY; parser keeps YY in `year`
        assert_eq!(v.month(), 1);
        assert_eq!(v.day(), 1);
        assert_eq!(v.hour(), 12);
        assert_eq!(v.minute(), 0);
        assert_eq!(v.second(), None);
        assert_eq!(v.offset(), &None);
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
        let value = Asn1Time::Generalized(
            Asn1GeneralizedTime::new(
                2024,
                6,
                15,
                8,
                Some(9),
                Some(10),
                Some(123),
                Some(Asn1Offset::generalized_offset(-1, 30).unwrap()),
            )
            .unwrap(),
        );
        let out = crate::encoder::Asn1Encoder::write(|w| -> Result<(), Asn1EncoderError> {
            w.write_generalized_time(&value)?;
            Ok(())
        })
        .unwrap();

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

    #[test]
    fn utc_time_validates_components() {
        assert!(Asn1UtcTime::new(10000, 1, 1, 0, 0, None, None).is_err());
        assert!(Asn1UtcTime::new(2024, 13, 1, 0, 0, None, None).is_err());
        assert!(Asn1UtcTime::new(2024, 1, 32, 0, 0, None, None).is_err());
        assert!(Asn1UtcTime::new(2024, 1, 1, 24, 0, None, None).is_err());
        assert!(Asn1UtcTime::new(2024, 1, 1, 0, 60, None, None).is_err());
        assert!(Asn1UtcTime::new(2024, 1, 1, 0, 0, Some(61), None).is_err());
    }

    #[test]
    fn generalized_time_validates_components() {
        assert!(Asn1GeneralizedTime::new(10000, 1, 1, 0, None, None, None, None).is_err());
        assert!(Asn1GeneralizedTime::new(2024, 13, 1, 0, None, None, None, None).is_err());
        assert!(Asn1GeneralizedTime::new(2024, 1, 32, 0, None, None, None, None).is_err());
        assert!(Asn1GeneralizedTime::new(2024, 1, 1, 24, None, None, None, None).is_err());
        assert!(Asn1GeneralizedTime::new(2024, 1, 1, 0, Some(60), None, None, None).is_err());
        assert!(Asn1GeneralizedTime::new(2024, 1, 1, 0, Some(1), Some(61), None, None).is_err());
        assert!(Asn1GeneralizedTime::new(2024, 1, 1, 0, Some(1), Some(1), Some(1000), None).is_err());
    }

    #[test]
    fn offset_validation_and_formatting() {
        assert!(Asn1Offset::utc_offset(0, 60).is_err());
        assert!(Asn1Offset::utc_offset(24, 0).is_err());

        let offset = Asn1Offset::generalized_offset(-1, 30).unwrap();
        assert_eq!(format_offset(&Some(offset)), "-0130");

        let offset = Asn1Offset::generalized_offset(1, 30).unwrap();
        assert_eq!(format_offset(&Some(offset)), "+0130");

        let offset = Asn1Offset::generalized_offset(1, -30).unwrap();
        assert_eq!(format_offset(&Some(offset)), "-0130");
    }

    #[test]
    fn parse_generalized_time_without_minutes() {
        let payload = b"2024061512Z";
        let mut der = Vec::with_capacity(2 + payload.len());
        der.push(tag(UniversalTag::GeneralizedTime));
        der.push(payload.len() as u8);
        der.extend_from_slice(payload);

        let dec = Asn1Decoder::new(&der);
        let t = dec.read(|s| s.read_generalized_time()).unwrap();
        let Asn1Time::Generalized(t) = t else {
            panic!("expected GENERALIZED time");
        };
        assert_eq!(t.minute(), None);
        assert_eq!(t.second(), None);
        assert!(t.offset().is_none());
    }

    #[test]
    fn parse_generalized_time_with_offset() {
        let payload = b"202406151200+0130";
        let mut der = Vec::with_capacity(2 + payload.len());
        der.push(tag(UniversalTag::GeneralizedTime));
        der.push(payload.len() as u8);
        der.extend_from_slice(payload);

        let dec = Asn1Decoder::new(&der);
        let t = dec.read(|s| s.read_generalized_time()).unwrap();
        let Asn1Time::Generalized(t) = t else {
            panic!("expected GENERALIZED time");
        };
        match t.offset() {
            Some(Asn1Offset::GeneralizedOffset { hours, minutes }) => {
                assert_eq!(*hours, 1);
                assert_eq!(*minutes, 30);
            }
            _ => panic!("expected GeneralizedOffset"),
        }
    }

    #[test]
    fn asn1_time_constructors() {
        let utc = Asn1Time::utc(2024, 1, 1, 0, 0, None, None).unwrap();
        assert!(utc.as_utc().is_some());

        let gen = Asn1Time::generalized(2024, 1, 1, 0, None, None, None, None).unwrap();
        assert!(gen.as_generalized().is_some());
    }

    #[test]
    fn write_time_type_mismatch_errors() {
        let utc = Asn1Time::utc(2024, 1, 1, 0, 0, None, None).unwrap();
        let gen = Asn1Time::generalized(2024, 1, 1, 0, None, None, None, None).unwrap();

        let err = crate::encoder::Asn1Encoder::write(|w| w.write_generalized_time(&utc)).unwrap_err();
        assert!(err.to_string().contains("expected GENERALIZED TIME"));

        let err = crate::encoder::Asn1Encoder::write(|w| w.write_utc_time(&gen)).unwrap_err();
        assert!(err.to_string().contains("expected UTC time"));
    }

    #[test]
    fn write_generalized_time_without_optional_parts() {
        let value = Asn1Time::generalized(2024, 6, 15, 8, None, None, None, None).unwrap();
        let out = crate::encoder::Asn1Encoder::write(|w| -> Result<(), Asn1EncoderError> {
            w.write_generalized_time(&value)?;
            Ok(())
        })
        .unwrap();

        let expected_payload = b"2024061508Z".to_vec();
        assert_eq!(out[0], tag(UniversalTag::GeneralizedTime));
        assert_eq!(out[1] as usize, expected_payload.len());
        assert_eq!(&out[2..], &expected_payload[..]);
    }
}
