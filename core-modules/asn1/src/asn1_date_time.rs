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

use regex::{Captures, Regex};
use std::fmt;
use std::io::{self, Write as IoWrite};
use std::str::FromStr;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq)]
pub struct Asn1UtcTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: Option<i32>,
    pub offset: Option<Offset>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Asn1GeneralizedTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: Option<i32>,
    pub second: Option<i32>,
    pub fraction_of_second: Option<i32>,
    pub offset: Option<Offset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset {
    pub hours: i8,
    pub minutes: i8,
}

static UTC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})?$")
        .expect("valid UTC regex")
});

static GEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d{1,3})?(Z|[+-]\d{2}\d{2})?$")
        .expect("valid generalized regex")
});

fn parse_captures<T: FromStr>(
    captures: &Captures,
    idx: usize,
    field: &str,
    input: &str,
) -> Result<T, String> {
    captures
        .get(idx)
        .ok_or_else(|| format!("Missing {} in `{}`", field, input))?
        .as_str()
        .parse::<T>()
        .map_err(|_| format!("Invalid {} in `{}`", field, input))
}

fn parse_captures_opt<T: FromStr>(
    captures: &Captures,
    idx: usize,
    field: &str,
    input: &str,
) -> Result<Option<T>, String> {
    captures
        .get(idx)
        .map(|m| {
            m.as_str()
                .parse::<T>()
                .map_err(|_| format!("Invalid {} in `{}`", field, input))
        })
        .transpose()
}

#[inline]
fn fmt_two_opt(v: Option<i32>) -> String {
    v.map_or(String::new(), |n| format!("{:02}", n))
}

#[inline]
fn fmt_frac_millis_opt(v: Option<i32>) -> String {
    v.map_or(String::new(), |n| format!(".{:03}", n))
}

/// Implementation of parser functions for utc time
impl Asn1UtcTime {
    pub fn parse(value: &str) -> Result<Self, String> {
        let caps = UTC_RE
            .captures(value)
            .ok_or_else(|| format!("Wrong utc time format: `{}`", value))?;

        // UTCTime encodes the year with two digits (YY).
        let year_short: i32 = parse_captures(&caps, 1, "year", value)?;
        let year = if year_short >= 50 {
            1900 + year_short
        } else {
            2000 + year_short
        };
        let month: i32 = parse_captures(&caps, 2, "month", value)?;
        let day: i32 = parse_captures(&caps, 3, "day", value)?;
        let hour: i32 = parse_captures(&caps, 4, "hour", value)?;
        let minute: i32 = parse_captures(&caps, 5, "minute", value)?;
        let second: Option<i32> = parse_captures_opt(&caps, 6, "second", value)?;
        let offset = caps
            .get(7)
            .map(|m| parse_offset(m.as_str()))
            .transpose()?
            .flatten();

        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            offset,
        })
    }

    pub fn format(&self) -> String {
        format!(
            "{:02}{:02}{:02}{:02}{:02}{}{}",
            self.year % 100,
            self.month,
            self.day,
            self.hour,
            self.minute,
            fmt_two_opt(self.second),
            format_offset(self.offset.as_ref()),
        )
    }

    /// Writes the UTC time in ASN.1 textual form into a `String` buffer.
    pub fn write_to_string(&self, out: &mut String) {
        out.push_str(&self.format());
    }

    /// Writes the UTC time in ASN.1 textual form as bytes to an `io::Write` sink.
    pub fn write_to_io<W: IoWrite>(&self, mut w: W) -> io::Result<()> {
        w.write_all(self.format().as_bytes())
    }
}

fn parse_offset(value: &str) -> Result<Option<Offset>, String> {
    if value == "Z" {
        return Ok(None);
    }
    if value.len() != 5 {
        return Err(format!("Invalid time zone format: {}", value));
    }
    let sign = match &value[..1] {
        "+" => 1i16,
        "-" => -1i16,
        _ => return Err(format!("Invalid sign in offset: {}", value)),
    };
    let hours: i16 = value[1..3]
        .parse()
        .map_err(|_| format!("Invalid hour in offset: {}", value))?;
    let minutes: i16 = value[3..5]
        .parse()
        .map_err(|_| format!("Invalid minute in offset: {}", value))?;
    // Bounds check (RFC 5280 allows +/- 12:00 typical)
    if hours.abs() > 23 || minutes.abs() > 59 {
        return Err(format!("Out-of-range offset: {}", value));
    }
    Ok(Some(Offset {
        hours: (sign * hours) as i8,
        minutes: (sign * minutes) as i8,
    }))
}

fn format_offset(offset: Option<&Offset>) -> String {
    match offset {
        None => "Z".to_string(),
        Some(o) => format!(
            "{}{:02}{:02}",
            if o.hours >= 0 { "+" } else { "-" },
            o.hours.abs(),
            o.minutes.abs()
        ),
    }
}

/// Implementation of parser functions for generalized time
impl Asn1GeneralizedTime {
    pub fn parse(value: &str) -> Result<Self, String> {
        let caps = GEN_RE
            .captures(value)
            .ok_or_else(|| format!("Wrong generalized time format: `{}`", value))?;

        let year: i32 = parse_captures(&caps, 1, "year", value)?;
        let month: i32 = parse_captures(&caps, 2, "month", value)?;
        let day: i32 = parse_captures(&caps, 3, "day", value)?;
        let hour: i32 = parse_captures(&caps, 4, "hour", value)?;
        let minute: Option<i32> = parse_captures_opt(&caps, 5, "minute", value)?;
        let second: Option<i32> = parse_captures_opt(&caps, 6, "second", value)?;
        let fraction_of_second = caps
            .get(7)
            .map(|m| {
                m.as_str()[1..]
                    .parse::<i32>()
                    .map_err(|_| format!("Invalid fraction in `{}`", value))
            })
            .transpose()?;
        let offset = caps
            .get(8)
            .map(|m| parse_offset(m.as_str()))
            .transpose()?
            .flatten();

        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction_of_second,
            offset,
        })
    }

    pub fn format(&self) -> String {
        format!(
            "{:04}{:02}{:02}{:02}{}{}{}{}",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute.map_or(String::new(), |m| format!("{:02}", m)),
            self.second.map_or(String::new(), |s| format!("{:02}", s)),
            fmt_frac_millis_opt(self.fraction_of_second),
            self.offset.as_ref().map_or("Z".to_string(), |o| format!(
                "{}{:02}{:02}",
                if o.hours >= 0 { "+" } else { "-" },
                o.hours.abs(),
                o.minutes.abs()
            )),
        )
    }

    /// Writes the GeneralizedTime in ASN.1 textual form into a `String` buffer.
    pub fn write_to_string(&self, out: &mut String) {
        out.push_str(&self.format());
    }

    /// Writes the GeneralizedTime in ASN.1 textual form as bytes to an `io::Write` sink.
    pub fn write_to_io<W: IoWrite>(&self, mut w: W) -> io::Result<()> {
        w.write_all(self.format().as_bytes())
    }
}

impl fmt::Display for Asn1UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

impl fmt::Display for Asn1GeneralizedTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_utc_time() {
        let time = Asn1UtcTime::parse("010203040506Z").unwrap();
        assert_eq!(time.year, 2001);
        assert_eq!(time.month, 2);
        assert_eq!(time.day, 3);
        assert_eq!(time.hour, 4);
        assert_eq!(time.minute, 5);
        assert_eq!(time.second, Some(6));
        assert_eq!(time.offset, None);

        let time = Asn1UtcTime::parse("951230120000+0300").unwrap();
        assert_eq!(time.year, 1995);
        assert_eq!(time.month, 12);
        assert_eq!(time.day, 30);
        assert_eq!(time.hour, 12);
        assert_eq!(time.minute, 0);
        assert_eq!(time.second, Some(0));
        assert_eq!(
            time.offset,
            Some(Offset {
                hours: 3,
                minutes: 0
            })
        );
    }

    #[test]
    fn test_format_utc_time() {
        let time = Asn1UtcTime {
            year: 2001,
            month: 2,
            day: 3,
            hour: 4,
            minute: 5,
            second: Some(6),
            offset: None,
        };
        assert_eq!(time.format(), "010203040506Z");

        let time = Asn1UtcTime {
            year: 1995,
            month: 12,
            day: 30,
            hour: 12,
            minute: 0,
            second: Some(0),
            offset: Some(Offset {
                hours: 3,
                minutes: 0,
            }),
        };
        assert_eq!(time.format(), "951230120000+0300");
    }

    #[test]
    fn test_parse_generalized_time() {
        let time = Asn1GeneralizedTime::parse("20010203040506Z").unwrap();
        assert_eq!(time.year, 2001);
        assert_eq!(time.month, 2);
        assert_eq!(time.day, 3);
        assert_eq!(time.hour, 4);
        assert_eq!(time.minute, Some(5));
        assert_eq!(time.second, Some(6));
        assert_eq!(time.fraction_of_second, None);
        assert_eq!(time.offset, None);

        let time = Asn1GeneralizedTime::parse("19951230120000.5+0300").unwrap();
        assert_eq!(time.year, 1995);
        assert_eq!(time.month, 12);
        assert_eq!(time.day, 30);
        assert_eq!(time.hour, 12);
        assert_eq!(time.minute, Some(0));
        assert_eq!(time.second, Some(0));
        assert_eq!(time.fraction_of_second, Some(5));
        assert_eq!(
            time.offset,
            Some(Offset {
                hours: 3,
                minutes: 0
            })
        );
    }

    #[test]
    fn test_write_utc_time_to_string_and_io() {
        let t = Asn1UtcTime {
            year: 1995,
            month: 12,
            day: 30,
            hour: 12,
            minute: 0,
            second: Some(0),
            offset: Some(Offset {
                hours: 3,
                minutes: 0,
            }),
        };
        let expected = "951230120000+0300".to_string();

        let mut s = String::new();
        t.write_to_string(&mut s);
        assert_eq!(s, expected);

        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        t.write_to_io(&mut cursor).unwrap();
        assert_eq!(String::from_utf8(cursor.into_inner()).unwrap(), expected);
    }

    #[test]
    fn test_write_generalized_time_to_string_and_io() {
        let t = Asn1GeneralizedTime {
            year: 1995,
            month: 12,
            day: 30,
            hour: 12,
            minute: Some(0),
            second: Some(0),
            fraction_of_second: Some(5),
            offset: Some(Offset {
                hours: 3,
                minutes: 0,
            }),
        };
        let expected = "19951230120000.005+0300".to_string();

        let mut s = String::new();
        t.write_to_string(&mut s);
        assert_eq!(s, expected);

        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        t.write_to_io(&mut cursor).unwrap();
        assert_eq!(String::from_utf8(cursor.into_inner()).unwrap(), expected);
    }
}
