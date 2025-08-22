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

use std::fmt;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub struct Asn1UtcTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: Option<i32>,
    pub offset: Option<UtcOffset>,
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
    pub offset: Option<GeneralizedOffset>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UtcOffset {
    pub hours: i32,
    pub minutes: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeneralizedOffset {
    pub hours: i32,
    pub minutes: i32,
}

// Implementation of parser functions
impl Asn1UtcTime {
    pub fn parse(value: &str) -> Result<Self, String> {
        // Define the regex pattern for UTC time
        let utc_time_regex = Regex::new(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})?$")
            .unwrap();

        let captures = utc_time_regex
            .captures(value)
            .ok_or_else(|| format!("Wrong utc time format: `{}`", value))?;

        let year_str = captures.get(1).unwrap().as_str();
        let year_short = year_str.parse::<i32>().unwrap();
        // Convert 2-digit year to 4-digit
        let year = if year_short >= 50 { 1900 + year_short } else { 2000 + year_short };

        Ok(Self {
            year,
            month: captures.get(2).unwrap().as_str().parse().unwrap(),
            day: captures.get(3).unwrap().as_str().parse().unwrap(),
            hour: captures.get(4).unwrap().as_str().parse().unwrap(),
            minute: captures.get(5).unwrap().as_str().parse().unwrap(),
            second: captures.get(6).map(|m| m.as_str().parse().unwrap()),
            offset: captures.get(7).map_or(Ok(None), |m| parse_time_zone_or_offset(m.as_str()))?,
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
            self.second.map_or("".to_string(), |s| format!("{:02}", s)),
            format_offset(&self.offset),
        )
    }
}

fn parse_time_zone_or_offset(value: &str) -> Result<Option<UtcOffset>, String> {
    if value == "Z" {
        Ok(None)
    } else if value.len() == 5 {
        let hours = value[1..3].parse::<i32>().map_err(|e| e.to_string())?;
        let minutes = value[3..5].parse::<i32>().map_err(|e| e.to_string())?;
        let offset = if &value[0..1] == "+" {
            UtcOffset { hours, minutes }
        } else {
            UtcOffset {
                hours: -hours,
                minutes: -minutes,
            }
        };
        Ok(Some(offset))
    } else {
        Err(format!("Invalid time zone format: {}", value))
    }
}

fn parse_generalized_offset(value: &str) -> Result<Option<GeneralizedOffset>, String> {
    if value == "Z" {
        Ok(None)
    } else if value.len() == 5 {
        let hours = value[1..3].parse::<i32>().map_err(|e| e.to_string())?;
        let minutes = value[3..5].parse::<i32>().map_err(|e| e.to_string())?;
        let offset = if &value[0..1] == "+" {
            GeneralizedOffset { hours, minutes }
        } else {
            GeneralizedOffset {
                hours: -hours,
                minutes: -minutes,
            }
        };
        Ok(Some(offset))
    } else {
        Err(format!("Invalid time zone format: {}", value))
    }
}

fn format_offset(offset: &Option<UtcOffset>) -> String {
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

impl Asn1GeneralizedTime {
    pub fn parse(value: &str) -> Result<Self, String> {
        // Define the regex pattern for generalized time
        let generalized_time_regex = Regex::new(
            r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d{1,3})?(Z|[+-]\d{2}\d{2})?$"
        ).unwrap();

        let captures = generalized_time_regex
            .captures(value)
            .ok_or_else(|| format!("Wrong generalized time format: `{}`", value))?;

        Ok(Self {
            year: captures.get(1).unwrap().as_str().parse().unwrap(),
            month: captures.get(2).unwrap().as_str().parse().unwrap(),
            day: captures.get(3).unwrap().as_str().parse().unwrap(),
            hour: captures.get(4).unwrap().as_str().parse().unwrap(),
            minute: captures.get(5).map(|m| m.as_str().parse().unwrap()),
            second: captures.get(6).map(|m| m.as_str().parse().unwrap()),
            fraction_of_second: captures
                .get(7)
                .map(|m| {
                    // Remove the leading "."
                    let frac_str = &m.as_str()[1..];
                    frac_str.parse().unwrap()
                }),
            offset: captures
                .get(8)
                .map_or(Ok(None), |m| parse_generalized_offset(m.as_str()))?,
        })
    }

    pub fn format(&self) -> String {
        format!(
            "{:04}{:02}{:02}{:02}{}{}{}{}",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute.map_or("".to_string(), |m| format!("{:02}", m)),
            self.second.map_or("".to_string(), |s| format!("{:02}", s)),
            self.fraction_of_second.map_or("".to_string(), |f| format!(".{}", f)),
            self.offset.as_ref().map_or("Z".to_string(), |o| format!(
                "{}{:02}{:02}",
                if o.hours >= 0 { "+" } else { "-" },
                o.hours.abs(),
                o.minutes.abs()
            )),
        )
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
        assert_eq!(time.offset, Some(UtcOffset { hours: 3, minutes: 0 }));
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
            offset: Some(UtcOffset { hours: 3, minutes: 0 }),
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
        assert_eq!(time.offset, Some(GeneralizedOffset { hours: 3, minutes: 0 }));
    }
}