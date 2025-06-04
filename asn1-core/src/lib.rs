use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asn1UtcTime {
    pub year: i32,
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: Option<i32>,
    pub offset: Option<UtcOffset>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Asn1Offset {
    Utc(UtcOffset),
    Generalized(GeneralizedOffset),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UtcOffset {
    pub hours: i32,
    pub minutes: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeneralizedOffset {
    pub hours: i32,
    pub minutes: i32,
}

// Implementation der Parser-Funktionen
impl Asn1UtcTime {
    pub fn parse(value: &str) -> Result<Self, String> {
        lazy_static! {
            static ref UTC_TIME_REGEX: Regex = 
                Regex::new(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}\d{2})")
                    .unwrap();
        }

        let captures = UTC_TIME_REGEX
            .captures(value)
            .ok_or_else(|| format!("Wrong utc time format: `{}`", value))?;

        Ok(Self {
            year: captures.get(1).unwrap().as_str().parse().unwrap(),
            month: captures.get(2).unwrap().as_str().parse().unwrap(),
            day: captures.get(3).unwrap().as_str().parse().unwrap(),
            hour: captures.get(4).unwrap().as_str().parse().unwrap(),
            minute: captures.get(5).unwrap().as_str().parse().unwrap(),
            second: captures.get(6).map(|m| m.as_str().parse().unwrap()),
            offset: parse_time_zone_or_offset(captures.get(7).unwrap().as_str())?,
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
    } else {
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
    }
}

fn parse_generalized_offset(value: &str) -> Result<Option<GeneralizedOffset>, String> {
    if value == "Z" {
        Ok(None)
    } else {
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
        lazy_static! {
            static ref GENERALIZED_TIME_REGEX: Regex = 
                Regex::new(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(\.\d{1,3})?(Z|[+-]\d{2}\d{2})?")
                    .unwrap();
        }

        let captures = GENERALIZED_TIME_REGEX
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
                .map(|m| m.as_str()[1..].parse().unwrap()),
            offset: captures
                .get(8)
                .map(|m| parse_generalized_offset(m.as_str()))
                .transpose()?.expect("REASON"),
        })
    }
}