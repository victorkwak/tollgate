//! Durations (`"100s"`, `"2h"`) and sizes (`"30G"`) in config files.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A positive duration written as text, e.g. `"100s"`, `"20m"`, `"1h30m"`.
///
/// Parsing uses jiff's friendly format. The text is kept for printing the
/// effective config as written.
#[derive(Debug, Clone)]
pub struct DurationSpec {
    raw: String,
    value: Duration,
}

impl DurationSpec {
    /// Parses a positive duration.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let parsed: jiff::SignedDuration = raw
            .trim()
            .parse()
            .map_err(|e| format!("invalid duration {raw:?}: {e}"))?;
        if parsed.is_negative() || parsed.is_zero() {
            return Err(format!("duration {raw:?} must be greater than zero"));
        }
        let value =
            Duration::try_from(parsed).map_err(|e| format!("invalid duration {raw:?}: {e}"))?;
        Ok(Self {
            raw: raw.trim().to_owned(),
            value,
        })
    }

    /// Parses a duration given on the command line (R113): a bare whole
    /// number is seconds; anything else follows [`Self::parse`]. Files
    /// (policy, host config) keep the unit rule and never call this.
    pub fn parse_cli(raw: &str) -> Result<Self, String> {
        let text = raw.trim();
        let bad =
            || format!("invalid duration {raw:?}: write seconds (300) or a unit (300s, 5m, 1h30m)");
        if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
            let secs: u64 = text.parse().map_err(|_| bad())?;
            if secs == 0 {
                return Err(bad());
            }
            return Ok(Self {
                raw: text.to_owned(),
                value: Duration::from_secs(secs),
            });
        }
        Self::parse(text).map_err(|_| bad())
    }

    /// The duration.
    #[must_use]
    pub fn get(&self) -> Duration {
        self.value
    }

    /// The text as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl PartialEq for DurationSpec {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for DurationSpec {}

impl fmt::Display for DurationSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Serialize for DurationSpec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for DurationSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// A byte size written as text: an integer with an optional binary unit
/// `K`, `M`, `G`, `T` (also `KB`/`KiB`, ...; case-insensitive). `"30G"` is
/// 30 GiB.
#[derive(Debug, Clone)]
pub struct SizeSpec {
    raw: String,
    bytes: u64,
}

impl SizeSpec {
    /// Parses a size.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let text = raw.trim();
        let digits_end = text
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len());
        let (num, unit) = text.split_at(digits_end);
        let num: u64 = num.parse().map_err(|_| {
            format!("invalid size {raw:?}: expected an integer and a unit like 30G")
        })?;
        let shift = match unit.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 0,
            "k" | "kb" | "kib" => 10,
            "m" | "mb" | "mib" => 20,
            "g" | "gb" | "gib" => 30,
            "t" | "tb" | "tib" => 40,
            _ => return Err(format!("invalid size {raw:?}: unknown unit {unit:?}")),
        };
        let bytes = num
            .checked_mul(1u64 << shift)
            .ok_or_else(|| format!("size {raw:?} is too large"))?;
        Ok(Self {
            raw: text.to_owned(),
            bytes,
        })
    }

    /// The size in bytes.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl PartialEq for SizeSpec {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for SizeSpec {}

impl fmt::Display for SizeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Serialize for SizeSpec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for SizeSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_use_the_spec_spellings() {
        for (raw, secs) in [
            ("100s", 100),
            ("20m", 1200),
            ("2h", 7200),
            ("1h30m", 5400),
            ("15m", 900),
            ("120s", 120),
        ] {
            assert_eq!(
                DurationSpec::parse(raw).unwrap().get().as_secs(),
                secs,
                "{raw}"
            );
        }
    }

    #[test]
    fn durations_must_be_positive_and_valid() {
        for bad in ["0s", "-5m", "", "soon", "5"] {
            assert!(DurationSpec::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn command_line_durations_take_bare_seconds_r113() {
        for (raw, secs) in [
            ("3000", 3000),
            (" 300 ", 300),
            ("300s", 300),
            ("1h30m", 5400),
        ] {
            assert_eq!(
                DurationSpec::parse_cli(raw).unwrap().get().as_secs(),
                secs,
                "{raw}"
            );
        }
        for bad in [
            "5x",
            "0",
            "0s",
            "-5",
            "1.5",
            "",
            "soon",
            "99999999999999999999",
        ] {
            assert_eq!(
                DurationSpec::parse_cli(bad).unwrap_err(),
                format!(
                    "invalid duration {bad:?}: write seconds (300) or a unit (300s, 5m, 1h30m)"
                ),
            );
        }
        // Files keep the unit rule (R63).
        assert!(DurationSpec::parse("3000").is_err());
    }

    #[test]
    fn sizes_are_binary_units() {
        assert_eq!(SizeSpec::parse("30G").unwrap().bytes(), 30 << 30);
        assert_eq!(SizeSpec::parse("40GiB").unwrap().bytes(), 40 << 30);
        assert_eq!(SizeSpec::parse("512m").unwrap().bytes(), 512 << 20);
        assert_eq!(SizeSpec::parse("1024").unwrap().bytes(), 1024);
        for bad in ["", "G", "1.5G", "3X", "99999999999T"] {
            assert!(SizeSpec::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn serde_keeps_the_written_text() {
        let d: DurationSpec = serde_json::from_str("\"2h\"").unwrap();
        assert_eq!(serde_json::to_string(&d).unwrap(), "\"2h\"");
        assert_eq!(d, DurationSpec::parse("120m").unwrap());
    }
}
