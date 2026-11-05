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
