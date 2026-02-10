use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};

pub fn from_unix(input: &str, millis: bool) -> Result<String> {
    let ts: i64 = input
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid unix timestamp: {e}"))?;

    let dt = if millis {
        Utc.timestamp_millis_opt(ts)
            .single()
            .ok_or_else(|| anyhow!("Timestamp milliseconds out of range"))?
    } else {
        Utc.timestamp_opt(ts, 0)
            .single()
            .ok_or_else(|| anyhow!("Timestamp seconds out of range"))?
    };

    Ok(dt.to_rfc3339_opts(SecondsFormat::Millis, true))
}

pub fn to_unix(input: &str, millis: bool) -> Result<i64> {
    let text = input.trim();

    let dt_utc = if let Ok(dt) = DateTime::parse_from_rfc3339(text) {
        dt.with_timezone(&Utc)
    } else if let Ok(naive_dt) = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S") {
        DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc)
    } else if let Ok(naive_date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        DateTime::<Utc>::from_naive_utc_and_offset(
            naive_date
                .and_hms_opt(0, 0, 0)
                .ok_or_else(|| anyhow!("Invalid date"))?,
            Utc,
        )
    } else {
        return Err(anyhow!(
            "Failed to parse datetime. Use RFC3339, 'YYYY-MM-DD HH:MM:SS', or 'YYYY-MM-DD'"
        ));
    };

    Ok(if millis {
        dt_utc.timestamp_millis()
    } else {
        dt_utc.timestamp()
    })
}

#[cfg(test)]
mod test {
    use super::{from_unix, to_unix};

    #[test]
    fn from_unix_seconds() {
        assert_eq!(from_unix("0", false).unwrap(), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn from_unix_millis() {
        assert_eq!(
            from_unix("1704067200123", true).unwrap(),
            "2024-01-01T00:00:00.123Z"
        );
    }

    #[test]
    fn to_unix_from_rfc3339() {
        assert_eq!(to_unix("1970-01-01T00:00:01Z", false).unwrap(), 1);
    }

    #[test]
    fn to_unix_from_space_datetime() {
        assert_eq!(to_unix("1970-01-01 00:00:01", false).unwrap(), 1);
    }

    #[test]
    fn to_unix_from_date_only() {
        assert_eq!(to_unix("1970-01-02", false).unwrap(), 86400);
    }

    #[test]
    fn invalid_timestamp() {
        let err = from_unix("abc", false).unwrap_err().to_string();
        assert!(err.contains("Invalid unix timestamp"));
    }

    #[test]
    fn invalid_datetime() {
        let err = to_unix("not-a-date", false).unwrap_err().to_string();
        assert!(err.contains("Failed to parse datetime"));
    }
}
