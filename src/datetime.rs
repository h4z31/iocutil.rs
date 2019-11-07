use chrono::{DateTime, Utc};
use time::Duration;

pub fn days_ago(n: i64) -> DateTime<Utc> {
    Utc::now() - Duration::days(n)
}

/// get datetime after duration from base datetime
pub fn after(base: impl Into<DateTime<Utc>>, after: Duration) -> DateTime<Utc> {
    base.into() + after
}

/// macro provides datetime at
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
///
/// let now = at!(now);
/// let ten_minutes_ago = at!(10, minutes ago);
/// let three_hours_ago = at!(3, hours ago);
/// let two_days_ago = at!(2, days ago);
/// let two_week_ago = at!(2, weeks ago);
/// at!(ten_minutes_ago => 5, minutes); // 5 minutes ago
/// at!(three_hours_ago => 1, hours); // 2 hours ago
/// at!(two_days_ago => 1, days); // a day ago
/// at!(two_week_ago => 1, weeks); // a week ago
///
/// let x = vtdatetime(at!(day!(1992, 01, 17).unwrap() => 1, days));
/// assert_eq!(x.as_str(), "1992-01-18T00:00:00")
/// ```
#[macro_export]
macro_rules! at {
    (now) => {
        chrono::Utc::now()
    };
    ($m:literal, minutes ago) => {
        chrono::Utc::now() - time::Duration::minutes($m)
    };
    ($h:literal, hours ago) => {
        chrono::Utc::now() - time::Duration::hours($h)
    };
    ($d:literal, days ago) => {
        chrono::Utc::now() - time::Duration::days($d)
    };
    ($w:literal, weeks ago) => {
        chrono::Utc::now() - time::Duration::weeks($w)
    };
    ($base:expr => $m:literal, minutes) => {
        iocutil::datetime::after($base, time::Duration::minutes($m))
    };
    ($base:expr => $h:literal, hours) => {
        iocutil::datetime::after($base, time::Duration::hours($h))
    };
    ($base:expr => $d:literal, days) => {
        iocutil::datetime::after($base, time::Duration::days($d))
    };
    ($base:expr => $w:literal, weeks) => {
        iocutil::datetime::after($base, time::Duration::weeks($w))
    };
}

/// macro provide day
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
/// use iocutil::day;
/// let b = vtdatetime(day!(1992, 01, 17).unwrap());
/// assert_eq!(b.as_str(), "1992-01-17T00:00:00")
/// ```
#[macro_export]
macro_rules! day {
    ($y:literal, $m:literal, $d:literal) => {
        chrono::DateTime::parse_from_rfc3339(
            format!("{:04}-{:02}-{:02}T00:00:00.000000-00:00", $y, $m, $d).as_str(),
        )
    };
}

/// virustotal query format
///
/// # Example
///
/// ```
/// use iocutil::datetime::*;
/// use chrono::{Utc, DateTime};
/// let datetime = DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").unwrap();
/// let x = vtdatetime(datetime);
/// assert_eq!("1996-12-20T00:39:57", x.as_str());
/// ```
pub fn vtdatetime(datetime: impl Into<DateTime<Utc>>) -> String {
    datetime.into().format("%FT%T").to_string()
}
