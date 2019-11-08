//! datetime utilities

use chrono::{DateTime, Utc};
use time::Duration;

/// get datetime n days ago
pub fn days_ago(n: i64) -> DateTime<Utc> {
    Utc::now() - Duration::days(n)
}

/// get datetime after duration from base datetime
pub fn after(base: impl Into<DateTime<Utc>>, after: Duration) -> DateTime<Utc> {
    base.into() + after
}

/// macro datetime at specified condition
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
/// at!(now => 10, minutes); // 10 minutes later
/// at!(now => 1, hours); // 1 hours later
/// at!(now => 10, days); // 10 days later
/// at!(now => 1, weeks); // 1 week later
///
/// let x = vtdatetime(at!(day!(1992, 01, 17).unwrap() => 1, days));
/// assert_eq!(x.as_str(), "1992-01-18T00:00:00")
/// ```
#[macro_export]
macro_rules! at {
    (now) => {
        chrono::Utc::now()
    };
    ($m:expr, minutes ago) => {
        chrono::Utc::now() - time::Duration::minutes($m)
    };
    ($h:expr, hours ago) => {
        chrono::Utc::now() - time::Duration::hours($h)
    };
    ($d:expr, days ago) => {
        chrono::Utc::now() - time::Duration::days($d)
    };
    ($w:expr, weeks ago) => {
        chrono::Utc::now() - time::Duration::weeks($w)
    };
    ($base:expr => $m:expr, minutes) => {
        $crate::datetime::after($base, time::Duration::minutes($m))
    };
    ($base:expr => $h:expr, hours) => {
        $crate::datetime::after($base, time::Duration::hours($h))
    };
    ($base:expr => $d:expr, days) => {
        $crate::datetime::after($base, time::Duration::days($d))
    };
    ($base:expr => $w:expr, weeks) => {
        $crate::datetime::after($base, time::Duration::weeks($w))
    };
    (now => $m:expr, minutes) => {
        $crate::datetime::after(chrono::Utc::now(), time::Duration::minutes($m))
    };
    (now => $h:expr, hours) => {
        $crate::datetime::after(chrono::Utc::now(), time::Duration::hours($h))
    };
    (now => $d:expr, days) => {
        $crate::datetime::after(chrono::Utc::now(), time::Duration::days($d))
    };
    (now => $w:expr, weeks) => {
        $crate::datetime::after(chrono::Utc::now(), time::Duration::weeks($w))
    };
}

/// macro datetime at specified day
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
/// use iocutil::day;
///
/// let a = vtdatetime(day!(1992, 01, 17).unwrap());
/// let b = vtdatetime(day!(1992, 01, 17, start).unwrap());
/// assert_eq!(a.as_str(), "1992-01-17T00:00:00");
/// assert_eq!(b.as_str(), "1992-01-17T00:00:00");
///
/// let c = vtdatetime(day!(1992, 01, 17, end).unwrap());
/// assert_eq!(c.as_str(), "1992-01-17T23:59:59");
/// ```
#[macro_export]
macro_rules! day {
    ($y:literal, $m:literal, $d:literal) => {
        chrono::DateTime::parse_from_rfc3339(
            format!("{:04}-{:02}-{:02}T00:00:00.000000-00:00", $y, $m, $d).as_str(),
        )
    };
    ($y:literal, $m:literal, $d:literal, start) => {
        chrono::DateTime::parse_from_rfc3339(
            format!("{:04}-{:02}-{:02}T00:00:00.000000-00:00", $y, $m, $d).as_str(),
        )
    };
    ($y:literal, $m:literal, $d:literal, end) => {
        chrono::DateTime::parse_from_rfc3339(
            format!("{:04}-{:02}-{:02}T23:59:59.000000-00:00", $y, $m, $d).as_str(),
        )
    };
}

/// get datetime as virustotal query format
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
