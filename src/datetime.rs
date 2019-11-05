use chrono::{DateTime, Utc};
use time::Duration;

pub fn days_ago(n: i64) -> DateTime<Utc> {
    Utc::now() - Duration::days(n)
}
