use chrono::prelude::*;
use derive_builder::Builder;
use failure::Fail;
use reqwest::header::HeaderValue;
use serde::Deserialize;

use crate::{GenericResult, SampleHash};

/// AlienVaultOTX API Client
pub struct AlienVaultOTXClient {
    apikey: String,
}

#[derive(Debug, Fail)]
pub enum AlienVaultOTXError {
    #[fail(display = "invalid setting")]
    InvalidSettingError(String),
}

impl AlienVaultOTXClient {
    /// make new client
    pub fn new(apikey: String) -> Self {
        AlienVaultOTXClient { apikey }
    }

    /// get pulses modified from specified datetime
    pub fn pulses_from(&self, datetime: DateTime<Utc>) -> GenericResult<Vec<Pulse>> {
        Ok(PulsesBuilder::default()
            .api_key(self.apikey.clone())
            .modified_since(datetime)
            .build()
            .map_err(AlienVaultOTXError::InvalidSettingError)?
            .get_all())
    }

    /// get pulses for x days
    pub fn pulses_for(&self, days: i64) -> GenericResult<Vec<Pulse>> {
        self.pulses_from(Utc::now() - time::Duration::days(days))
    }
}

#[derive(Builder, Debug)]
pub struct Pulses {
    #[builder(
        default = "std::env::var(\"OTX_APIKEY\").map_err(|_err| \"could not get OTX APIKEY\".to_owned())?"
    )]
    api_key: String,
    #[builder(default = "50")]
    limit: u32,
    #[builder(default = "1")]
    page: u32,
    #[builder(default = "Utc::now() - time::Duration::days(7)")]
    modified_since: DateTime<Utc>,
    #[builder(default = "false")]
    has_done: bool,
}

#[derive(Debug, Deserialize)]
pub enum IndicatorType {
    IPv4,
    IPv6,
    #[serde(rename = "domain")]
    Domain,
    #[serde(rename = "hostname")]
    Hostname,
    #[serde(rename = "email")]
    Email,
    URL,
    URI,
    #[serde(rename = "FileHash-MD5")]
    MD5,
    #[serde(rename = "FileHash-SHA1")]
    SHA1,
    #[serde(rename = "FileHash-SHA256")]
    SHA256,
    #[serde(rename = "FileHash-PEHASH")]
    PEHash,
    #[serde(rename = "FileHash-IMPHASH")]
    IMPHash,
    CIDR,
    FilePath,
    Mutex,
    CVE,
    YARA,
    #[serde(other)]
    Unknown,
}

/// ref. https://github.com/AlienVault-OTX/OTX-Go-SDK/blob/master/src/otxapi/pulses.go#L19

#[derive(Debug, Deserialize)]
pub struct Indicator {
    pub id: i64,
    pub indicator: String,
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub _type: IndicatorType,
}

/// ref. https://github.com/AlienVault-OTX/OTX-Go-SDK/blob/master/src/otxapi/pulses.go#L10
#[derive(Debug, Deserialize)]
pub struct Pulse {
    pub id: String,
    pub name: String,
    pub author_name: String,
    pub description: Option<String>,
    pub created: Option<String>,
    pub modified: String,
    pub references: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub targeted_countries: Vec<String>,
    pub indicators: Option<Vec<Indicator>>,
    pub revision: Option<i64>,
    pub adversary: Option<String>,
}

impl Into<Vec<SampleHash>> for Pulse {
    fn into(self) -> Vec<SampleHash> {
        self.indicators
            .unwrap_or_default()
            .into_iter()
            .map(|x| SampleHash::new(x.indicator))
            .flat_map(|x| x)
            .collect()
    }
}

/// hashes in specified pulses
pub fn hashes_in(pulses: Vec<Pulse>) -> Vec<SampleHash> {
    pulses
        .into_iter()
        .map(|x| x.into())
        .flat_map(|x: Vec<SampleHash>| x)
        .collect()
}

/// Response from subscribed API
#[derive(Debug, Deserialize)]
pub struct Response {
    pub count: i64,
    pub next: Option<String>,
    pub previous: Option<String>,
    pub results: Vec<Pulse>,
}

impl Pulses {
    /// request page
    fn request(&mut self) -> GenericResult<Response> {
        let res: Response = reqwest::Client::new()
            .get(format!(
                "https://otx.alienvault.com/api/v1/pulses/subscribed?limit={}&page={}&modified_since={}",
                self.limit,
                self.page,
                self.modified_since.to_rfc3339()).as_str()
            )
            .header("X-OTX-API-KEY", HeaderValue::from_str(self.api_key.as_str()).unwrap())
            .send()?
            .json()?;

        // update page number
        self.page += 1;

        // it's done if next is null(or maybe empty).
        if res.next == None {
            self.has_done = true;
        }

        Ok(res)
    }

    /// get all matched pulses
    pub fn get_all(self) -> Vec<Pulse> {
        self.flat_map(|x| x).collect()
    }

    /// get all hashes in all matched pulse
    pub fn get_all_hashes(self) -> Vec<SampleHash> {
        hashes_in(self.get_all())
    }
}

impl Iterator for Pulses {
    type Item = Vec<Pulse>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.has_done {
            // No more pages.
            None
        } else {
            if self.page != 1 {
                //  wait 1 second before request
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            // request a page
            self.request().and_then(|x| Ok(x.results)).ok()
        }
    }
}
