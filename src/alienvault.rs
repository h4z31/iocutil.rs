//! AlienVault OTX client and its utilities

use crate::util::unwrap_try_into;
use chrono::prelude::*;
use derive_builder::Builder;
use failure::Fail;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use std::convert::TryInto;

use crate::datetime::days_ago;
use crate::{GenericResult, SampleHash};

/// AlienVaultOTX API Client (default use `$OTX_APIKEY` environment variable as apikey)
pub struct AlienVaultOTXClient {
    apikey: String,
}

impl Default for AlienVaultOTXClient {
    fn default() -> Self {
        AlienVaultOTXClient {
            apikey: std::env::var("OTX_APIKEY")
                .expect("please set AlienVault OTX API key to environment var $OTX_APIKEY"),
        }
    }
}

/// Errors in operating AlienVault OTX
#[derive(Debug, Fail)]
pub enum AlienVaultOTXError {
    #[fail(display = "invalid setting")]
    InvalidSetting(String),

    #[fail(display = "request failed")]
    RequestFailed,
}

/// QueryType when query about a indicator
#[derive(Debug)]
pub enum QueryType {
    General,
    Analysis,
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            QueryType::General => write!(f, "general"),
            QueryType::Analysis => write!(f, "analysis"),
        }
    }
}

impl AlienVaultOTXClient {
    /// make new client
    pub fn new(apikey: String) -> Self {
        AlienVaultOTXClient { apikey }
    }

    /// get pulses modified from specified datetime
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = AlienVaultOTXClient::default();
    /// let pulses = client.pulses_from(days_ago(7));
    /// ```
    pub fn pulses_from(&self, datetime: impl Into<DateTime<Utc>>) -> GenericResult<Vec<Pulse>> {
        Ok(PulsesBuilder::default()
            .api_key(self.apikey.clone())
            .modified_since(datetime.into())
            .build()
            .map_err(AlienVaultOTXError::InvalidSetting)?
            .get_all())
    }

    /// get pulses for x days
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = AlienVaultOTXClient::default();
    /// let pulses = client.pulses_for(7); // get for 7 days
    /// ```
    pub fn pulses_for(&self, days: i64) -> GenericResult<Vec<Pulse>> {
        self.pulses_from(days_ago(days))
    }

    /// make indicator url
    fn indicator_url(&self, hash: impl AsRef<str>, section: QueryType) -> String {
        format!(
            "https://otx.alienvault.com/api/v1/indicators/file/{}/{}",
            hash.as_ref(),
            section
        )
    }

    /// make get request
    fn make_get_request(&self, url: impl AsRef<str>) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .get(url.as_ref())
            .header("X-OTX-API-KEY", self.apikey.as_str())
    }

    /// get raw json report about indicator
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = AlienVaultOTXClient::default();
    /// let general = client.get_raw_json("4451058bebb3385efa33d41c30566646", QueryType::General).unwrap();
    /// let analysis = client.get_raw_json("4451058bebb3385efa33d41c30566646", QueryType::Analysis).unwrap();
    /// ```
    pub fn get_raw_json(
        &self,
        hash: impl TryInto<SampleHash>,
        section: QueryType,
    ) -> GenericResult<String> {
        let hash = unwrap_try_into(hash)?;

        let mut res = self
            .make_get_request(self.indicator_url(hash, section))
            .send()?;

        if !res.status().is_success() {
            return Err(AlienVaultOTXError::RequestFailed.into());
        }

        Ok(res.text()?)
    }

    /// query with free format
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Response {
    ///     page_type: String,
    ///     // ...
    /// }
    ///
    /// let client = AlienVaultOTXClient::default();
    /// let report: Response = client.query("4451058bebb3385efa33d41c30566646", QueryType::Analysis).unwrap();
    /// assert_eq!(report.page_type.as_str(), "ELF");
    /// ```
    pub fn query<T>(&self, hash: impl TryInto<SampleHash>, section: QueryType) -> GenericResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let hash = unwrap_try_into(hash)?;
        let mut res = self
            .make_get_request(self.indicator_url(hash, section))
            .send()?;

        if !res.status().is_success() {
            return Err(AlienVaultOTXError::RequestFailed.into());
        }

        Ok(res.json()?)
    }
}

/// request context object for pulses subscribed api
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
    #[builder(default = "days_ago(7)")]
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

/// a indicator in pulse
#[derive(Debug, Deserialize)]
pub struct Indicator {
    pub id: i64,
    pub indicator: String,
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub _type: IndicatorType,
}

/// a pulse
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

impl Pulse {
    /// get webpage url of pulse
    pub fn get_url(&self) -> String {
        format!("https://otx.alienvault.com/pulse/{}", self.id)
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
