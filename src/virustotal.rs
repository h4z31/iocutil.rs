use chrono::Utc;
use failure::Fail;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;

pub struct VirusTotalClient {
    apikey: String,
}

impl VirusTotalClient {
    /// new client with apikey
    pub fn new(apikey: impl AsRef<str>) -> Self {
        VirusTotalClient {
            apikey: apikey.as_ref().to_owned(),
        }
    }

    fn file_report_url(&self, resource: impl AsRef<str>, allinfo: bool) -> String {
        format!(
            "https://www.virustotal.com/vtapi/v2/file/report?apikey={}&allinfo={}&resource={}",
            self.apikey,
            allinfo,
            resource.as_ref()
        )
    }

    fn internal_query<T>(
        &self,
        resource: impl AsRef<str>,
        allinfo: bool,
    ) -> Result<T, failure::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        Ok(reqwest::get(self.file_report_url(resource, allinfo).as_str())?.json()?)
    }

    /// get file report of VirusTotal (with allinfo option)
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct FieldsWhatYouNeed {
    ///     response_code: i32,
    ///     // fields you want to retrieve
    /// }
    ///
    /// let client = VirusTotalClient::default();
    /// let sample = SampleHash::new("d41d8cd98f00b204e9800998ecf8427e").expect("failed to parse hash");
    /// let report: FieldsWhatYouNeed = client.query_filereport_allinfo(sample).expect("failed to retrieve hash");
    /// assert_eq!(report.response_code, 1);
    /// ```
    ///
    pub fn query_filereport_allinfo<T>(
        &self,
        resource: impl AsRef<str>,
    ) -> Result<T, failure::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.internal_query(resource, true)
    }

    /// get raw filereport as text
    pub fn get_raw_filereport_text(
        &self,
        resource: impl AsRef<str>,
        allinfo: bool,
    ) -> Result<String, failure::Error> {
        Ok(reqwest::get(self.file_report_url(resource, allinfo).as_str())?.text()?)
    }

    /// query file report (without allinfo)
    pub fn query_filereport(
        &self,
        resource: impl AsRef<str>,
    ) -> Result<FileReport, failure::Error> {
        let report: RawFileReport = self.internal_query(resource, false)?;
        Ok(report.try_into()?)
    }

    /// batch query file report
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct FieldsWhatYouNeed {
    ///     response_code: i32,
    ///     // fields you want to retrieve
    /// }
    ///
    /// let vtclient = VirusTotalClient::default();
    /// let hashes = &["d41d8cd98f00b204e9800998ecf8427e"];
    /// let items: Vec<Result<FieldsWhatYouNeed, failure::Error>> = vtclient.batch_query_allinfo(hashes);
    /// for item in items {
    ///     item.expect("failed to retrieve");
    /// }
    /// ```
    pub fn batch_query_allinfo<T>(
        &self,
        resources: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Vec<Result<T, failure::Error>>
    where
        T: serde::de::DeserializeOwned,
    {
        resources
            .into_iter()
            .enumerate()
            .inspect(|(idx, _)| {
                if *idx != 0 {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            })
            .map(|(_idx, item)| self.query_filereport_allinfo(item))
            .collect()
    }

    /// batch query file report
    ///
    /// # Example
    ///
    /// ```
    /// use iocutil::prelude::*;
    ///
    /// let vtclient = VirusTotalClient::default();
    /// let hashes = &["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"];
    /// let items = vtclient.batch_query(hashes, true);
    /// for item in items {
    ///     item.expect("failed to retrieve");
    /// }
    /// ```
    ///
    pub fn batch_query(
        &self,
        resources: impl IntoIterator<Item = impl AsRef<str>>,
        public_api: bool,
    ) -> Vec<Result<FileReport, failure::Error>> {
        let sleeptime = if public_api {
            std::time::Duration::from_secs(15)
        } else {
            std::time::Duration::from_secs(1)
        };
        resources
            .into_iter()
            .enumerate()
            .inspect(|(idx, _item)| {
                if *idx != 0 {
                    std::thread::sleep(sleeptime);
                }
            })
            .map(|(_idx, item)| self.query_filereport(item))
            .collect()
    }
}

/// scan_id for virustotal
/// You can use this to get a report at the specific time.
pub fn scan_id(sample: crate::SampleHash, datetime: chrono::DateTime<Utc>) -> String {
    format!("{}-{}", sample.as_ref(), datetime.timestamp())
}

impl Default for VirusTotalClient {
    fn default() -> Self {
        VirusTotalClient {
            apikey: std::env::var("VTAPIKEY")
                .expect("please set VirusTotal API key to environment var $VTAPIKEY"),
        }
    }
}

#[derive(Fail, Debug)]
pub enum VTError {
    #[fail(display = "VT not returned status code 1")]
    ResponseCodeError(i32),

    #[fail(display = "record missing field(s)")]
    MissingFields(String),
}

/// ScanResult item of "scans"
#[derive(Deserialize, Serialize, Debug)]
pub struct ScanResult {
    detected: bool,
    version: Option<String>,
    result: Option<String>,
    update: Option<String>,
}

/// RawFileReport structure (without fields included only in allinfo option)
#[derive(Deserialize, Serialize, Debug)]
pub struct RawFileReport {
    response_code: i32,
    verbose_msg: String,
    sha1: Option<String>,
    sha256: Option<String>,
    md5: Option<String>,
    scan_date: Option<String>,
    permalink: Option<String>,
    positives: Option<u32>,
    total: Option<u32>,
    scans: Option<HashMap<String, ScanResult>>,
}

impl std::convert::TryInto<FileReport> for RawFileReport {
    type Error = VTError;

    fn try_into(self) -> Result<FileReport, Self::Error> {
        if self.response_code != 1 {
            // virustotal returns reposnse code 1 when succeeded to retrieve scan result.
            return Err(VTError::ResponseCodeError(self.response_code));
        }

        Ok(FileReport {
            sha1: self
                .sha1
                .ok_or(VTError::MissingFields("sha1".to_string()))?,
            sha256: self
                .sha256
                .ok_or(VTError::MissingFields("sha256".to_string()))?,
            md5: self.md5.ok_or(VTError::MissingFields("md5".to_string()))?,
            scan_date: self
                .scan_date
                .ok_or(VTError::MissingFields("scan_date".to_string()))?,
            permalink: self
                .permalink
                .ok_or(VTError::MissingFields("permalink".to_string()))?,
            positives: self
                .positives
                .ok_or(VTError::MissingFields("positives".to_string()))?,
            total: self
                .total
                .ok_or(VTError::MissingFields("total".to_string()))?,
            scans: self
                .scans
                .ok_or(VTError::MissingFields("scans".to_string()))?,
        })
    }
}

/// FileReport (without fields included only in allinfo option)
#[derive(Debug, Serialize, Deserialize)]
pub struct FileReport {
    sha1: String,
    sha256: String,
    md5: String,
    scan_date: String,
    permalink: String,
    positives: u32,
    total: u32,
    scans: HashMap<String, ScanResult>,
}
