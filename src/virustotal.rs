use chrono::Utc;
use failure::Fail;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;

use crate::util::unwrap_try_into;
use crate::{GenericResult, SampleHash};

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

    fn download_url(&self, hash: impl AsRef<str>) -> String {
        format!(
            "https://www.virustotal.com/vtapi/v2/file/download?apikey={}&hash={}",
            self.apikey,
            hash.as_ref()
        )
    }

    fn internal_query<T>(&self, resource: impl AsRef<str>, allinfo: bool) -> GenericResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut res = reqwest::get(self.file_report_url(resource, allinfo).as_str())?;
        if res.status().is_success() == false {
            return Err(VTError::RequestFailed.into());
        }
        Ok(res.json()?)
    }

    /// get file report of VirusTotal (with allinfo option)
    ///
    /// # Example
    ///
    /// ```ignore
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
    pub fn query_filereport_allinfo<T>(&self, resource: impl AsRef<str>) -> GenericResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.internal_query(resource, true)
    }

    /// get raw filereport as text
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = VirusTotalClient::default();
    /// let json_text = client.get_raw_filereport_json(
    ///         "d41d8cd98f00b204e9800998ecf8427e",
    ///         false,
    ///     ).expect("failed to get report");
    /// ```
    pub fn get_raw_filereport_json(
        &self,
        resource: impl AsRef<str>,
        allinfo: bool,
    ) -> GenericResult<String> {
        let mut res = reqwest::get(self.file_report_url(resource, allinfo).as_str())?;
        if res.status().is_success() == false {
            return Err(VTError::RequestFailed.into());
        }
        Ok(res.text()?)
    }

    /// get raw filereport json at specified datetime
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = VirusTotalClient::default();
    /// let json_text = client.get_raw_filereport_json_at(
    ///         "d41d8cd98f00b204e9800998ecf8427e",
    ///         false,
    ///         days_ago(7)
    ///     ).expect("failed to get report");
    /// ```
    pub fn get_raw_filereport_json_at(
        &self,
        hash: impl TryInto<SampleHash>,
        allinfo: bool,
        datetime: chrono::DateTime<Utc>,
    ) -> GenericResult<String> {
        let hash = unwrap_try_into(hash)?;
        let r = scan_id(hash, datetime);
        self.get_raw_filereport_json(r, allinfo)
    }

    /// query_filereport_at
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    /// let client = VirusTotalClient::default();
    ///
    /// let report = client.query_filereport_at(
    ///         "d41d8cd98f00b204e9800998ecf8427e",
    ///         days_ago(7)
    ///     ).expect("failed to query");
    /// ```
    pub fn query_filereport_at(
        &self,
        hash: impl TryInto<SampleHash>,
        datetime: chrono::DateTime<Utc>,
    ) -> GenericResult<FileReport> {
        let hash = unwrap_try_into(hash)?;
        let r = scan_id(hash, datetime);
        self.query_filereport(r)
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
    /// ```ignore
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
    /// ```ignore
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

    /// download a file from hash
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = VirusTotalClient::default();
    /// client.download(
    ///         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ///         "./e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ///     ).expect("failed to download file");
    ///
    /// std::fs::remove_file("./e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ///     .expect("failed to remove file");
    /// ```
    pub fn download(
        &self,
        hash: impl TryInto<SampleHash>,
        into: impl AsRef<std::path::Path>,
    ) -> Result<(), failure::Error> {
        let h = unwrap_try_into(hash)?;
        let h = h.as_ref();

        let mut res = reqwest::get(self.download_url(h).as_str())?;
        if !res.status().is_success() {
            return Err(VTError::DownloadFailed(h.to_owned()).into());
        }

        let mut f = std::fs::File::create(into)?;
        std::io::copy(&mut res, &mut f)?;

        Ok(())
    }

    /// search by page (Private API required)
    /// https://www.virustotal.com/intelligence/help/file-search/#search-modifiers
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = VirusTotalClient::default();
    /// let mut pages = client.search_by_pages("p:5+ AND submitter:CN", Some(600));
    ///
    /// let samples: Vec<_> = pages.do_search().expect("failed to search");
    /// assert_eq!(samples.len(), 300)
    /// ```
    pub fn search_by_pages(&self, query: impl AsRef<str>, goal: Option<usize>) -> Search {
        Search::new(&self.apikey, query, goal)
    }

    /// search samples (Private API required)
    /// https://www.virustotal.com/intelligence/help/file-search/#search-modifiers
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::prelude::*;
    ///
    /// let client = VirusTotalClient::default();
    ///
    /// let samples: Vec<_> = client.search("p:5+ AND submitter:CN", Some(600));
    /// assert_eq!(samples.len(), 600)
    /// ```
    pub fn search<T>(&self, query: impl AsRef<str>, goal: Option<usize>) -> T
    where
        T: std::iter::FromIterator<SampleHash>,
    {
        self.search_by_pages(query, goal)
            .into_iter()
            .flat_map(|x| x)
            .collect()
    }
}

pub struct Search {
    apikey: String,
    query: String,
    goal: Option<usize>,
    offset: Option<String>,
    current: usize,
    has_done: bool,
}

impl Search {
    /// create new object
    pub fn new(apikey: impl AsRef<str>, query: impl AsRef<str>, goal: Option<usize>) -> Self {
        Search {
            apikey: apikey.as_ref().to_owned(),
            query: Search::escape_search_query(query),
            offset: None,
            current: 0,
            has_done: false,
            goal,
        }
    }

    fn escape_search_query(query: impl AsRef<str>) -> String {
        utf8_percent_encode(query.as_ref(), NON_ALPHANUMERIC).to_string()
    }

    fn search_url(&self, offset: &Option<String>) -> String {
        match offset {
            Some(o) => format!(
                "https://www.virustotal.com/vtapi/v2/file/search?apikey={}&query={}&offset={}",
                self.apikey.as_str(),
                self.query.as_str(),
                o,
            ),
            None => format!(
                "https://www.virustotal.com/vtapi/v2/file/search?apikey={}&query={}",
                self.apikey.as_str(),
                self.query.as_str(),
            ),
        }
    }

    /// do search once (most 300 samples per a page)
    pub fn do_search<T>(&mut self) -> GenericResult<T>
    where
        T: std::iter::FromIterator<SampleHash>,
    {
        if self.has_done {
            return Err(VTError::AlreadyReachToGoal.into());
        }

        let url = self.search_url(&self.offset);

        let mut res = reqwest::get(url.as_str())?;
        if !res.status().is_success() {
            return Err(VTError::RequestFailed.into());
        }

        let result: SearchResponse = res.json()?;
        if result.response_code != 1 {
            return Err(VTError::ResponseCodeError(result.response_code).into());
        }

        let hashes = result.hashes.ok_or(VTError::RequestFailed)?;

        if let Some(x) = self.goal {
            self.current += hashes.len();
            if x <= self.current {
                self.has_done = true;
            }
        }

        if result.offset.is_none() {
            self.has_done = true;
        }

        self.offset = result.offset;

        SampleHash::try_map(hashes)
    }
}

impl Iterator for Search {
    type Item = Vec<SampleHash>;

    fn next(&mut self) -> Option<Self::Item> {
        self.do_search().ok()
    }
}

/// scan_id for virustotal
/// You can use this to get a report at the specific time.
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
///
/// let client = VirusTotalClient::default();
///
/// let sample =  SampleHash::new("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
/// let sid = scan_id(sample, at!(1, weeks ago));
///
/// // let report_at_one_week_ago = client.query_filereport(sid).unwrap();
/// ```
pub fn scan_id(sample: crate::SampleHash, datetime: impl Into<chrono::DateTime<Utc>>) -> String {
    format!("{}-{}", sample.as_ref(), datetime.into().timestamp())
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

    #[fail(display = "download failed")]
    DownloadFailed(String),

    #[fail(
        display = "request failed. Usually, it caused by wrong query. Or it's a Private API if you use public API key."
    )]
    RequestFailed,

    #[fail(display = "already reach to goal")]
    AlreadyReachToGoal,
}

/// ScanResult item of "scans"
#[derive(Deserialize, Serialize, Debug)]
pub struct ScanResult {
    pub detected: bool,
    pub version: Option<String>,
    pub result: Option<String>,
    pub update: Option<String>,
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
    pub sha1: String,
    pub sha256: String,
    pub md5: String,
    pub scan_date: String,
    pub permalink: String,
    pub positives: u32,
    pub total: u32,
    pub scans: HashMap<String, ScanResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    response_code: i32,
    offset: Option<String>,
    hashes: Option<Vec<String>>,
}

/// macro provides easy way to make format for query first submission
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
///
/// let f = day!(2019, 11, 01).unwrap();
/// let t = day!(2019, 11, 02).unwrap();
/// let fs1 = fs!(f => t);
/// assert_eq!(fs1.as_str(), "(fs:2019-11-01T00:00:00+ AND fs:2019-11-02T00:00:00-)");
///
/// let fs2 = fs!(f =>);
/// assert_eq!(fs2.as_str(), "fs:2019-11-01T00:00:00+");
///
/// let fs3 = fs!(=> t);
/// assert_eq!(fs3.as_str(), "fs:2019-11-02T00:00:00-");
///
/// let for_a_week = fs!(at!(1, weeks ago) =>);
/// ```
#[macro_export]
macro_rules! fs {
    ($from:expr => $to:expr) => {
        format!(
            "(fs:{}+ AND fs:{}-)",
            $crate::datetime::vtdatetime($from),
            $crate::datetime::vtdatetime($to)
        )
    };
    ($from:expr =>) => {
        format!("fs:{}+", $crate::datetime::vtdatetime($from))
    };
    (=> $to:expr) => {
        format!("fs:{}-", $crate::datetime::vtdatetime($to))
    };
}

/// macro provides easy way to make format for query last submission
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
///
/// let f = day!(2019, 11, 01).unwrap();
/// let t = day!(2019, 11, 02).unwrap();
/// let ls1 = ls!(f => t);
/// assert_eq!(ls1.as_str(), "(ls:2019-11-01T00:00:00+ AND ls:2019-11-02T00:00:00-)");
///
/// let ls2 = ls!(f =>);
/// assert_eq!(ls2.as_str(), "ls:2019-11-01T00:00:00+");
///
/// let ls3 = ls!(=> t);
/// assert_eq!(ls3.as_str(), "ls:2019-11-02T00:00:00-");
///
/// let for_a_week = ls!(at!(1, weeks ago) =>);
/// ```
#[macro_export]
macro_rules! ls {
    ($from:expr => $to:expr) => {
        format!(
            "(ls:{}+ AND ls:{}-)",
            $crate::datetime::vtdatetime($from),
            $crate::datetime::vtdatetime($to)
        )
    };
    ($from:expr =>) => {
        format!("ls:{}+", $crate::datetime::vtdatetime($from))
    };
    (=> $to:expr) => {
        format!("ls:{}-", $crate::datetime::vtdatetime($to))
    };
}

/// macro provides easy way to make format for query last analysis
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
///
/// let f = day!(2019, 11, 01).unwrap();
/// let t = day!(2019, 11, 02).unwrap();
///
/// let la1 = la!(f => t);
/// assert_eq!(la1.as_str(), "(la:2019-11-01T00:00:00+ AND la:2019-11-02T00:00:00-)");
///
/// let la2 = la!(f =>);
/// assert_eq!(la2.as_str(), "la:2019-11-01T00:00:00+");
///
/// let la3 = la!(=> t);
/// assert_eq!(la3.as_str(), "la:2019-11-02T00:00:00-");
///
/// let for_a_week = la!(at!(1, weeks ago) =>);
/// ```
#[macro_export]
macro_rules! la {
    ($from:expr => $to:expr) => {
        format!(
            "(la:{}+ AND la:{}-)",
            $crate::datetime::vtdatetime($from),
            $crate::datetime::vtdatetime($to)
        )
    };
    ($from:expr =>) => {
        format!("la:{}+", $crate::datetime::vtdatetime($from))
    };
    (=> $to:expr) => {
        format!("la:{}-", $crate::datetime::vtdatetime($to))
    };
}

/// macro provides easy way to make format for query positive numbers
///
/// # Example
///
/// ```
/// use iocutil::prelude::*;
///
/// let p1 = p!(1 => 10);
/// assert_eq!(p1.as_str(), "(p:1+ AND p:10-)");
///
/// let p2 = p!(1 =>);
/// assert_eq!(p2.as_str(), "p:1+");
///
/// let p3 = p!(=> 10);
/// assert_eq!(p3.as_str(), "p:10-");
/// ```
#[macro_export]
macro_rules! p {
    ($from:expr => $to:expr) => {
        format!("(p:{}+ AND p:{}-)", $from, $to)
    };
    ($num:expr =>) => {
        format!("p:{}+", $num)
    };
    (=> $num:expr) => {
        format!("p:{}-", $num)
    };
}
