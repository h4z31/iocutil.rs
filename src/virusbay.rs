use crate::util::unwrap_try_into;
use crate::{GenericResult, SampleHash};
use failure::Fail;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Default)]
pub struct VirusBayClient;

#[derive(Serialize, Deserialize, Debug)]
pub struct Enterprise {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Uploader {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub enterprise: Option<Enterprise>,
}

#[allow(non_snake_case)]
#[derive(Deserialize, Serialize, Debug)]
pub struct Tag {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub lowerCaseName: String,
    pub isHash: bool,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct AVRecord {
    pub ml: String,
    pub av: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct VTReport {
    pub positives: Option<i32>,
    pub total: Option<i32>,
    pub avs: Vec<AVRecord>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SearchResult {
    #[serde(rename = "_id")]
    pub id: String,
    pub uploadedBy: Option<Uploader>,
    pub md5: Option<String>,
    pub tags: Option<Vec<Tag>>,
    pub vt_report: Option<VTReport>,
    pub fileType: Option<String>,
    pub fileSize: Option<String>,
    pub publishDate: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub search: Vec<SearchResult>,
}

#[derive(Fail, Debug)]
pub enum VirusBayError {
    #[fail(display = "sample not found on VirusBay")]
    NotFoundOnVirusBay,
}

impl VirusBayClient {
    fn query_url(&self, hash: impl AsRef<str>) -> String {
        format!("https://beta.virusbay.io/sample/search?q={}", hash.as_ref())
    }

    /// get raw json
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::virusbay::VirusBayClient;
    ///
    /// let client = VirusBayClient::default();
    ///
    /// client.get_raw_json("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ///     .expect("failed to get report");
    /// ```
    pub fn get_raw_json(&self, hash: impl TryInto<SampleHash>) -> GenericResult<String> {
        Ok(reqwest::get(self.query_url(unwrap_try_into(hash)?).as_str())?.text()?)
    }

    /// query with free format
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::virusbay::{VirusBayClient, Response};
    ///
    /// let client = VirusBayClient::default();
    ///
    /// let r: Response = client.query("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ///     .expect("failed to search");
    /// ```
    pub fn query<T>(&self, hash: impl TryInto<SampleHash>) -> GenericResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        Ok(reqwest::get(self.query_url(unwrap_try_into(hash)?).as_str())?.json()?)
    }

    /// formatted query
    /// there are no guarantee for correctness of format.
    /// (I could not find any documents about this.)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use iocutil::virusbay::VirusBayClient;
    ///
    /// let client = VirusBayClient::default();
    /// client.fquery("9fbdc5eca123e81571e8966b9b4e4a1e").expect("failed to retrieve sample 9fbdc5eca123e81571e8966b9b4e4a1e");
    /// ```
    pub fn fquery(&self, hash: impl TryInto<SampleHash>) -> GenericResult<Vec<SearchResult>> {
        let r: Response = self.query(hash)?;
        if r.search.is_empty() {
            return Err(VirusBayError::NotFoundOnVirusBay.into());
        }

        Ok(r.search)
    }
}
