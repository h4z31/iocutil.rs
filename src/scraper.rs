use failure::Fail;
use lazy_static::lazy_static;
use scraper::{Html, Selector};

lazy_static! {
    static ref ARTICLE_SELECTOR: Selector = Selector::parse("article").unwrap();
    static ref BODY_SELECTOR: Selector = Selector::parse("body").unwrap();
}

/// get html from specified url
pub fn get_html(url: impl AsRef<str>) -> Result<String, failure::Error> {
    Ok(reqwest::get(url.as_ref())?.text()?)
}

pub fn scrape_articles(html: impl AsRef<str>) -> Vec<String> {
    let document = Html::parse_document(html.as_ref());
    document
        .select(&ARTICLE_SELECTOR)
        .into_iter()
        .map(|x| x.text().into_iter().collect::<Vec<_>>().join(" "))
        .collect()
}

pub fn scrape_body(html: impl AsRef<str>) -> Vec<String> {
    let document = Html::parse_document(html.as_ref());
    document
        .select(&BODY_SELECTOR)
        .into_iter()
        .map(|x| x.text().into_iter().collect::<Vec<_>>().join(" "))
        .collect()
}

#[derive(Fail, Debug)]
pub enum ScrapingError {
    #[fail(display = "could not find target elements")]
    TargetNotFound,
}

/// get article (or body) text from specified url
pub fn get_article(url: impl AsRef<str>) -> Result<Vec<String>, failure::Error> {
    let html = get_html(url)?;
    let articles = scrape_articles(&html);
    if !articles.is_empty() {
        return Ok(articles);
    }
    let body = scrape_body(&html);
    if body.is_empty() {
        return Err(ScrapingError::TargetNotFound.into());
    }
    Ok(body)
}
