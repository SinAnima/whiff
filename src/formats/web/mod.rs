//! `web` extractors (feature `common`): Shockwave Flash and small web
//! files (robots.txt, PAC, Metalink, filter lists, cookie jars, bookmarks,
//! `.netrc`, WARC).

pub(crate) mod misc;
pub(crate) mod swf;

pub(crate) use super::archive::unix_time;
