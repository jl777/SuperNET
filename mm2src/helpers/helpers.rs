//! A common dependency for the non-WASM crates.
//! 
//!                  helpers
//!                     ^
//!                     |
//!     subcrate A   ---+---   subcrate B
//!         ^                      ^
//!         |                      |
//!         +-----------+----------+
//!                     |
//!                   main

extern crate libc;
extern crate hyper;
extern crate hyper_tls;
extern crate serde;
extern crate serde_json;
extern crate futures_cpupool;

use libc::malloc;
use std::os::raw::c_char;
use std::intrinsics::copy;

use hyper::{ Client, Request };
use hyper::header::{ HeaderValue, CONTENT_TYPE };
use hyper_tls::HttpsConnector;
use hyper::rt::{ self, Future, Stream };
use futures_cpupool::CpuPool;

/// Helps sharing a string slice with C code by allocating a zero-terminated string with the C standard library allocator.
/// 
/// The difference from `CString` is that the memory is then *owned* by the C code instead of being temporarily borrowed,
/// that is it doesn't need to be recycled in Rust.
/// Plus we don't check the slice for zeroes, most of our code doesn't need that extra check.
pub fn str_to_malloc (s: &str) -> *mut c_char {unsafe {
    let buf = malloc (s.len() + 1) as *mut u8;
    copy (s.as_ptr(), buf, s.len());
    *buf.offset (s.len() as isize) = 0;
    buf as *mut c_char
}}

// Define a type so we can return multiple types of errors
#[derive(Debug)]
pub enum FetchError {
    Http(hyper::Error),
    Json(serde_json::Error),
}

impl From<hyper::Error> for FetchError {
    fn from(err: hyper::Error) -> FetchError {
        FetchError::Http(err)
    }
}

impl From<serde_json::Error> for FetchError {
    fn from(err: serde_json::Error) -> FetchError {
        FetchError::Json(err)
    }
}

pub fn fetch_json<T: 'static>(url: hyper::Uri) -> impl Future<Item=T, Error=FetchError>
    where T: serde::de::DeserializeOwned + std::marker::Send {
    let pool = CpuPool::new(1);
    let https = HttpsConnector::new(4).unwrap();
    let client = Client::builder()
        .executor(pool.clone())
        .build::<_, hyper::Body>(https);

    pool.spawn(
        client
            // Fetch the url...
            .get(url)
            // And then, if we get a response back...
            .and_then(|res| {
                // asynchronously concatenate chunks of the body
                res.into_body().concat2()
            })
            .from_err::<FetchError>()
            // use the body after concatenation
            .and_then(|body| {
                // try to parse as json with serde_json
                let result = serde_json::from_slice(&body)?;

                Ok(result)
            })
            .from_err()
    )
}

pub fn post_json<T: 'static>(url: hyper::Uri, json: String) -> impl Future<Item=T, Error=FetchError>
    where T: serde::de::DeserializeOwned + std::marker::Send {
    let pool = CpuPool::new(1);
    let https = HttpsConnector::new(4).unwrap();
    let client = Client::builder()
        .executor(pool.clone())
        .build::<_, hyper::Body>(https);

    let request = Request::builder()
        .method("POST")
        .uri(url)
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json")
        )
        .body(json.into())
        .unwrap();

    pool.spawn(
        client
            // Post the url...
            .request(request)
            // And then, if we get a response back...
            .and_then(|res| {
                // asynchronously concatenate chunks of the body
                res.into_body().concat2()
            })
            .from_err::<FetchError>()
            // use the body after concatenation
            .and_then(|body| {
                // try to parse as json with serde_json
                let result = serde_json::from_slice(&body)?;

                Ok(result)
            })
            .from_err()
    )
}

//? pub fn bytes_to_malloc (slice: &[u8]) -> *mut c_void
