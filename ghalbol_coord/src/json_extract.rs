//! JSON body extractor — rejects with [`ServerError::BadRequest`] (not Axum's default 422).

use axum::body::Body;
use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;
use serde::de::DeserializeOwned;

pub struct ApiJson<T>(pub T);

fn wants_json_content_type(headers: &HeaderMap) -> bool {
    let Some(raw) = headers.get(CONTENT_TYPE) else {
        return false;
    };
    let Ok(value) = raw.to_str() else {
        return false;
    };
    value
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|mime| mime.eq_ignore_ascii_case("application/json"))
}

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = crate::error::ServerError;

    async fn from_request(req: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        if !wants_json_content_type(&parts.headers) {
            return Err(crate::error::ServerError::BadRequest(
                "content-type must be application/json".into(),
            ));
        }
        let bytes = axum::body::to_bytes(body, crate::MAX_REQUEST_BODY_BYTES)
            .await
            .map_err(|_| {
                crate::error::ServerError::BadRequest("request body too large".into())
            })?;
        let value: T = serde_json::from_slice(&bytes).map_err(|err| {
            if err.is_syntax() {
                crate::error::ServerError::BadRequest("malformed json".into())
            } else {
                crate::error::ServerError::BadRequest("json field invalid".into())
            }
        })?;
        Ok(ApiJson(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use serde::Deserialize;
    use tower::ServiceExt;

    #[derive(Deserialize)]
    struct Ping {
        x: u8,
    }

    async fn handle_ping(ApiJson(p): ApiJson<Ping>) -> &'static str {
        if p.x == 1 {
            "ok"
        } else {
            "no"
        }
    }

    fn ping_app() -> Router {
        Router::new().route("/ping", post(handle_ping))
    }

    #[tokio::test]
    async fn rejects_missing_content_type() {
        let app = ping_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ping")
                    .body(Body::from(r#"{"x":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_oversized_body_without_router_layer() {
        let app = ping_app();
        let pad = "a".repeat(crate::MAX_REQUEST_BODY_BYTES);
        let body = format!(r#"{{"x":1,"pad":"{pad}"}}"#);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/ping")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
