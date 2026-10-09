//! Liveness: whether this node can still write its own database.
//!
//! Answers from memory only (the node's last successful heartbeat), so a
//! locked database cannot make the check hang. Unauthenticated and status
//! only; readiness stays on `/api/info`.

use poem::http::StatusCode;
use poem::web::{Data, Json};
use poem::{IntoResponse, Response, handler};
use serde::Serialize;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::cluster::HeartbeatHealth;

#[derive(Serialize, Debug, PartialEq, Eq)]
struct HealthBody {
    status: &'static str,
    heartbeat_age_seconds: u64,
}

fn health_response(health: HeartbeatHealth) -> (StatusCode, HealthBody) {
    let (status, label) = if health.stale {
        (StatusCode::SERVICE_UNAVAILABLE, "stale")
    } else {
        (StatusCode::OK, "ok")
    };
    (
        status,
        HealthBody {
            status: label,
            heartbeat_age_seconds: health.age_seconds,
        },
    )
}

#[handler]
pub async fn health_endpoint(ctx: Data<&UnauthenticatedRequestContext>) -> Response {
    let (status, body) = health_response(ctx.services().cluster.heartbeat_health());
    Json(body).with_status(status).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_heartbeat_is_200_ok() {
        let (status, body) = health_response(HeartbeatHealth {
            age_seconds: 4,
            stale: false,
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            HealthBody {
                status: "ok",
                heartbeat_age_seconds: 4
            }
        );
    }

    #[test]
    fn a_stale_heartbeat_is_503_stale() {
        let (status, body) = health_response(HeartbeatHealth {
            age_seconds: 120,
            stale: true,
        });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            HealthBody {
                status: "stale",
                heartbeat_age_seconds: 120
            }
        );
    }

    #[test]
    fn the_body_is_exactly_status_and_age() {
        let (_, body) = health_response(HeartbeatHealth {
            age_seconds: 7,
            stale: false,
        });
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"status":"ok","heartbeat_age_seconds":7}"#
        );
    }
}
