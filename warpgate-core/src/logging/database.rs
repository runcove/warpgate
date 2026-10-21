use std::future::Future;
use std::sync::OnceLock;

use sea_orm::query::JsonValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use time::OffsetDateTime;
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
use tracing::{Subscriber, error, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;
pub use warpgate_common::helpers::logging::format_related_ids;
use warpgate_db_entities::LogEntry;

use super::layer::ValuesLogLayer;
use super::values::SerializedRecordValues;

static LOG_SENDER: OnceLock<tokio::sync::broadcast::Sender<LogEntry::ActiveModel>> =
    OnceLock::new();

pub fn make_database_logger_layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let _ = LOG_SENDER.set(tokio::sync::broadcast::channel(1024).0);
    ValuesLogLayer::new(|values, target| {
        if let Some(sender) = LOG_SENDER.get()
            && is_stored_in_database(&target, values.get("message").map_or("", String::as_str))
            && let Some(entry) = values_to_log_entry_data(values, target)
        {
            let _ = sender.send(entry);
        }
    })
}

/// Whether a log event is also written to the database's log table.
///
/// The MySQL proxy logs every statement a client sends ("SQL", with the
/// statement as a field). A busy client turns that into one database write
/// per statement: on one deployment it made the log table about 85% of the
/// database and added constant write load to SQLite. Those lines still reach
/// stdout; only this one per-statement event is kept out of the table,
/// matched by target and message, so every other MySQL session line (login,
/// target, end) is still stored and searchable per session.
fn is_stored_in_database(target: &str, message: &str) -> bool {
    !(target == "warpgate_protocol_mysql::session" && message == "SQL")
}

pub fn install_database_logger(database: DatabaseConnection) {
    tokio::spawn(async move {
        #[allow(clippy::expect_used)]
        let receiver = LOG_SENDER
            .get()
            .expect("Log sender not ready yet")
            .subscribe();
        store_log_entries(receiver, |log_entry| {
            let database = &database;
            async move {
                if let Err(error) = log_entry.insert(database).await {
                    error!(?error, "Failed to store log entry");
                }
            }
        })
        .await;
    });
}

/// Hands every entry from the channel to `store` until the channel closes.
///
/// A receiver that falls behind (a slow or locked database) gets `Lagged`
/// from the broadcast channel once it has dropped entries; that is not the
/// end of the stream, so the loop warns and keeps going. The warning has no
/// session and a non-audit target, so `values_to_log_entry_data` discards
/// it: it cannot feed back into this channel as a stored row.
async fn store_log_entries<T, F, Fut>(mut receiver: Receiver<T>, mut store: F)
where
    T: Clone,
    F: FnMut(T) -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        match receiver.recv().await {
            Ok(log_entry) => store(log_entry).await,
            Err(RecvError::Lagged(skipped)) => {
                warn!(skipped, "Database logger fell behind, log entries were dropped");
            }
            Err(RecvError::Closed) => break,
        }
    }
}

fn values_to_log_entry_data(
    mut values: SerializedRecordValues,
    target: String,
) -> Option<LogEntry::ActiveModel> {
    use sea_orm::ActiveValue::Set;

    let session_id = (*values)
        .remove("session")
        .and_then(|x| Uuid::parse_str(&x).ok());

    // include audit events even if they don't have a session ID
    if session_id.is_none() && target != "audit" {
        return None;
    }

    // In a session, username field = session user
    // outside it's the subject and session_username is the actor
    let username = (*values).remove("session_username").or_else(|| {
        (*values)
            .get("username")
            .cloned()
            .filter(|_| session_id.is_some())
    });
    let related_users = (*values).remove("related_users");
    let related_access_roles = (*values).remove("related_access_roles");
    let related_admin_roles = (*values).remove("related_admin_roles");
    let message = (*values).remove("message").unwrap_or_default();

    Some(LogEntry::ActiveModel {
        id: Set(Uuid::new_v4()),
        text: Set(message),
        target: Set(target),
        values: Set(values
            .into_values()
            .into_iter()
            .map(|(k, v)| (k, JsonValue::from(v)))
            .collect()),
        session_id: Set(session_id),
        username: Set(username),
        related_users: Set(related_users),
        related_access_roles: Set(related_access_roles),
        related_admin_roles: Set(related_admin_roles),
        timestamp: Set(OffsetDateTime::now_utc()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_query_mysql_lines_are_not_stored() {
        assert!(!is_stored_in_database(
            "warpgate_protocol_mysql::session",
            "SQL"
        ));
    }

    #[test]
    fn other_mysql_and_session_lines_are_still_stored() {
        assert!(is_stored_in_database(
            "warpgate_protocol_mysql::session",
            "Selected database: x"
        ));
        assert!(is_stored_in_database(
            "warpgate_protocol_mysql",
            "Session ended"
        ));
        assert!(is_stored_in_database(
            "warpgate_protocol_postgres::session",
            "SQL"
        ));
        assert!(is_stored_in_database("audit", "SQL"));
    }

    #[tokio::test]
    async fn logger_keeps_storing_after_the_channel_lags() {
        let (sender, receiver) = tokio::sync::broadcast::channel::<u32>(2);
        // Four sends into a capacity-2 channel: the receiver lags past 1 and 2.
        for n in 1..=4 {
            sender.send(n).unwrap();
        }
        // Closed only once the buffered entries have been read.
        drop(sender);

        let mut stored = Vec::new();
        store_log_entries(receiver, |n| {
            stored.push(n);
            async {}
        })
        .await;

        // Before the fix the first Lagged ended the loop and nothing was stored.
        assert_eq!(stored, vec![3, 4]);
    }
}
