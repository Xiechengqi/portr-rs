//! In-memory tracker for recent proxy requests, keyed by user-origin country.
//!
//! Two views are exposed via [`RecentTraffic::snapshot`]:
//! - **`country_counts`** — ISO 3166-1 alpha-3 → request count over the last
//!   [`COUNTRY_WINDOW`]. Drives the dashboard's "demand" overlay.
//! - **`recent_events`** — last [`MAX_EVENTS`] request starts. Drives the burst-arc
//!   animation; the frontend dedupes by `request_id`.
//!
//! No persistence — the tracker lives inside `ServerState` and resets on restart.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::geo::iso2_to_iso3;

/// Sliding window for country count aggregation.
const COUNTRY_WINDOW_SECS: i64 = 5 * 60;
/// Maximum number of events held in the ring buffer.
const MAX_EVENTS: usize = 64;
/// Hard cap on retained event records — protects memory under sustained spikes.
const MAX_RETAINED: usize = 4096;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentRequestEvent {
    pub request_id: String,
    pub share_id: String,
    /// ISO 3166-1 alpha-2 country code of the end user (`cf-ipcountry`).
    /// `None` when the connecting peer was not Cloudflare-trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_country: Option<String>,
    /// Same value translated to alpha-3, ready to address SVG country paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_country_iso3: Option<String>,
    pub started_at: DateTime<Utc>,
}

#[derive(Default, Debug)]
struct State {
    events: VecDeque<RecentRequestEvent>,
}

#[derive(Debug, Default, Clone)]
pub struct RecentTraffic {
    inner: Arc<RwLock<State>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentTrafficSnapshot {
    pub country_counts: HashMap<String, usize>,
    pub recent_events: Vec<RecentRequestEvent>,
}

impl RecentTraffic {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request entering the proxy. Cheap: one write lock + a couple of
    /// VecDeque ops.
    pub async fn record(&self, share_id: String, user_country_iso2: Option<String>) -> String {
        let request_id = Uuid::new_v4().to_string();
        let user_country_iso3 = user_country_iso2
            .as_deref()
            .and_then(iso2_to_iso3)
            .map(str::to_string);
        let event = RecentRequestEvent {
            request_id: request_id.clone(),
            share_id,
            user_country: user_country_iso2,
            user_country_iso3,
            started_at: Utc::now(),
        };
        let mut state = self.inner.write().await;
        state.events.push_back(event);
        // Prune by hard size cap; window-based pruning happens at snapshot time.
        while state.events.len() > MAX_RETAINED {
            state.events.pop_front();
        }
        request_id
    }

    /// Build the dashboard payload. Walks the ring once to compute country counts and
    /// pick the latest events; also drops anything older than the window so the
    /// buffer cannot grow without bound under quiet periods.
    pub async fn snapshot(&self) -> RecentTrafficSnapshot {
        let cutoff = Utc::now() - Duration::seconds(COUNTRY_WINDOW_SECS);
        let mut state = self.inner.write().await;
        while let Some(front) = state.events.front() {
            if front.started_at < cutoff {
                state.events.pop_front();
            } else {
                break;
            }
        }
        let mut country_counts: HashMap<String, usize> = HashMap::new();
        for event in state.events.iter() {
            if let Some(iso3) = event.user_country_iso3.as_deref() {
                *country_counts.entry(iso3.to_string()).or_insert(0) += 1;
            }
        }
        // Last MAX_EVENTS only; ring already chronologically ordered.
        let take_from = state.events.len().saturating_sub(MAX_EVENTS);
        let recent_events: Vec<_> = state.events.iter().skip(take_from).cloned().collect();
        RecentTrafficSnapshot {
            country_counts,
            recent_events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_then_snapshot_aggregates_iso3() {
        let traffic = RecentTraffic::new();
        traffic.record("share-1".into(), Some("US".into())).await;
        traffic.record("share-1".into(), Some("us".into())).await; // case test
        traffic.record("share-2".into(), Some("DE".into())).await;
        traffic.record("share-2".into(), None).await;
        let snap = traffic.snapshot().await;
        // "us" lowercase won't hit iso2_to_iso3 (which expects uppercase).
        assert_eq!(snap.country_counts.get("USA"), Some(&1));
        assert_eq!(snap.country_counts.get("DEU"), Some(&1));
        assert_eq!(snap.recent_events.len(), 4);
    }

    #[tokio::test]
    async fn ring_caps_at_max_events() {
        let traffic = RecentTraffic::new();
        for _ in 0..100 {
            traffic.record("s".into(), Some("US".into())).await;
        }
        let snap = traffic.snapshot().await;
        assert_eq!(snap.recent_events.len(), MAX_EVENTS);
    }
}
