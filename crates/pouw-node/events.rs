//! The event log of `contracts/node-events.md`. The owner of the log records what
//! components observe with [`emit`]; the log numbers the events and serves
//! pages of them to `GET /v1/events`. A log that has used every sequence number is a
//! fault of the node, returned as [`SeqExhausted`].

use std::collections::VecDeque;

use pouw_api::event::{Event, EventKind, EventTime, MAX_LIMIT, NodeId};
use serde::Serialize;
use thiserror::Error;

/// The cursor of a request is older than the oldest retained event (HTTP 410).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("oldest available seq is {oldest_seq}")]
pub struct CursorExpired {
    /// The oldest retained event.
    pub oldest_seq: u64,
}

/// The log has used every sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the event sequence numbers are exhausted")]
pub struct SeqExhausted;

/// Events of one page, borrowed from the log, and the cursor for the next request. It
/// serializes as an `EventsPage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventsSlice<'a> {
    /// The events in ascending `seq`.
    pub events: Vec<&'a Event>,
    /// The `seq` to pass as `after` next time.
    pub next: u64,
}

/// An event log in memory that keeps the last `retention` events. Its numbering
/// restarts with the process.
#[derive(Debug)]
pub struct EventLog {
    pub node_id: NodeId,
    pub retention: usize,
    pub events: VecDeque<Event>,
    pub last_seq: u64,
}

/// Events with `seq` above `after`, at most `limit` and at most [`MAX_LIMIT`].
pub fn page(log: &EventLog, after: u64, limit: u32) -> Result<EventsSlice<'_>, CursorExpired> {
    if let Some(oldest) = log.events.front()
        && oldest.seq.checked_sub(1).is_some_and(|prev| after < prev)
    {
        return Err(CursorExpired {
            oldest_seq: oldest.seq,
        });
    }
    let limit = usize::try_from(limit.min(MAX_LIMIT)).unwrap_or(usize::MAX);
    let events: Vec<&Event> = log
        .events
        .iter()
        .filter(|event| event.seq > after)
        .take(limit)
        .collect();
    let next = events.last().map_or(after, |event| event.seq);
    Ok(EventsSlice { events, next })
}

/// Records one event with the current time.
pub fn emit(log: &mut EventLog, kind: EventKind) -> Result<(), SeqExhausted> {
    log.last_seq = log.last_seq.checked_add(1).ok_or(SeqExhausted)?;
    log.events.push_back(Event {
        seq: log.last_seq,
        time: EventTime::now(),
        node_id: log.node_id.clone(),
        kind,
    });
    while log.events.len() > log.retention {
        log.events.pop_front();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use pouw_api::event::Peer;

    use super::*;

    fn log(retention: usize) -> EventLog {
        EventLog {
            node_id: "node-a".parse().unwrap(),
            retention,
            events: VecDeque::new(),
            last_seq: 0,
        }
    }

    fn peer(n: u32) -> EventKind {
        EventKind::PeerConnected(Peer {
            peer_id: format!("peer-{n}"),
        })
    }

    #[test]
    fn seq_starts_at_one_without_gaps() {
        let mut log = log(10);
        for n in 0..3 {
            emit(&mut log, peer(n)).unwrap();
        }
        let first = page(&log, 0, 100).unwrap();
        let seqs: Vec<u64> = first.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [1, 2, 3]);
        assert_eq!(first.next, 3);
        let empty = page(&log, 3, 100).unwrap();
        assert_eq!(empty.events, Vec::<&Event>::new());
        assert_eq!(empty.next, 3);
        assert_eq!(page(&log, 1, 1).unwrap().next, 2);
        let json = serde_json::to_value(&first).unwrap();
        let back: pouw_api::event::EventsPage = serde_json::from_value(json).unwrap();
        assert_eq!(back.events.len(), 3);
        assert_eq!(back.next, 3);
    }

    #[test]
    fn an_expired_cursor_reports_the_oldest_seq() {
        let mut log = log(2);
        for n in 0..5 {
            emit(&mut log, peer(n)).unwrap();
        }
        assert_eq!(page(&log, 0, 10), Err(CursorExpired { oldest_seq: 4 }));
        assert_eq!(page(&log, 3, 10).unwrap().events.len(), 2);
    }

    #[test]
    fn the_last_seq_is_used_once_and_then_emit_fails() {
        let mut log = log(10);
        log.last_seq = u64::MAX - 1;
        assert_eq!(emit(&mut log, peer(0)), Ok(()));
        assert_eq!(emit(&mut log, peer(1)), Err(SeqExhausted));
        let seqs: Vec<u64> = log.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [u64::MAX]);
        assert_eq!(page(&log, u64::MAX, 10).unwrap().events.len(), 0);
    }
}
