extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{fence, AtomicU64, Ordering};

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{EventRecord, EVENT_RECORD_BYTES};

pub const EVENT_RING_CAPACITY: usize = 1024;
const EVENT_WORDS: usize = EVENT_RECORD_BYTES / 8;

#[repr(C, align(64))]
struct AtomicEventSlot {
    words: [AtomicU64; EVENT_WORDS],
    ordinal: AtomicU64,
    version: AtomicU64,
}

impl AtomicEventSlot {
    const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; EVENT_WORDS],
            ordinal: AtomicU64::new(u64::MAX),
            version: AtomicU64::new(0),
        }
    }

    fn publish(&self, ordinal: u64, record: EventRecord) {
        let words = record.encode_words();
        let previous = self.version.fetch_add(1, Ordering::AcqRel);
        for (destination, source) in self.words[..].iter().zip(&words[..]) {
            destination.store(*source, Ordering::Relaxed);
        }
        self.ordinal.store(ordinal, Ordering::Relaxed);
        self.version
            .store(previous.wrapping_add(2) & !1, Ordering::Release);
    }

    fn snapshot(&self) -> Option<(u64, EventRecord)> {
        let first = self.version.load(Ordering::Acquire);
        if first & 1 != 0 {
            return None;
        }
        let mut words = [0u64; EVENT_WORDS];
        for (destination, source) in words[..].iter_mut().zip(&self.words[..]) {
            *destination = source.load(Ordering::Relaxed);
        }
        let ordinal = self.ordinal.load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        if self.version.load(Ordering::Relaxed) != first {
            return None;
        }
        Some((ordinal, EventRecord::decode_words(words)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingSnapshot {
    pub count: usize,
    pub next_sequence: u64,
    pub dropped: u64,
}

pub struct EventRing {
    slots: Box<[AtomicEventSlot]>,
    next_sequence: AtomicU64,
    published_count: AtomicU64,
    reader_ordinal: AtomicU64,
    reader_sequence: AtomicU64,
    dropped: AtomicU64,
}

impl EventRing {
    pub fn try_new() -> MonadResult<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(EVENT_RING_CAPACITY).map_err(|_| {
            MonadError::new(
                ErrorPhase::Telemetry,
                ErrorCode::AllocationFailure,
                EVENT_RING_CAPACITY as u64,
            )
        })?;
        slots.extend((0..EVENT_RING_CAPACITY).map(|_| AtomicEventSlot::new()));
        Ok(Self {
            slots: slots.into_boxed_slice(),
            next_sequence: AtomicU64::new(1),
            published_count: AtomicU64::new(0),
            reader_ordinal: AtomicU64::new(0),
            reader_sequence: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    }

    pub fn record(&self, mut record: EventRecord) {
        let ordinal = self.published_count.load(Ordering::Relaxed);
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        record.sequence = sequence;
        let reader = self.reader_ordinal.load(Ordering::Acquire);
        if ordinal.saturating_sub(reader) >= EVENT_RING_CAPACITY as u64 {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.slots[ordinal as usize % EVENT_RING_CAPACITY].publish(ordinal, record);
        self.published_count
            .store(ordinal.wrapping_add(1), Ordering::Release);
    }

    pub fn snapshot(&self, output: &mut [EventRecord]) -> RingSnapshot {
        let published = self.published_count.load(Ordering::Acquire);
        let mut cursor = self.reader_ordinal.load(Ordering::Acquire);
        let earliest = published.saturating_sub(EVENT_RING_CAPACITY as u64);
        if cursor < earliest {
            cursor = earliest;
        }
        let available = published.saturating_sub(cursor) as usize;
        let wanted = available.min(output.len());
        let mut copied = 0usize;
        let mut attempts = 0usize;
        while copied < wanted && attempts < EVENT_RING_CAPACITY {
            let slot = &self.slots[cursor as usize % EVENT_RING_CAPACITY];
            let Some((slot_ordinal, record)) = slot.snapshot() else {
                break;
            };
            attempts += 1;
            if slot_ordinal != cursor {
                if slot_ordinal.wrapping_sub(cursor) < (1u64 << 63) {
                    cursor = slot_ordinal;
                    continue;
                }
                break;
            }
            output[copied] = record;
            copied += 1;
            cursor = cursor.wrapping_add(1);
        }
        let next_sequence = if copied == 0 {
            self.reader_sequence.load(Ordering::Acquire)
        } else {
            output[copied - 1].sequence
        };
        self.reader_sequence.store(next_sequence, Ordering::Release);
        self.reader_ordinal.store(cursor, Ordering::Release);
        RingSnapshot {
            count: copied,
            next_sequence,
            dropped: self.dropped.load(Ordering::Acquire),
        }
    }

    pub fn snapshot_from(
        &self,
        after_sequence: u64,
        output: &mut [EventRecord],
    ) -> MonadResult<RingSnapshot> {
        let expected = self.reader_sequence.load(Ordering::Acquire);
        if after_sequence != 0 && after_sequence != expected {
            return Err(MonadError::new(
                ErrorPhase::Telemetry,
                ErrorCode::StaleHandle,
                after_sequence,
            ));
        }
        Ok(self.snapshot(output))
    }

    pub fn latest_sequence(&self) -> u64 {
        self.next_sequence.load(Ordering::Acquire).wrapping_sub(1)
    }

    #[cfg(test)]
    fn set_next_sequence(&self, sequence: u64) {
        self.next_sequence.store(sequence, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn ring_wrap_drop_and_snapshot() {
        let ring = EventRing::try_new().expect("ring");
        ring.set_next_sequence(u64::MAX - 1);
        for index in 0..EVENT_RING_CAPACITY + 9 {
            let mut record = EventRecord::zeroed();
            record.detail = index as u32;
            ring.record(record);
        }
        let mut records = vec![EventRecord::zeroed(); EVENT_RING_CAPACITY];
        let snapshot = ring.snapshot(&mut records);
        assert_eq!(snapshot.count, EVENT_RING_CAPACITY);
        assert_eq!(snapshot.dropped, 9);
        assert_eq!(records[0].detail, 9);
        assert_eq!(records[0].sequence, 7);
        assert_eq!(snapshot.next_sequence, 1030);

        let ring = Arc::new(EventRing::try_new().expect("ring"));
        let producer = Arc::clone(&ring);
        let worker = thread::spawn(move || {
            for index in 0..4096u32 {
                let mut record = EventRecord::zeroed();
                record.detail = index;
                producer.record(record);
            }
        });
        let mut last = 0u64;
        let mut records = [EventRecord::zeroed(); 31];
        while !worker.is_finished() {
            let snapshot = ring.snapshot(&mut records);
            for record in &records[..snapshot.count] {
                if last != 0 {
                    assert!(record.sequence.wrapping_sub(last) < (1u64 << 63));
                }
                assert_eq!(record.sequence, u64::from(record.detail) + 1);
                last = record.sequence;
            }
        }
        worker.join().expect("producer");
        loop {
            let snapshot = ring.snapshot(&mut records);
            for record in &records[..snapshot.count] {
                if last != 0 {
                    assert!(record.sequence.wrapping_sub(last) < (1u64 << 63));
                }
                assert_eq!(record.sequence, u64::from(record.detail) + 1);
                last = record.sequence;
            }
            if snapshot.count == 0 {
                break;
            }
        }
        assert_eq!(last, 4096);
    }
    #[test]
    fn attempt_identity_is_payload_not_the_ring_version_word() {
        let ring = EventRing::try_new().expect("ring");
        let event = EventRecord::zeroed().with_provenance(0x1234, 7, 99);
        ring.record(event);
        let mut output = [EventRecord::zeroed(); 1];
        let snapshot = ring.snapshot_from(0, &mut output).expect("snapshot");
        assert_eq!(snapshot.count, 1);
        assert_eq!(
            (
                output[0].run_id,
                output[0].view_epoch,
                output[0].attempt_epoch
            ),
            (0x1234, 7, 99)
        );
    }
}
