//! Progress tracking for large file conversions.

use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A simple progress tracker for streaming conversions.
#[derive(Clone)]
pub struct ProgressTracker {
    elements_processed: Arc<AtomicUsize>,
    relationships_processed: Arc<AtomicUsize>,
    start_time: Instant,
    last_report_count: Arc<AtomicUsize>,
    report_interval: usize,
}

impl ProgressTracker {
    /// Create a new progress tracker with a specified reporting interval.
    ///
    /// The tracker will log progress every `report_interval` elements.
    pub fn new(report_interval: usize) -> Self {
        Self {
            elements_processed: Arc::new(AtomicUsize::new(0)),
            relationships_processed: Arc::new(AtomicUsize::new(0)),
            start_time: Instant::now(),
            last_report_count: Arc::new(AtomicUsize::new(0)),
            report_interval,
        }
    }

    /// Increment the element counter and log progress if interval reached.
    pub fn increment_element(&self) {
        let count = self.elements_processed.fetch_add(1, Ordering::Relaxed) + 1;
        let last = self.last_report_count.load(Ordering::Relaxed);

        if count - last >= self.report_interval {
            self.last_report_count.store(count, Ordering::Relaxed);
            let elapsed = self.start_time.elapsed();
            let rate = count as f64 / elapsed.as_secs_f64();
            info!(
                "Progress: {} elements processed ({:.0} elem/sec, elapsed: {:.1}s)",
                count,
                rate,
                elapsed.as_secs_f64()
            );
        }
    }

    /// Increment the relationship counter (silent).
    pub fn increment_relationship(&self) {
        self.relationships_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Log final statistics.
    pub fn finish(&self) {
        let elements = self.elements_processed.load(Ordering::Relaxed);
        let relationships = self.relationships_processed.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();
        let rate = elements as f64 / elapsed.as_secs_f64();
        
        info!(
            "Conversion complete: {} elements, {} relationships processed in {:.2}s ({:.0} elem/sec)",
            elements, relationships, elapsed.as_secs_f64(), rate
        );
    }

    /// Get the current element count.
    pub fn element_count(&self) -> usize {
        self.elements_processed.load(Ordering::Relaxed)
    }

    /// Get the current relationship count.
    pub fn relationship_count(&self) -> usize {
        self.relationships_processed.load(Ordering::Relaxed)
    }
}
