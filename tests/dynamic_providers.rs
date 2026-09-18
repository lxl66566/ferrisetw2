//! Dynamic provider enable/disable and session statistics on a running trace
//!
//! Starting an ETW trace session requires administrator privileges,
//! so this whole test is gated behind the `admin_tests` feature.
//!
//! Events are generated in-process through TraceLogging providers, so that event
//! production is fully under the test's control (no dependency on external processes
//! or on unrelated system activity). Every test gets its own provider GUID, so the
//! tests can run in parallel without one test's events polluting another's counters.
//! Assertions on event delivery use lower bounds and "no growth over a stable window"
//! checks instead of exact counts, as delivery is asynchronous (buffers flush about
//! once a second).
#![cfg(feature = "admin_tests")]

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ferrisetw::{
    EventRecord, GUID,
    provider::Provider,
    schema_locator::SchemaLocator,
    trace::{RealTimeTraceTrait, TraceTrait, UserTrace, stop_trace_by_name},
};
use tracelogging as tlg;

const PROVIDER_LIFECYCLE_NAME: &str = "ferrisetw.DynamicProviders.Lifecycle";
const PROVIDER_INDEPENDENT_A_NAME: &str = "ferrisetw.DynamicProviders.IndependentA";
const PROVIDER_INDEPENDENT_B_NAME: &str = "ferrisetw.DynamicProviders.IndependentB";
const PROVIDER_STATS_A_NAME: &str = "ferrisetw.DynamicProviders.StatsA";
const PROVIDER_STATS_B_NAME: &str = "ferrisetw.DynamicProviders.StatsB";
const PROVIDER_SEMANTICS_NAME: &str = "ferrisetw.DynamicProviders.Semantics";
const PROVIDER_STOPPED_NAME: &str = "ferrisetw.DynamicProviders.Stopped";

tlg::define_provider!(PROVIDER_LIFECYCLE, "ferrisetw.DynamicProviders.Lifecycle");
tlg::define_provider!(
    PROVIDER_INDEPENDENT_A,
    "ferrisetw.DynamicProviders.IndependentA"
);
tlg::define_provider!(
    PROVIDER_INDEPENDENT_B,
    "ferrisetw.DynamicProviders.IndependentB"
);
tlg::define_provider!(PROVIDER_STATS_A, "ferrisetw.DynamicProviders.StatsA");
tlg::define_provider!(PROVIDER_STATS_B, "ferrisetw.DynamicProviders.StatsB");
tlg::define_provider!(PROVIDER_SEMANTICS, "ferrisetw.DynamicProviders.Semantics");
tlg::define_provider!(PROVIDER_STOPPED, "ferrisetw.DynamicProviders.Stopped");

/// Number of events in each generation burst
const EVENTS_PER_BATCH: usize = 4;
/// Generous upper bound to wait for a burst of events to be delivered
const EVENT_WAIT: Duration = Duration::from_secs(15);
/// Duration without counter growth after which delivery is considered settled
/// (a couple of flush timers, so in-flight buffers have been drained)
const STABLE_WINDOW: Duration = Duration::from_secs(2);

/// Burst `count` events of a TraceLogging provider
// Must be defined before its use sites: `macro_rules!` is textually scoped
macro_rules! write_events {
    ($provider:ident, $count:expr) => {
        for _ in 0..$count {
            tlg::write_event!($provider, "MatrixEvent", str8("Tag", "ferrisetw"));
        }
    };
}

#[test]
fn provider_can_be_enabled_disabled_and_re_enabled_at_runtime() {
    let guid = providers().lifecycle;
    let counter = Arc::new(AtomicUsize::new(0));

    // An empty trace: everything below is added and removed at runtime
    let trace = UserTrace::new().start_and_process().unwrap();
    assert!(trace.providers().is_empty());

    // enable -> events flow
    trace
        .enable_provider(counting_provider(guid, Arc::clone(&counter)))
        .unwrap();
    assert_eq!(trace.providers().len(), 1);
    write_events!(PROVIDER_LIFECYCLE, EVENTS_PER_BATCH);
    let seen = wait_for_count(&counter, EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen >= EVENTS_PER_BATCH,
        "no event after enable (saw {seen})"
    );
    let settled = wait_until_stable(&counter, EVENT_WAIT);

    // disable -> events written after disable_provider returns stop flowing
    assert_eq!(trace.disable_provider(guid).unwrap(), 1);
    assert!(trace.providers().is_empty());
    write_events!(PROVIDER_LIFECYCLE, EVENTS_PER_BATCH);
    let after = wait_until_stable(&counter, EVENT_WAIT);
    assert_eq!(after, settled, "events delivered after disable");

    // re-enable -> events flow again
    trace
        .enable_provider(counting_provider(guid, Arc::clone(&counter)))
        .unwrap();
    assert_eq!(trace.providers().len(), 1);
    write_events!(PROVIDER_LIFECYCLE, EVENTS_PER_BATCH);
    let seen = wait_for_count(&counter, settled + EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen >= settled + EVENTS_PER_BATCH,
        "no event after re-enable (saw {seen}, want at least {})",
        settled + EVENTS_PER_BATCH
    );

    trace.stop().unwrap();
}

#[test]
fn providers_are_enabled_and_disabled_independently() {
    let guids = providers();
    let counter_a = Arc::new(AtomicUsize::new(0));
    let counter_b = Arc::new(AtomicUsize::new(0));

    // Both providers enabled at build time
    let trace = UserTrace::new()
        .enable(counting_provider(
            guids.independent_a,
            Arc::clone(&counter_a),
        ))
        .enable(counting_provider(
            guids.independent_b,
            Arc::clone(&counter_b),
        ))
        .start_and_process()
        .unwrap();
    assert_eq!(trace.providers().len(), 2);

    write_events!(PROVIDER_INDEPENDENT_A, EVENTS_PER_BATCH);
    write_events!(PROVIDER_INDEPENDENT_B, EVENTS_PER_BATCH);
    // Sanity check: a provider that never delivered would make the
    // "no event after disable" assertions below pass vacuously
    let seen_a = wait_for_count(&counter_a, EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen_a >= EVENTS_PER_BATCH,
        "A never delivered while enabled (saw {seen_a})"
    );
    let seen_b = wait_for_count(&counter_b, EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen_b >= EVENTS_PER_BATCH,
        "B never delivered while enabled (saw {seen_b})"
    );
    let settled_a = wait_until_stable(&counter_a, EVENT_WAIT);
    let settled_b = wait_until_stable(&counter_b, EVENT_WAIT);

    // Disabling A must not disturb B
    assert_eq!(trace.disable_provider(guids.independent_a).unwrap(), 1);
    assert_eq!(trace.providers().len(), 1);
    write_events!(PROVIDER_INDEPENDENT_A, EVENTS_PER_BATCH);
    write_events!(PROVIDER_INDEPENDENT_B, EVENTS_PER_BATCH);
    let after_a = wait_until_stable(&counter_a, EVENT_WAIT);
    let seen_b = wait_for_count(&counter_b, settled_b + EVENTS_PER_BATCH, EVENT_WAIT);
    assert_eq!(
        after_a, settled_a,
        "A events delivered after A was disabled"
    );
    assert!(
        seen_b >= settled_b + EVENTS_PER_BATCH,
        "B stopped receiving events"
    );

    // Re-enabling A restores its delivery, B untouched
    trace
        .enable_provider(counting_provider(
            guids.independent_a,
            Arc::clone(&counter_a),
        ))
        .unwrap();
    assert_eq!(trace.providers().len(), 2);
    write_events!(PROVIDER_INDEPENDENT_A, EVENTS_PER_BATCH);
    write_events!(PROVIDER_INDEPENDENT_B, EVENTS_PER_BATCH);
    let seen_a = wait_for_count(&counter_a, settled_a + EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen_a >= settled_a + EVENTS_PER_BATCH,
        "A did not resume after re-enable"
    );

    trace.stop().unwrap();
}

#[test]
fn statistics_stay_consistent_while_providers_come_and_go() {
    let guids = providers();
    let counter_a = Arc::new(AtomicUsize::new(0));
    let counter_b = Arc::new(AtomicUsize::new(0));

    let mut trace = UserTrace::new()
        .enable(counting_provider(guids.stats_a, Arc::clone(&counter_a)))
        .start_and_process()
        .unwrap();

    write_events!(PROVIDER_STATS_A, EVENTS_PER_BATCH);
    let seen_a = wait_for_count(&counter_a, EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen_a >= EVENTS_PER_BATCH,
        "A never delivered while enabled (saw {seen_a})"
    );
    let stats_enabled_a = trace.statistics().unwrap();
    assert_eq!(trace.providers().len(), 1);

    // Interleave enable / disable / statistics: queries must not disturb the
    // registry, and mutations must not invalidate the statistics
    trace
        .enable_provider(counting_provider(guids.stats_b, Arc::clone(&counter_b)))
        .unwrap();
    write_events!(PROVIDER_STATS_B, EVENTS_PER_BATCH);
    let seen_b = wait_for_count(&counter_b, EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen_b >= EVENTS_PER_BATCH,
        "B never delivered while enabled (saw {seen_b})"
    );
    let stats_enabled_b = trace.statistics().unwrap();
    assert_eq!(trace.providers().len(), 2);

    assert_eq!(trace.disable_provider(guids.stats_a).unwrap(), 1);
    let stats_disabled_a = trace.statistics().unwrap();
    assert_eq!(trace.providers().len(), 1);

    assert_eq!(trace.disable_provider(guids.stats_b).unwrap(), 1);
    let stats_disabled_b = trace.statistics().unwrap();
    assert!(trace.providers().is_empty());

    // logger-side buffer accounting only ever grows, and the logger thread is the
    // same for the whole life of the session
    for (earlier, later) in [
        (&stats_enabled_a, &stats_enabled_b),
        (&stats_enabled_b, &stats_disabled_a),
        (&stats_disabled_a, &stats_disabled_b),
    ] {
        assert!(
            later.buffers_written >= earlier.buffers_written,
            "buffers_written went backwards: {earlier:?} then {later:?}"
        );
        assert!(
            later.free_buffers <= later.number_of_buffers,
            "more free buffers than allocated: {later:?}"
        );
        assert_eq!(
            later.logger_thread_id, earlier.logger_thread_id,
            "the logger thread changed mid-session"
        );
    }

    // Events were delivered, so the session wrote (logger-side) and the consumer
    // read (consumer-side) at least one buffer
    assert!(trace.events_handled() > 0);
    assert!(stats_disabled_b.buffers_written >= 1);
    assert!(trace.buffers_read() >= 1);

    // `events_lost`/`real_time_buffers_lost` cannot be forced without saturating the
    // session buffers: any value (including 0) is legitimate here, so only their
    // presence through successful queries is asserted.

    trace.stop().unwrap();
}

#[test]
fn disable_provider_semantics_for_unknown_and_repeated_calls() {
    let guid = providers().semantics;
    let counter = Arc::new(AtomicUsize::new(0));

    let trace = UserTrace::new()
        .enable(counting_provider(guid, Arc::clone(&counter)))
        .start_and_process()
        .unwrap();

    // A GUID nothing is registered under is a no-op: Ok(0), the session is untouched
    // (a GUID derived from a name whose provider is never registered anywhere)
    assert_eq!(
        trace
            .disable_provider(guid_from_name("ferrisetw.DynamicProviders.Nothing"))
            .unwrap(),
        0
    );
    assert_eq!(trace.providers().len(), 1);

    // The same GUID may be registered several times (each entry with its own
    // callbacks): one disable removes every entry at once
    trace
        .enable_provider(counting_provider(guid, Arc::clone(&counter)))
        .unwrap();
    assert_eq!(trace.providers().len(), 2);
    assert_eq!(trace.disable_provider(guid).unwrap(), 2);
    assert!(trace.providers().is_empty());

    // A repeated disable is equally idempotent: nothing is registered anymore
    assert_eq!(trace.disable_provider(guid).unwrap(), 0);

    trace.stop().unwrap();
}

#[test]
fn provider_controls_fail_after_the_session_stopped() {
    let guid = providers().stopped;
    let counter = Arc::new(AtomicUsize::new(0));

    let trace_name = format!("ferrisetw-dynamic-providers-{}", std::process::id());
    let mut trace = UserTrace::new()
        .named(trace_name.clone())
        .enable(counting_provider(guid, Arc::clone(&counter)))
        .start_and_process()
        .unwrap();
    write_events!(PROVIDER_STOPPED, EVENTS_PER_BATCH);
    let seen = wait_for_count(&counter, EVENTS_PER_BATCH, EVENT_WAIT);
    assert!(
        seen >= EVENTS_PER_BATCH,
        "sanity check failed: session never delivered"
    );

    // stop() would consume the trace, which would make the calls below
    // unrepresentable: stop the session behind the trace's back instead
    stop_trace_by_name(&trace_name).unwrap();

    // With the session gone, the control calls report an error rather than silently
    // succeeding. The exact Win32 code depends on the call and Windows version
    // (ERROR_INVALID_HANDLE, ERROR_WMI_INSTANCE_NOT_FOUND): only Err is asserted.
    assert!(
        trace
            .enable_provider(counting_provider(guid, Arc::clone(&counter)))
            .is_err()
    );
    // The failed enable was rolled back: only the build-time entry remains
    assert_eq!(trace.providers().len(), 1);
    assert!(trace.disable_provider(guid).is_err());
    assert!(trace.statistics().is_err());

    // Dropping the trace stops (in vain) and closes the consumer; errors are ignored
    drop(trace);
}

/// A provider whose callbacks count every delivered event into `counter`
fn counting_provider(guid: GUID, counter: Arc<AtomicUsize>) -> Provider {
    Provider::by_guid(guid)
        .add_callback(move |_record: &EventRecord, _locator: &SchemaLocator| {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .build()
}

/// The GUIDs of the TraceLogging providers, registering them exactly once
///
/// Registration is never undone: the tests of this binary run in parallel, and the
/// process exit unregisters the providers anyway.
fn providers() -> &'static ProviderGuids {
    static REGISTRATION: OnceLock<ProviderGuids> = OnceLock::new();
    REGISTRATION.get_or_init(|| {
        // Safety: nothing to uphold, `register` merely tracks the provider for the
        // process lifetime (same call as the `tlg` test)
        unsafe {
            PROVIDER_LIFECYCLE.register();
            PROVIDER_INDEPENDENT_A.register();
            PROVIDER_INDEPENDENT_B.register();
            PROVIDER_STATS_A.register();
            PROVIDER_STATS_B.register();
            PROVIDER_SEMANTICS.register();
            PROVIDER_STOPPED.register();
        }
        ProviderGuids {
            lifecycle: guid_from_name(PROVIDER_LIFECYCLE_NAME),
            independent_a: guid_from_name(PROVIDER_INDEPENDENT_A_NAME),
            independent_b: guid_from_name(PROVIDER_INDEPENDENT_B_NAME),
            stats_a: guid_from_name(PROVIDER_STATS_A_NAME),
            stats_b: guid_from_name(PROVIDER_STATS_B_NAME),
            semantics: guid_from_name(PROVIDER_SEMANTICS_NAME),
            stopped: guid_from_name(PROVIDER_STOPPED_NAME),
        }
    })
}

#[derive(Debug, Clone, Copy)]
struct ProviderGuids {
    lifecycle: GUID,
    independent_a: GUID,
    independent_b: GUID,
    stats_a: GUID,
    stats_b: GUID,
    semantics: GUID,
    stopped: GUID,
}

fn guid_from_name(name: &str) -> GUID {
    let bytes = tlg::Guid::from_name(name).to_utf8_bytes();
    let text = std::str::from_utf8(&bytes).unwrap();
    text.try_into().unwrap()
}

/// Wait until the counter reaches `min`, and return the value seen at that time
///
/// Returns the current value on timeout: the caller asserts on the lower bound.
fn wait_for_count(counter: &AtomicUsize, min: usize, timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    loop {
        let value = counter.load(Ordering::SeqCst);
        if value >= min || Instant::now() >= deadline {
            return value;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Wait until the counter has not grown for [`STABLE_WINDOW`], and return its value
///
/// Absorbs the asynchronous delivery of events that were written before the call
/// (ETW delivers whole buffers, about once per flush timer). Returns the latest
/// value if delivery never settles within `timeout`.
fn wait_until_stable(counter: &AtomicUsize, timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    let mut last = counter.load(Ordering::SeqCst);
    let mut last_change = Instant::now();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
        let value = counter.load(Ordering::SeqCst);
        if value != last {
            last = value;
            last_change = Instant::now();
        } else if last_change.elapsed() >= STABLE_WINDOW {
            return value;
        }
    }
    last
}
