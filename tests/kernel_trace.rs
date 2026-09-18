//! Use a kernel provider to test a few things regarding kernel traces
//!
//! Starting an ETW trace session requires administrator privileges,
//! so this test is gated behind the `admin_tests` feature.
#![cfg(feature = "admin_tests")]

use std::time::Duration;

use ferrisetw::{
    EventRecord,
    parser::Parser,
    provider::{EventFilter, Provider, kernel_providers},
    schema_locator::SchemaLocator,
    trace::{KernelTrace, TraceTrait},
};
use windows::{
    Win32::System::LibraryLoader::{LOAD_LIBRARY_FLAGS, LoadLibraryExW},
    core::HSTRING,
};

mod utils;
use utils::{Status, StatusNotifier, TestKind};

const TEST_LIBRARY_NAME: &str = "crypt32.dll"; // this DLL is available on all Windows versions (so that the test can run everywhere)

#[test]
fn kernel_trace_tests() {
    let passed1 = Status::new(TestKind::ExpectSuccess);
    let notifier1 = passed1.notifier();

    // Calling a sub-function, and getting the trace back. This ensures we are able to move the
    // Trace around the stack (see https://github.com/n4r1b/ferrisetw/pull/28)
    let moved_trace = create_simple_kernel_trace_trace(notifier1);

    generate_image_load_events();

    passed1.assert_passed();
    moved_trace.stop().unwrap();
    println!("Test passed");
}

fn create_simple_kernel_trace_trace(notifier: StatusNotifier) -> KernelTrace {
    println!("We are process {}", std::process::id());
    let our_process_id = std::process::id();

    let kernel_provider = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
        // NB: `ByPids` is enforced at runtime on kernel sessions: starting the trace
        // issues a per-provider `EnableTraceEx2` carrying the filter descriptor.
        // Kernel rundown (DCStart) events are nevertheless delivered session-wide,
        // some of them carrying special PIDs (e.g. 0xFFFFFFFF). So neither this
        // filter nor the callback may assert that every event's PID is ours: the
        // only PID-checked event is the DLL load the test generates itself, in
        // `has_seen_dll_load`.
        .add_filter(EventFilter::ByPids(vec![our_process_id]))
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                let schema = schema_locator.event_schema(record).unwrap();
                let parser = Parser::create(record, &schema);

                if has_seen_dll_load(record, &parser, our_process_id) {
                    notifier.notify_success();
                }
            },
        )
        .build();

    KernelTrace::new()
        .enable(kernel_provider)
        .start_and_process()
        .unwrap()
}

fn load_library(libname: &str) {
    let widename = HSTRING::from(libname);

    // Safety: LoadLibraryExW expects a valid string in lpLibFileName.
    let res = unsafe { LoadLibraryExW(&widename, None, LOAD_LIBRARY_FLAGS::default()) };

    res.unwrap();
}

fn generate_image_load_events() {
    std::thread::sleep(Duration::from_secs(1));
    println!("Will load a specific DLL...");
    load_library(TEST_LIBRARY_NAME);
    println!("Loading done.");
}

fn has_seen_dll_load(record: &EventRecord, parser: &Parser, our_process_id: u32) -> bool {
    // The only PID-checked event: the DLL load the test generates itself.
    // Other processes also load images while the session runs, and the kernel
    // rundown lists the system-wide modules, so no other event is attributable.
    if record.process_id() == our_process_id {
        let filename = parser.try_parse::<String>("FileName");
        println!("   this one's for us: {filename:?}");
        if let Ok(filename) = filename
            && filename.ends_with(TEST_LIBRARY_NAME)
        {
            return true;
        }
    }

    false
}
