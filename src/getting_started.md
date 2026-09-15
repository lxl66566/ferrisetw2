use ferrisetw::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::{UserTrace, TraceTrait};

fn process_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    // Basic event scrutinizing can be done directly from the `EventRecord`
    if record.event_id() == 2 {
        // More advanced info can be retrieved from the event schema
        // (the SchemaLocator caches the schema for a given kind of event, so this call is cheap in case you've already encountered the same event kind previously)
        match schema_locator.event_schema(record) {
            Err(err) => println!("Error {:?}", err),
            Ok(schema) => {
                println!("Received an event from provider {}", schema.provider_name());

                // Finally, properties for a given event can be retrieved using a Parser
                let parser = Parser::create(record, &schema);

                // You'll need type inference to tell ferrisetw what type you want to parse into
                // In actual code, be sure to correctly handle Err values!
                let process_id: u32 = parser.try_parse("ProcessID").unwrap();
                let image_name: String = parser.try_parse("ImageName").unwrap();
                println!("PID: {} ImageName: {}", process_id, image_name);
            }
        }
    }
}

fn main() {
    // First we build a Provider
    let process_provider = Provider
        ::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
        .add_callback(process_callback)
        // .add_callback(process_callback) // it is possible to add multiple callbacks for a given provider
        // .add_filter(event_filters)      // it is possible to filter by event ID, process ID, etc.
        .build();

    // We start a real-time trace session for the previously registered provider
    // Callbacks will be run in a separate thread.
    let mut trace = UserTrace::new()
        .named(String::from("MyTrace"))
        .enable(process_provider)
        // .enable(other_provider) // It is possible to enable multiple providers on the same trace.
        // .set_etl_dump_file(...) // It is possible to dump the events that the callbacks are processing into a file
        .start_and_process()       // This call will spawn the thread for you.
                                   // See the doc for alternative ways of processing the trace,
                                   // with more or less flexibility regarding this spawned thread.
        .unwrap();

    std::thread::sleep(std::time::Duration::from_secs(3));

    // We stop the trace
    trace.stop();
}
