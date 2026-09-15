use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use ferrisetw::{
    EventRecord,
    parser::{Parser, Pointer},
    provider::*,
    schema_locator::SchemaLocator,
    trace::*,
};

fn registry_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            if record.event_id() == 7 {
                let parser = Parser::create(record, &schema);
                let pid = record.process_id();
                let key_obj: Pointer = parser.try_parse("KeyObject").unwrap_or_default();
                let status: u32 = parser.try_parse("Status").unwrap_or(0);
                let value_name: String = parser.try_parse("ValueName").unwrap_or_default();
                println!(
                    "QueryValueKey (PID: {pid}) -> KeyObj: {key_obj:#08x}, ValueName: \
                     {value_name}, Status: {status:#04X}",
                );
            }
        },
        Err(err) => println!("Error {err:?}"),
    }
}

fn tcpip_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            if record.event_id() == 11 {
                let parser = Parser::create(record, &schema);
                let size: u32 = parser.try_parse("size").unwrap_or(0);
                let daddr: IpAddr = parser
                    .try_parse("daddr")
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let dport: u16 = parser.try_parse("dport").unwrap_or(0);
                let saddr: IpAddr = parser
                    .try_parse("saddr")
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let sport: u16 = parser.try_parse("sport").unwrap_or(0);
                println!("{size} bytes received from {saddr}:{sport} to {daddr}:{dport}");
            }
        },
        Err(err) => println!("Error {err:?}"),
    }
}

fn main() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let tcpip_provider = Provider::by_guid(0x7dd42a49_5329_4832_8dfd_43d979153a88) // Microsoft-Windows-Kernel-Network
        .add_callback(tcpip_callback)
        .build();

    let process_provider = Provider::by_guid(0x70eb4f03_c1de_4f73_a051_33d13d5413bd) // Microsoft-Windows-Kernel-Registry
        .add_callback(registry_callback)
        .build();

    let user_trace = UserTrace::new()
        .enable(process_provider)
        .enable(tcpip_provider)
        .start_and_process()
        .unwrap();

    std::thread::sleep(Duration::new(10, 0));

    user_trace.stop().unwrap(); // optional. Simply dropping user_trace has the same effect
}
