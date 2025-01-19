use std::{sync::atomic::{AtomicU32, Ordering}, time::Duration};
use provider_enum::{enumerate_etw, EventProvider, EventProviders};
use ferrisetw::{
    native::{time::{FileTime, SystemTime}, EvntraceNativeError, ExtendedDataItem}, parser::{Parser, Pointer}, provider::{Provider, TraceFlags}, schema::Schema, schema_locator::SchemaLocator, trace::{stop_trace_by_name, UserTrace}, EventRecord, GUID
};
use ferrisetw::trace::TraceError;

static N_EVENTS: AtomicU32 = AtomicU32::new(0);
lazy_static::lazy_static! {
    static ref EVENT_PROVIDERS: EventProviders = enumerate_etw();
}

fn etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    if let Ok(schema) = schema_locator.event_schema(record) {
        parse_etw_event(&schema, record);
    }
}

fn print_event(parser: &Parser, provider: &EventProvider, event_id: u16) {
    provider.events.get(&event_id).map(|event| {
        println!("Provider: {}, Event_id: {}", provider.name, event_id);
        for property in &event.properties {
            
            match property.value_type.as_str() {
                "FileTime" => {
                    match parser.try_parse::<FileTime>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value.as_unix_timestamp()),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "GUID" => {
                    match parser.try_parse::<GUID>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value.to_u128()),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "Pointer" => {
                    match parser.try_parse::<Pointer>(&property.name) {
                        Ok(value) => println!("\t{}: 0x{:x}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "bool" => {
                    match parser.try_parse::<bool>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "Vec<u8>" => {
                    match parser.try_parse::<Vec<u8>>(&property.name) {
                        Ok(value) => println!("\t{}: {:?}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "SystemTime" => {
                    match parser.try_parse::<SystemTime>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value.as_unix_timestamp()),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "String" => {
                    match parser.try_parse::<String>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "u8" => {
                    match parser.try_parse::<u8>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "i8" => {
                    match parser.try_parse::<i8>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "i16" => {
                    match parser.try_parse::<i16>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "u16" => {
                    match parser.try_parse::<u16>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "i32" => {
                    match parser.try_parse::<i32>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "u32" => {
                    match parser.try_parse::<u32>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "i64" => {
                    match parser.try_parse::<i64>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "u64" => {
                    match parser.try_parse::<u64>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "f32" => {
                    match parser.try_parse::<f32>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                "f64" => {
                    match parser.try_parse::<f64>(&property.name) {
                        Ok(value) => println!("\t{}: {}", &property.name, value),
                        Err(e) => println!("\tError parsing {} ({}): {:?}", &property.name, property.value_type, e),
                    };
                },
                value => { 
                    println!("Unsupported: {}", value);
                }
            }
        }
    });
}

fn parse_etw_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);

    let provider = EVENT_PROVIDERS.get(&record.provider_id().to_u128());
    if provider.is_none() {
        return;
    }

    print_event(&parser, provider.unwrap(), record.event_id());

    //record.extended_data().iter().for_each(|edata| {
    //    let item = edata.to_extended_data_item();
    //    match item {
    //        ExtendedDataItem::StackTrace64(trace) => {
    //            println!("\tStack Trace:");
    //            for address in trace.addresses() {
    //                println!("\t\tsymbol: {}", symbolize_address(address));
    //            }
    //        }
//
    //        _ => {}
    //    }
    //});
}

fn is_accessible(guid: &str) -> bool {
    let process_provider = Provider::by_guid(guid)
        .build();

    let trace = UserTrace::new()
        .named(String::from("test"))
        .enable(process_provider)
        .start();

    match trace { 
        Ok((trace    , _)) => {
            let _ = trace.stop();
            let _ = stop_trace_by_name("test");
            true
        }

        Err(_) => {
            let _ = stop_trace_by_name("test");
            false
        }
    }
}

fn start_trace() -> Option<UserTrace> {
    let mut trace = UserTrace::new().named("Gimmie".to_owned());
    
    for (_, provider) in EVENT_PROVIDERS.iter() {
        if !is_accessible(provider.guid.as_str()) {
            continue;
        }
        let provider = Provider::by_guid(provider.guid.as_str())
            .add_callback(etw_callback)
            .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE)
            .build();

        trace = trace.enable(provider);
    }

    match trace.start_and_process() {
        Ok(trace) => {
            return Some(trace);
        }

        Err(err) => {
            if let TraceError::EtwNativeError(err) = err {
                if let EvntraceNativeError::AlreadyExist = err {
                    stop_trace_by_name("Gimmie").unwrap();
                    return start_trace();
                }
                panic!("Unable to start the ETW trace: {:?}", err);
            }
            None
        }
    }
}




fn main() {
    let trace = start_trace();

    std::thread::sleep(Duration::new(5, 0));

    trace.unwrap().stop().unwrap();
    
    println!("Done: {:?} events", N_EVENTS);
}