use std::collections::HashMap;
use windows::{
    core::{GUID, PWSTR},
    Wdk::System::SystemServices::{RtlGUIDFromString, RtlStringFromGUID},
    Win32::{
        Foundation::{NTSTATUS, STATUS_SUCCESS, UNICODE_STRING},
        System::{
            Diagnostics::Etw::{
                TdhEnumerateManifestProviderEvents, TdhGetManifestEventInformation, TdhEnumerateProviders,
                TRACE_PROVIDER_INFO, PROVIDER_ENUMERATION_INFO, EVENT_DESCRIPTOR, EVENT_PROPERTY_INFO,
                PROVIDER_EVENT_INFO, TRACE_EVENT_INFO,
            },
            WindowsProgramming::RtlFreeUnicodeString,
        },
    },
};
use bitflags::bitflags;

#[derive(Debug, Clone)]
pub struct Event {
    pub name: String,
    pub properties: Vec<EventProperty>,
}

#[derive(Debug, Clone)]
pub struct EventProperty {
    pub name: String,
    pub value_type: String,
}

pub struct EventProvider {
    pub name: String,
    pub guid: String,
    pub events: HashMap<u16, Event>,
}

pub type EventProviders = HashMap<u128, EventProvider>;

#[derive(Clone)]
pub struct MyGUID(GUID);

impl MyGUID {
    pub const fn to_u128(&self) -> u128 {
        ((self.0.data1 as u128) << 96)
            + ((self.0.data2 as u128) << 80)
            + ((self.0.data3 as u128) << 64)
            + u64::from_be_bytes(self.0.data4) as u128
    }
}

impl From<&str> for MyGUID {
    fn from(guid_str: &str) -> Self {
        let mut guid = GUID::default();
        let wide: Vec<u16> = format!("{{{}}}", guid_str).encode_utf16().collect();

        let unicode_string = windows::Win32::Foundation::UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: PWSTR(wide.as_ptr() as *mut u16),
        };
        unsafe {
            let _ = RtlGUIDFromString(&unicode_string, &mut guid);
        }

        MyGUID(guid)
    }
}

impl From<GUID> for MyGUID {
    fn from(guid: GUID) -> Self {
        MyGUID(guid)
    }
}

impl Into<GUID> for MyGUID {
    fn into(self) -> GUID {
        self.0
    }
}

impl From<String> for MyGUID {
    fn from(guid_str: String) -> Self {
        MyGUID::from(guid_str.as_str())
    }
}

impl From<MyGUID> for String {
    fn from(guid: MyGUID) -> Self {
        let mut buffer: UNICODE_STRING = UNICODE_STRING::default();
        let result: NTSTATUS;

        unsafe {
            result = RtlStringFromGUID(&guid.0, &mut buffer as *mut _);
        }

        if result != STATUS_SUCCESS {
            return String::new();
        }

        let guid_slice = unsafe { std::slice::from_raw_parts(buffer.Buffer.0, buffer.Length as usize / 2) };
        let guid = String::from_utf16_lossy(guid_slice);

        unsafe {
            RtlFreeUnicodeString(&mut buffer as *mut _);
        }

        return guid.replace("{", "").replace("}", "");
    }
}

#[repr(u16)]
#[allow(dead_code)]
enum TdhInputType {
    Null,
    UnicodeString,
    AnsiString,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    Boolean,
    Binary,
    GUID,
    Pointer,
    FILETIME,
    SYSTEMTIME,
    SID,
    HexInt32,
    HexInt64,
    CountedUtf16String = 22,
    CountedMbcsString = 23,
    Struct = 24,
    CountedString = 300,
    CountedAnsiString,
    ReversedCountedString,
    ReversedCountedAnsiString,
    NonNullTerminatedString,
    NonNullTerminatedAnsiString,
    UnicodeChar,
    AnsiChar,
    SizeT,
    HexDump,
    WbemSID,
}
impl TdhInputType {
    fn to_string(value: u16) -> String {
        match value {
            1 => "String".to_string(),
            2 => "String".to_string(),
            3 => "i8".to_string(),
            4 => "u8".to_string(),
            5 => "i16".to_string(),
            6 => "u16".to_string(),
            7 => "i32".to_string(),
            8 => "u32".to_string(),
            9 => "i64".to_string(),
            10 => "u64".to_string(),
            11 => "f64".to_string(),
            12 => "u64".to_string(),
            13 => "bool".to_string(),
            14 => "Vec<u8>".to_string(),
            15 => "GUID".to_string(),
            16 => "Pointer".to_string(),
            17 => "FileTime".to_string(),
            18 => "SystemTime".to_string(),
            19 => "String".to_string(),
            20 => "i32".to_string(),
            21 => "i32".to_string(),
            300 => "String".to_string(),
            301 => "String".to_string(),
            308 => "u64".to_string(),
            309 => "String".to_string(),
            310 => "String".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

bitflags! {
    struct PropertyFlags: u32 {
        const PropertyStruct = 0x1;
        const PropertyParamLength = 0x2;
        const PropertyParamCount = 0x4;
        const PropertyWBEMXmlFragment = 0x8;
        const PropertyParamFixedLength = 0x10;
        const PropertyParamFixedCount = 0x20;
        const PropertyHasTags = 0x40;
        const PropertyHasCustomSchema = 0x80;
    }
}

fn get_value(buffer: &[u8], offset: usize) -> String {
    let mut end = offset;
    
    while end < buffer.len() && buffer[end] != 0 || buffer[end + 1] != 0 {
        end += 2;
    }
    
    let u16_buffer: Vec<u16> = buffer[offset..end]
        .chunks(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16_lossy(&u16_buffer).to_string()
}

fn parse_properties(buffer: &[u8], trace_event_info: &TRACE_EVENT_INFO) -> Option<Vec<EventProperty>> {
    let mut properties: Vec<EventProperty> = Vec::new();

    for i in 0..trace_event_info.PropertyCount {
        let property = unsafe {
            *(trace_event_info.EventPropertyInfoArray.as_ptr() as *const EVENT_PROPERTY_INFO).add(i as usize)
        };
        let name = get_value(&buffer, property.NameOffset as usize);
        let flags = PropertyFlags::from_bits(property.Flags.0 as u32).unwrap_or(PropertyFlags::empty());
        let struct_type = flags.contains(PropertyFlags::PropertyStruct);
        let custom_schema = flags.contains(PropertyFlags::PropertyHasCustomSchema);
        let mut in_type: u16 = 0;

        if custom_schema {
            in_type = unsafe { property.Anonymous1.customSchemaType.InType };
        }

        if !struct_type {
            in_type = unsafe { property.Anonymous1.nonStructType.InType };
        }

        properties.push(EventProperty {
            name,
            value_type: TdhInputType::to_string(in_type),
        });
    }

    Some(properties)
    
}

fn parse_event(provider_guid: &GUID, event_descriptor: &EVENT_DESCRIPTOR) -> Option<(u16, Event)> {
    let mut buffer_size: u32 = 1;
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

    unsafe {
        let _ = TdhGetManifestEventInformation(provider_guid, event_descriptor, Some(buffer.as_ptr() as *mut TRACE_EVENT_INFO), &mut buffer_size);
    }

    buffer.resize(buffer_size as usize, 0);

    unsafe {
        let result = TdhGetManifestEventInformation(provider_guid, event_descriptor, Some(buffer.as_ptr() as *mut TRACE_EVENT_INFO), &mut buffer_size);
        if result != 0 {
            return None;
        }
    }

    let trace_event_info = buffer.as_ptr() as *const TRACE_EVENT_INFO;
    let trace_event_info = unsafe { &*trace_event_info };
    let mut name = get_value(&buffer, trace_event_info.TaskNameOffset as usize);
    if name.is_empty() {
        name = format!("task_{}", trace_event_info.EventDescriptor.Id);
    }
    let properties = parse_properties(&buffer, trace_event_info);

    Some((trace_event_info.EventDescriptor.Id, Event {
        name,
        properties: properties?,
    }))

}

pub fn get_events(guid: &MyGUID) -> Option<HashMap<u16, Event>> {
    let mut buffer_size: u32 = 1;
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

    unsafe {
        let _ = TdhEnumerateManifestProviderEvents(&guid.0, Some(buffer.as_ptr() as *mut PROVIDER_EVENT_INFO), &mut buffer_size);
    }

    buffer.resize(buffer_size as usize, 0);

    unsafe {
        let result = TdhEnumerateManifestProviderEvents(&guid.0, Some(buffer.as_ptr() as *mut PROVIDER_EVENT_INFO), &mut buffer_size);
        if result != 0 {
            return None;
        }
    }

    let provider_event_info = buffer.as_ptr() as *const PROVIDER_EVENT_INFO;
    let provider_event_info = unsafe { &*provider_event_info };
    let mut events = Vec::new();
    
    for i in 0..provider_event_info.NumberOfEvents {
        let event_descriptor = unsafe {
            *(provider_event_info.EventDescriptorsArray.as_ptr() as *const EVENT_DESCRIPTOR).add(i as usize)
        };
        if let Some(event) = parse_event(&guid.0, &event_descriptor) {
            events.push(event);
        }
    }

    let mut unique_events = HashMap::new();

    for (id, event) in events {
        let event_clone = event.clone();
        unique_events
            .entry(id)
            .and_modify(|e: &mut Event| {
                if event_clone.properties.len() > e.properties.len() {
                    *e = event_clone.clone();
                }
            })
            .or_insert(event);
    }

    Some(unique_events)
}

pub fn get_providers() -> Option<Vec<(String, MyGUID)>> {
    let mut buffer_size: u32 = 1;
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

    unsafe {
        let _ = TdhEnumerateProviders(Some(buffer.as_ptr() as *mut PROVIDER_ENUMERATION_INFO), &mut buffer_size);
    }

    buffer.resize(buffer_size as usize, 0);

    unsafe {
        let result = TdhEnumerateProviders(Some(buffer.as_ptr() as *mut PROVIDER_ENUMERATION_INFO), &mut buffer_size);
        if result != 0 {
            return None;
        }
    }

    let provider_enumeration_info = buffer.as_ptr() as *const PROVIDER_ENUMERATION_INFO;
    let provider_enumeration_info = unsafe { &*provider_enumeration_info };
    let mut providers = Vec::new();

    for i in 0..provider_enumeration_info.NumberOfProviders {
        let provider = unsafe {
            *(provider_enumeration_info.TraceProviderInfoArray.as_ptr() as *const TRACE_PROVIDER_INFO).add(i as usize)
        };
        let name = get_value(&buffer, provider.ProviderNameOffset as usize);
        let guid = MyGUID(provider.ProviderGuid);
        providers.push((name, guid));
    }

    Some(providers)
}

pub fn enumerate_etw() -> EventProviders {
    let mut event_providers = EventProviders::new();

    if let Some(providers) = get_providers() {
        for (name, guid) in providers {
            let provider: EventProvider = EventProvider {
                guid: guid.clone().into(),
                name,
                events: get_events(&guid).unwrap_or_default(),
            };
            event_providers.insert(guid.to_u128(), provider);
        }
    }

    event_providers
}