use windows::core::GUID;

pub fn rand_string() -> String {
    // A random (v4) GUID is as good a source of uniqueness as anything, and
    // avoids pulling in the `rand` crate just for a 10-char string
    GUID::new()
        .map(|guid| format!("{guid:?}"))
        .unwrap_or_default()
}
