//! RFC 3501 date-time / date-text conversions (src/time.rs). Reference values computed
//! independently (Python calendar.timegm) and checked against RFC 3501 section 9 grammar.

use synology_mail_server::time::{
    format_imap_datetime, imap_day, parse_imap_date, parse_imap_datetime,
};

#[test]
fn formats_date_time_with_space_padded_day_and_utc_zone() {
    assert_eq!(format_imap_datetime(0), " 1-Jan-1970 00:00:00 +0000");
    assert_eq!(
        format_imap_datetime(1_793_870_040),
        " 5-Nov-2026 09:14:00 +0000"
    );
    assert_eq!(
        format_imap_datetime(1_709_251_199),
        "29-Feb-2024 23:59:59 +0000"
    );
    assert_eq!(
        format_imap_datetime(1_798_761_599),
        "31-Dec-2026 23:59:59 +0000"
    );
    assert_eq!(
        format_imap_datetime(4_107_542_400),
        " 1-Mar-2100 00:00:00 +0000"
    );
}

#[test]
fn formats_every_month_name() {
    let mid_month_2026 = [
        1_768_478_400,
        1_771_156_800,
        1_773_576_000,
        1_776_254_400,
        1_778_846_400,
        1_781_524_800,
        1_784_116_800,
        1_786_795_200,
        1_789_473_600,
        1_792_065_600,
        1_794_744_000,
        1_797_336_000,
    ];
    let names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    for (t, m) in mid_month_2026.iter().zip(names) {
        assert_eq!(
            format_imap_datetime(*t),
            format!("15-{m}-2026 12:00:00 +0000")
        );
    }
}

#[test]
fn parses_rfc3501_example_with_negative_zone() {
    // RFC 3501 6.3.11 example: "17-Jul-1996 02:44:25 -0700" = 09:44:25 UTC.
    assert_eq!(
        parse_imap_datetime("17-Jul-1996 02:44:25 -0700"),
        Some(837_596_665)
    );
}

#[test]
fn parses_both_day_forms_and_any_month_case() {
    for s in [
        " 5-Nov-2026 09:14:00 +0000",
        "05-Nov-2026 09:14:00 +0000",
        "05-nov-2026 09:14:00 +0000",
        "05-NOV-2026 09:14:00 +0000",
    ] {
        assert_eq!(parse_imap_datetime(s), Some(1_793_870_040), "{s:?}");
    }
}

#[test]
fn parses_zone_offsets_with_minutes_and_across_year_boundary() {
    assert_eq!(
        parse_imap_datetime("04-Nov-2026 22:30:00 +0130"),
        Some(1_793_826_000)
    );
    assert_eq!(
        parse_imap_datetime("01-Jan-2026 00:30:00 +0100"),
        Some(1_767_223_800)
    ); // 2025-12-31 23:30 UTC
}

#[test]
fn date_time_round_trips() {
    let mut samples = vec![
        0i64,
        1,
        59,
        86_399,
        86_400,
        951_782_400,
        1_709_251_199,
        1_793_870_040,
        4_107_542_400,
    ];
    let mut t = 0i64;
    while t < 4_200_000_000 {
        samples.push(t);
        t += 9_999_991;
    }
    for t in samples {
        let s = format_imap_datetime(t);
        assert_eq!(
            parse_imap_datetime(&s),
            Some(t),
            "round trip of {t} via {s:?}"
        );
    }
}

#[test]
fn rejects_invalid_date_times() {
    for s in [
        "",
        "32-Nov-2026 09:14:00 +0000",
        "29-Feb-2025 09:14:00 +0000",
        "31-Apr-2026 09:14:00 +0000",
        "05-Foo-2026 09:14:00 +0000",
        "05-Nov-26 09:14:00 +0000",
        "05-Nov-2026 24:00:00 +0000",
        "05-Nov-2026 09:60:00 +0000",
        "05-Nov-2026 09:14:61 +0000",
        "05-Nov-2026 09:14:00",
        "05-Nov-2026 09:14:00 0000",
        "05-Nov-2026 09:14:00 +0060",
        "05-Nov-2026 09:14:00 +0000 trailing",
        "\"05-Nov-2026 09:14:00 +0000\"",
    ] {
        assert_eq!(parse_imap_datetime(s), None, "{s:?} must be rejected");
    }
}

#[test]
fn parses_search_date_text_to_utc_midnight() {
    assert_eq!(parse_imap_date("1-Feb-1994"), Some(760_060_800)); // RFC 3501 6.4.4 example
    assert_eq!(parse_imap_date("01-Feb-1994"), Some(760_060_800));
    assert_eq!(parse_imap_date("1-feb-1994"), Some(760_060_800));
    assert_eq!(parse_imap_date("29-Feb-2000"), Some(951_782_400));
    assert_eq!(parse_imap_date("5-Nov-2026"), Some(1_793_836_800));
}

#[test]
fn rejects_impossible_search_dates() {
    for s in [
        "",
        "29-Feb-1900",
        "29-Feb-2025",
        "31-Apr-2026",
        "0-Jan-2026",
        "32-Jan-2026",
        "1-Foo-2026",
        "1-Feb-94",
        "1-Feb-1994 ",
        "1 Feb 1994",
    ] {
        assert_eq!(parse_imap_date(s), None, "{s:?} must be rejected");
    }
}

#[test]
fn imap_day_floors_to_utc_midnight() {
    assert_eq!(imap_day(1_793_870_040), 1_793_836_800);
    assert_eq!(imap_day(1_793_836_800), 1_793_836_800);
    assert_eq!(imap_day(1_793_836_799), 1_793_836_800 - 86_400);
    assert_eq!(imap_day(0), 0);
}
