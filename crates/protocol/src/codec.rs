//! Total, allocation-free frame encoder and decoder.

use crate::records::*;
use crate::{
    valid_node_id, valid_qname, valid_short, Header, MsgKind, HEADER_FIXED_BYTES, MAGIC,
    MAX_AP_ENTRIES, MAX_FRAME_BYTES, MAX_LABEL, MAX_SHORT_ID, SCHEMA_VERSION,
};

/// Why a frame was rejected. Every variant is a counted, non-panicking outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooLarge,
    Truncated,
    BadMagic,
    UnsupportedSchema(u16),
    UnknownKind(u8),
    BadNodeId,
    BadString,
    BadEnum { rtype: u8 },
    RecordTooShort { rtype: u8 },
    RecordCountMismatch,
    TrailingBytes,
    InvalidField { rtype: u8 },
}

impl DecodeError {
    /// Stable short label for metrics.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Truncated => "truncated",
            Self::BadMagic => "bad_magic",
            Self::UnsupportedSchema(_) => "unsupported_schema",
            Self::UnknownKind(_) => "unknown_kind",
            Self::BadNodeId => "bad_node_id",
            Self::BadString => "bad_string",
            Self::BadEnum { .. } => "bad_enum",
            Self::RecordTooShort { .. } => "record_too_short",
            Self::RecordCountMismatch => "record_count_mismatch",
            Self::TrailingBytes => "trailing_bytes",
            Self::InvalidField { .. } => "invalid_field",
        }
    }
}

/// Why encoding failed. The writer is left unchanged when a push fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    BufferFull,
    TooManyRecords,
    InvalidField,
}

// ---------------------------------------------------------------- reader

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.arr::<1>()?[0])
    }
    fn i8(&mut self) -> Result<i8, DecodeError> {
        Ok(i8::from_le_bytes(self.arr::<1>()?))
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    /// Length-prefixed (u8) string validated with `valid_short(max)`.
    fn short(&mut self, max: usize) -> Result<&'a str, DecodeError> {
        let n = self.u8()? as usize;
        let b = self.take(n)?;
        let s = core::str::from_utf8(b).map_err(|_| DecodeError::BadString)?;
        if !valid_short(s, max) {
            return Err(DecodeError::BadString);
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------- writer

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn put(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        let end = self
            .pos
            .checked_add(b.len())
            .ok_or(EncodeError::BufferFull)?;
        let dst = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(EncodeError::BufferFull)?;
        dst.copy_from_slice(b);
        self.pos = end;
        Ok(())
    }
    fn u8(&mut self, v: u8) -> Result<(), EncodeError> {
        self.put(&[v])
    }
    fn u16(&mut self, v: u16) -> Result<(), EncodeError> {
        self.put(&v.to_le_bytes())
    }
    fn u32(&mut self, v: u32) -> Result<(), EncodeError> {
        self.put(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) -> Result<(), EncodeError> {
        self.put(&v.to_le_bytes())
    }
    fn short(&mut self, s: &str, max: usize) -> Result<(), EncodeError> {
        if !valid_short(s, max) {
            return Err(EncodeError::InvalidField);
        }
        let n = u8::try_from(s.len()).map_err(|_| EncodeError::InvalidField)?;
        self.u8(n)?;
        self.put(s.as_bytes())
    }
}

fn opt_mac(flags: u8, bit: u8, mac: [u8; 6]) -> Option<[u8; 6]> {
    (flags & bit != 0).then_some(mac)
}

// ---------------------------------------------------------------- records

fn decode_record(rtype: u8, p: &[u8]) -> Result<Record<'_>, DecodeError> {
    let short = DecodeError::RecordTooShort { rtype };
    let bad = DecodeError::BadEnum { rtype };
    let mut r = Reader::new(p);
    let map = |e: DecodeError| match e {
        DecodeError::Truncated => short,
        other => other,
    };
    let rec = (|| -> Result<Record<'_>, DecodeError> {
        Ok(match rtype {
            rtype::WIFI_LINK => {
                let age_ms = r.u32()?;
                let status = LinkStatus::from_u8(r.u8()?);
                let rssi = r.i8()?;
                let channel = r.u8()?;
                let flags = r.u8()?;
                let bssid = r.arr::<6>()?;
                let assoc_gen = r.u16()?;
                Record::WifiLink(WifiLink {
                    age_ms,
                    status,
                    rssi_dbm: (flags & 1 != 0).then_some(rssi),
                    channel,
                    bssid: opt_mac(flags, 2, bssid),
                    assoc_gen,
                })
            }
            rtype::AP_SCAN => {
                let age_ms = r.u32()?;
                let scan_id = r.u16()?;
                let duration_ms = r.u16()?;
                let completeness = ScanCompleteness::from_u8(r.u8()?).ok_or(bad)?;
                let n = r.u8()? as usize;
                if n > MAX_AP_ENTRIES {
                    return Err(DecodeError::InvalidField { rtype });
                }
                let channel_counts = r.arr::<14>()?;
                let _reserved = r.arr::<4>()?;
                let raw = r.take(n * 8)?;
                Record::ApScan(ApScan {
                    age_ms,
                    scan_id,
                    duration_ms,
                    completeness,
                    channel_counts,
                    entries: ApEntries::Raw(raw),
                })
            }
            rtype::PROBE => {
                let age_ms = r.u32()?;
                let target_id = r.short(MAX_SHORT_ID)?;
                let kind = ProbeKind::from_u8(r.u8()?).ok_or(bad)?;
                let outcome = ProbeOutcome::from_u8(r.u8()?).ok_or(bad)?;
                let flags = r.u8()?;
                let dscp = r.u8()?;
                let rtt = r.u32()?;
                let sched_late_ms = r.u16()?;
                let error_code = r.i16()?;
                let rtt_valid = flags & 1 != 0;
                // A successful probe must carry an RTT and only a success may carry one.
                if rtt_valid != (outcome == ProbeOutcome::Success) {
                    return Err(DecodeError::InvalidField { rtype });
                }
                let dns = if flags & 4 != 0 {
                    let rcode = r.u8()?;
                    let answer = DnsAnswer::from_u8(r.u8()?).ok_or(bad)?;
                    let transport = r.u8()?;
                    let qtype = r.u16()?;
                    Some(DnsDetail {
                        rcode,
                        answer,
                        transport,
                        qtype,
                    })
                } else {
                    None
                };
                Record::Probe(Probe {
                    age_ms,
                    target_id,
                    kind,
                    outcome,
                    rtt_us: rtt_valid.then_some(rtt),
                    scan_overlap: flags & 2 != 0,
                    dscp,
                    sched_late_ms,
                    error_code,
                    dns,
                })
            }
            rtype::LIFECYCLE => {
                let age_ms = r.u32()?;
                let event = LifecycleEvent::from_u8(r.u8()?).ok_or(bad)?;
                let flags = r.u8()?;
                let reason = r.u16()?;
                let prior = r.arr::<6>()?;
                let new = r.arr::<6>()?;
                let duration = r.u32()?;
                Record::Lifecycle(Lifecycle {
                    age_ms,
                    event,
                    reason,
                    prior_bssid: opt_mac(flags, 1, prior),
                    new_bssid: opt_mac(flags, 2, new),
                    duration_ms: (flags & 4 != 0).then_some(duration),
                })
            }
            rtype::SYSTEM => {
                let age_ms = r.u32()?;
                let uptime_s = r.u32()?;
                let heap_free = r.u32()?;
                let heap_min = r.u32()?;
                let heap_max_block = r.u32()?;
                let heap_frag_pct = r.u8()?;
                let reset_reason = r.u8()?;
                let queue_fill_pct = r.u8()?;
                let _reserved = r.u8()?;
                let drops_overflow = r.u16()?;
                let drops_budget = r.u16()?;
                let drops_expired = r.u16()?;
                let missed_schedules = r.u16()?;
                let loop_lag_max_ms = r.u16()?;
                let reconnects = r.u16()?;
                let tx_bytes = r.u32()?;
                let tx_frames = r.u32()?;
                let fw_version = r.short(MAX_LABEL)?;
                if heap_frag_pct > 100 || queue_fill_pct > 100 {
                    return Err(DecodeError::InvalidField { rtype });
                }
                Record::System(System {
                    age_ms,
                    uptime_s,
                    heap_free,
                    heap_min,
                    heap_max_block,
                    heap_frag_pct,
                    reset_reason,
                    queue_fill_pct,
                    drops_overflow,
                    drops_budget,
                    drops_expired,
                    missed_schedules,
                    loop_lag_max_ms,
                    reconnects,
                    tx_bytes,
                    tx_frames,
                    fw_version,
                })
            }
            rtype::BLE => {
                let age_ms = r.u32()?;
                let window_ms = r.u16()?;
                let device_id = r.short(MAX_SHORT_ID)?;
                let count = r.u16()?;
                let rssi_min = r.i8()?;
                let rssi_max = r.i8()?;
                let rssi_sum = r.i32()?;
                let last_seen_age_ms = r.u16()?;
                let coverage_permille = r.u16()?;
                if count == 0 || rssi_min > rssi_max || coverage_permille > 1000 {
                    return Err(DecodeError::InvalidField { rtype });
                }
                Record::Ble(BleSummary {
                    age_ms,
                    window_ms,
                    device_id,
                    count,
                    rssi_min,
                    rssi_max,
                    rssi_sum,
                    last_seen_age_ms,
                    coverage_permille,
                })
            }
            rtype::SENSOR => Record::Sensor(Sensor {
                age_ms: r.u32()?,
                sensor_id: r.short(MAX_SHORT_ID)?,
                kind: r.u8()?,
                unit: r.u8()?,
                value_milli: r.i32()?,
                quality: r.u8()?,
                calibration_rev: r.u16()?,
            }),
            rtype::CAPABILITIES => Record::Capabilities(Capabilities {
                chip: r.short(MAX_LABEL)?,
                flash_kb: r.u32()?,
                ram_kb: r.u16()?,
                features: r.u32()?,
                fw_version: r.short(MAX_LABEL)?,
                profile: r.short(MAX_LABEL)?,
                max_payload: r.u16()?,
                max_probe_targets: r.u8()?,
                max_tracked_bssids: r.u8()?,
                max_ble_devices: r.u8()?,
            }),
            rtype::CONFIG_STATUS => Record::ConfigStatus(ConfigStatus {
                revision: r.u64()?,
                state: ConfigState::from_u8(r.u8()?).ok_or(bad)?,
                reason: r.u8()?,
            }),
            rtype::NODE_STATUS => Record::NodeStatus(NodeStatus {
                online: r.u8()? != 0,
                reason: r.u8()?,
                uptime_s: r.u32()?,
            }),
            rtype::CONFIG_PARAMS => {
                let c = ConfigParams {
                    revision: r.u64()?,
                    report_ms: r.u32()?,
                    wifi_link_ms: r.u32()?,
                    ap_scan_ms: r.u32()?,
                    heartbeat_ms: r.u32()?,
                    health_ms: r.u32()?,
                    egress_bytes_per_sec: r.u16()?,
                    egress_burst_bytes: r.u16()?,
                    max_payload: r.u16()?,
                    offline_buffer_bytes: r.u16()?,
                    flags: r.u16()?,
                    max_probe_inflight: {
                        let v = r.u8()?;
                        let _reserved = r.u8()?;
                        v
                    },
                    scan_max_dwell_ms: r.u16()?,
                };
                let _reserved = r.arr::<8>()?;
                Record::ConfigParams(c)
            }
            rtype::PROBE_TARGET => {
                let id = r.short(MAX_SHORT_ID)?;
                let kind = ProbeKind::from_u8(r.u8()?).ok_or(bad)?;
                let addr_source = AddrSource::from_u8(r.u8()?).ok_or(bad)?;
                let ipv4 = r.arr::<4>()?;
                let port = r.u16()?;
                let interval_ms = r.u32()?;
                let timeout_ms = r.u16()?;
                let dscp = r.u8()?;
                let expect = DnsExpect::from_u8(r.u8()?).ok_or(bad)?;
                let expect_ipv4 = r.arr::<4>()?;
                let qtype = r.u16()?;
                let n = r.u8()? as usize;
                let qb = r.take(n)?;
                let qname = core::str::from_utf8(qb).map_err(|_| DecodeError::BadString)?;
                if !(qname.is_empty() || valid_qname(qname)) {
                    return Err(DecodeError::BadString);
                }
                Record::ProbeTarget(ProbeTarget {
                    id,
                    kind,
                    addr_source,
                    ipv4,
                    port,
                    interval_ms,
                    timeout_ms,
                    dscp,
                    expect,
                    expect_ipv4,
                    qtype,
                    qname,
                })
            }
            rtype::TRACKED_BSSID => Record::TrackedBssid(r.arr::<6>()?),
            rtype::ACK => Record::Ack(Ack {
                boot_id: r.arr::<16>()?,
                sequence: r.u64()?,
            }),
            other => Record::Unknown {
                rtype: other,
                len: u16::try_from(p.len()).map_err(|_| DecodeError::TooLarge)?,
            },
        })
    })()
    .map_err(map)?;
    // Records longer than the known layout keep their prefix (additive compatibility);
    // `r.remaining()` trailing bytes are intentionally ignored.
    let _ = r.remaining();
    Ok(rec)
}

fn encode_record(w: &mut Writer<'_>, rec: &Record<'_>) -> Result<(), EncodeError> {
    match rec {
        Record::WifiLink(x) => {
            w.u32(x.age_ms)?;
            w.u8(x.status as u8)?;
            w.u8(x.rssi_dbm.unwrap_or(0) as u8)?;
            w.u8(x.channel)?;
            w.u8(u8::from(x.rssi_dbm.is_some()) | (u8::from(x.bssid.is_some()) << 1))?;
            w.put(&x.bssid.unwrap_or([0; 6]))?;
            w.u16(x.assoc_gen)
        }
        Record::ApScan(x) => {
            let n = x.entries.len();
            if n > MAX_AP_ENTRIES {
                return Err(EncodeError::InvalidField);
            }
            w.u32(x.age_ms)?;
            w.u16(x.scan_id)?;
            w.u16(x.duration_ms)?;
            w.u8(x.completeness as u8)?;
            w.u8(u8::try_from(n).map_err(|_| EncodeError::InvalidField)?)?;
            w.put(&x.channel_counts)?;
            w.put(&[0; 4])?;
            for e in x.entries.iter() {
                w.put(&e.bssid)?;
                w.u8(e.channel)?;
                w.u8(e.rssi_dbm as u8)?;
            }
            Ok(())
        }
        Record::Probe(x) => {
            if x.rtt_us.is_some() != (x.outcome == ProbeOutcome::Success) {
                return Err(EncodeError::InvalidField);
            }
            w.u32(x.age_ms)?;
            w.short(x.target_id, MAX_SHORT_ID)?;
            w.u8(x.kind as u8)?;
            w.u8(x.outcome as u8)?;
            let flags = u8::from(x.rtt_us.is_some())
                | (u8::from(x.scan_overlap) << 1)
                | (u8::from(x.dns.is_some()) << 2);
            w.u8(flags)?;
            w.u8(x.dscp)?;
            w.u32(x.rtt_us.unwrap_or(0))?;
            w.u16(x.sched_late_ms)?;
            w.put(&x.error_code.to_le_bytes())?;
            if let Some(d) = x.dns {
                w.u8(d.rcode)?;
                w.u8(d.answer as u8)?;
                w.u8(d.transport)?;
                w.u16(d.qtype)?;
            }
            Ok(())
        }
        Record::Lifecycle(x) => {
            w.u32(x.age_ms)?;
            w.u8(x.event as u8)?;
            let flags = u8::from(x.prior_bssid.is_some())
                | (u8::from(x.new_bssid.is_some()) << 1)
                | (u8::from(x.duration_ms.is_some()) << 2);
            w.u8(flags)?;
            w.u16(x.reason)?;
            w.put(&x.prior_bssid.unwrap_or([0; 6]))?;
            w.put(&x.new_bssid.unwrap_or([0; 6]))?;
            w.u32(x.duration_ms.unwrap_or(0))
        }
        Record::System(x) => {
            if x.heap_frag_pct > 100 || x.queue_fill_pct > 100 {
                return Err(EncodeError::InvalidField);
            }
            for v in [
                x.age_ms,
                x.uptime_s,
                x.heap_free,
                x.heap_min,
                x.heap_max_block,
            ] {
                w.u32(v)?;
            }
            w.put(&[x.heap_frag_pct, x.reset_reason, x.queue_fill_pct, 0])?;
            for v in [
                x.drops_overflow,
                x.drops_budget,
                x.drops_expired,
                x.missed_schedules,
                x.loop_lag_max_ms,
                x.reconnects,
            ] {
                w.u16(v)?;
            }
            w.u32(x.tx_bytes)?;
            w.u32(x.tx_frames)?;
            w.short(x.fw_version, MAX_LABEL)
        }
        Record::Ble(x) => {
            if x.count == 0 || x.rssi_min > x.rssi_max || x.coverage_permille > 1000 {
                return Err(EncodeError::InvalidField);
            }
            w.u32(x.age_ms)?;
            w.u16(x.window_ms)?;
            w.short(x.device_id, MAX_SHORT_ID)?;
            w.u16(x.count)?;
            w.u8(x.rssi_min as u8)?;
            w.u8(x.rssi_max as u8)?;
            w.put(&x.rssi_sum.to_le_bytes())?;
            w.u16(x.last_seen_age_ms)?;
            w.u16(x.coverage_permille)
        }
        Record::Sensor(x) => {
            w.u32(x.age_ms)?;
            w.short(x.sensor_id, MAX_SHORT_ID)?;
            w.u8(x.kind)?;
            w.u8(x.unit)?;
            w.put(&x.value_milli.to_le_bytes())?;
            w.u8(x.quality)?;
            w.u16(x.calibration_rev)
        }
        Record::Capabilities(x) => {
            w.short(x.chip, MAX_LABEL)?;
            w.u32(x.flash_kb)?;
            w.u16(x.ram_kb)?;
            w.u32(x.features)?;
            w.short(x.fw_version, MAX_LABEL)?;
            w.short(x.profile, MAX_LABEL)?;
            w.u16(x.max_payload)?;
            w.put(&[x.max_probe_targets, x.max_tracked_bssids, x.max_ble_devices])
        }
        Record::ConfigStatus(x) => {
            w.u64(x.revision)?;
            w.u8(x.state as u8)?;
            w.u8(x.reason)
        }
        Record::NodeStatus(x) => {
            w.u8(u8::from(x.online))?;
            w.u8(x.reason)?;
            w.u32(x.uptime_s)
        }
        Record::ConfigParams(x) => {
            w.u64(x.revision)?;
            for v in [
                x.report_ms,
                x.wifi_link_ms,
                x.ap_scan_ms,
                x.heartbeat_ms,
                x.health_ms,
            ] {
                w.u32(v)?;
            }
            for v in [
                x.egress_bytes_per_sec,
                x.egress_burst_bytes,
                x.max_payload,
                x.offline_buffer_bytes,
                x.flags,
            ] {
                w.u16(v)?;
            }
            w.u8(x.max_probe_inflight)?;
            w.u8(0)?;
            w.u16(x.scan_max_dwell_ms)?;
            w.put(&[0; 8])
        }
        Record::ProbeTarget(x) => {
            if !(x.qname.is_empty() || valid_qname(x.qname)) {
                return Err(EncodeError::InvalidField);
            }
            w.short(x.id, MAX_SHORT_ID)?;
            w.u8(x.kind as u8)?;
            w.u8(x.addr_source as u8)?;
            w.put(&x.ipv4)?;
            w.u16(x.port)?;
            w.u32(x.interval_ms)?;
            w.u16(x.timeout_ms)?;
            w.u8(x.dscp)?;
            w.u8(x.expect as u8)?;
            w.put(&x.expect_ipv4)?;
            w.u16(x.qtype)?;
            w.u8(u8::try_from(x.qname.len()).map_err(|_| EncodeError::InvalidField)?)?;
            w.put(x.qname.as_bytes())
        }
        Record::TrackedBssid(b) => w.put(b),
        Record::Ack(a) => {
            w.put(&a.boot_id)?;
            w.u64(a.sequence)
        }
        Record::Unknown { .. } => Err(EncodeError::InvalidField),
    }
}

// ---------------------------------------------------------------- frames

/// A fully validated frame borrowing the input buffer.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub header: Header<'a>,
    pub record_count: u8,
    records: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Iterate records. The frame was validated during decode, so this never fails.
    pub fn records(&self) -> RecordIter<'a> {
        RecordIter {
            r: Reader::new(self.records),
            left: self.record_count,
        }
    }
}

/// Iterator over a validated frame's records.
pub struct RecordIter<'a> {
    r: Reader<'a>,
    left: u8,
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Record<'a>;
    fn next(&mut self) -> Option<Record<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let rtype = self.r.u8().ok()?;
        let len = self.r.u16().ok()? as usize;
        let payload = self.r.take(len).ok()?;
        decode_record(rtype, payload).ok()
    }
}

/// Decode and fully validate a frame.
pub fn decode_frame(buf: &[u8]) -> Result<Frame<'_>, DecodeError> {
    if buf.len() > MAX_FRAME_BYTES {
        return Err(DecodeError::TooLarge);
    }
    let mut r = Reader::new(buf);
    if r.arr::<2>()? != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let schema = r.u16()?;
    if schema != SCHEMA_VERSION {
        return Err(DecodeError::UnsupportedSchema(schema));
    }
    let kind_b = r.u8()?;
    let kind = MsgKind::from_u8(kind_b).ok_or(DecodeError::UnknownKind(kind_b))?;
    let flags = r.u8()?;
    let n = r.u8()? as usize;
    let id_b = r.take(n)?;
    let node_id = core::str::from_utf8(id_b).map_err(|_| DecodeError::BadNodeId)?;
    if !valid_node_id(node_id) {
        return Err(DecodeError::BadNodeId);
    }
    let boot_id = r.arr::<16>()?;
    let sequence = r.u64()?;
    let sent_mono_ms = r.u64()?;
    let config_revision = r.u64()?;
    let record_count = r.u8()?;
    let start = r.pos;
    for _ in 0..record_count {
        let rtype = r.u8()?;
        let len = r.u16()? as usize;
        let payload = r.take(len).map_err(|_| DecodeError::RecordCountMismatch)?;
        decode_record(rtype, payload)?;
    }
    if r.remaining() != 0 {
        return Err(DecodeError::TrailingBytes);
    }
    let records = buf.get(start..).ok_or(DecodeError::Truncated)?;
    Ok(Frame {
        header: Header {
            kind,
            flags,
            node_id,
            boot_id,
            sequence,
            sent_mono_ms,
            config_revision,
        },
        record_count,
        records,
    })
}

/// Incremental frame builder over a caller-supplied buffer (no allocation).
pub struct FrameWriter<'a> {
    w: Writer<'a>,
    count_pos: usize,
    count: u8,
    limit: usize,
}

impl<'a> FrameWriter<'a> {
    /// Start a frame. `limit` caps the encoded size (<= `MAX_FRAME_BYTES`).
    pub fn new(buf: &'a mut [u8], header: &Header<'_>, limit: usize) -> Result<Self, EncodeError> {
        if !valid_node_id(header.node_id) {
            return Err(EncodeError::InvalidField);
        }
        let limit = limit.min(MAX_FRAME_BYTES).min(buf.len());
        if limit < HEADER_FIXED_BYTES + header.node_id.len() {
            return Err(EncodeError::BufferFull);
        }
        let mut w = Writer { buf, pos: 0 };
        w.put(&MAGIC)?;
        w.u16(SCHEMA_VERSION)?;
        w.u8(header.kind as u8)?;
        w.u8(header.flags)?;
        w.u8(u8::try_from(header.node_id.len()).map_err(|_| EncodeError::InvalidField)?)?;
        w.put(header.node_id.as_bytes())?;
        w.put(&header.boot_id)?;
        w.u64(header.sequence)?;
        w.u64(header.sent_mono_ms)?;
        w.u64(header.config_revision)?;
        let count_pos = w.pos;
        w.u8(0)?;
        Ok(Self {
            w,
            count_pos,
            count: 0,
            limit,
        })
    }

    /// Bytes written so far.
    pub fn len(&self) -> usize {
        self.w.pos
    }

    /// True when no records have been added.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Append a record. On error the frame is unchanged, so callers can flush and retry.
    pub fn push(&mut self, rec: &Record<'_>) -> Result<(), EncodeError> {
        if self.count == u8::MAX {
            return Err(EncodeError::TooManyRecords);
        }
        let start = self.w.pos;
        let res = (|| {
            self.w.u8(rec.rtype())?;
            let len_pos = self.w.pos;
            self.w.u16(0)?;
            encode_record(&mut self.w, rec)?;
            let len = self.w.pos - len_pos - 2;
            if self.w.pos > self.limit {
                return Err(EncodeError::BufferFull);
            }
            let len16 = u16::try_from(len).map_err(|_| EncodeError::BufferFull)?;
            let dst = self
                .w
                .buf
                .get_mut(len_pos..len_pos + 2)
                .ok_or(EncodeError::BufferFull)?;
            dst.copy_from_slice(&len16.to_le_bytes());
            Ok(())
        })();
        match res {
            Ok(()) => {
                self.count += 1;
                Ok(())
            }
            Err(e) => {
                self.w.pos = start;
                Err(e)
            }
        }
    }

    /// Finish the frame and return its length.
    pub fn finish(self) -> usize {
        if let Some(b) = self.w.buf.get_mut(self.count_pos) {
            *b = self.count;
        }
        self.w.pos
    }
}
