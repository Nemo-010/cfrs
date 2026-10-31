//! RFC 9297 capsules and the CONNECT-IP capsule types of RFC 9484.
//!
//! Over HTTP/2 there are no QUIC datagrams, so IP packets travel inside
//! `CAPSULE_CONNECT_IP_DATA` capsules in the request body's DATA frames. The
//! framing is a pair of QUIC variable-length integers (RFC 9000 §16) — the
//! capsule type and the value length — followed by the value.

use bytes::{BufMut, Bytes};

/// An IP packet. The only capsule type that carries traffic.
pub const CAPSULE_DATA: u64 = 0x00;
/// The tunnel assigning an address to the client.
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
/// The client asking for an address.
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
/// The tunnel advertising a route.
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

/// Write a QUIC variable-length integer.
pub fn put_varint(out: &mut impl BufMut, value: u64) {
    if value < 64 {
        out.put_u8(value as u8);
    } else if value < 16_384 {
        out.put_u8(0x40 | (value >> 8) as u8);
        out.put_u8(value as u8);
    } else if value < 1_073_741_824 {
        out.put_u8(0x80 | (value >> 24) as u8);
        out.put_u8((value >> 16) as u8);
        out.put_u8((value >> 8) as u8);
        out.put_u8(value as u8);
    } else {
        out.put_u8(0xC0 | (value >> 56) as u8);
        out.put_u8((value >> 48) as u8);
        out.put_u8((value >> 40) as u8);
        out.put_u8((value >> 32) as u8);
        out.put_u8((value >> 24) as u8);
        out.put_u8((value >> 16) as u8);
        out.put_u8((value >> 8) as u8);
        out.put_u8(value as u8);
    }
}

/// Read a QUIC variable-length integer, returning `(value, bytes_consumed)`.
pub fn get_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &byte in &input[1..len] {
        value = (value << 8) | byte as u64;
    }
    Some((value, len))
}

/// Encode one capsule into `out`.
pub fn put_capsule(out: &mut impl BufMut, capsule_type: u64, value: &[u8]) {
    put_varint(out, capsule_type);
    put_varint(out, value.len() as u64);
    out.put_slice(value);
}

/// A streaming decoder for a capsule-framed byte stream.
///
/// Chunks are pushed as they arrive; whole capsules are consumed as they
/// complete, so a capsule split across DATA frames reassembles without copying
/// the payload twice.
#[derive(Default)]
pub struct CapsuleDecoder {
    buf: Vec<u8>,
}

impl CapsuleDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Yield the next complete capsule, or `None` if more bytes are needed.
    pub fn next_capsule(&mut self) -> Option<(u64, Bytes)> {
        let (capsule_type, type_len) = get_varint(&self.buf)?;
        let (length, len_len) = get_varint(&self.buf[type_len..])?;
        let header = type_len + len_len;
        let total = header + length as usize;
        if self.buf.len() < total {
            return None;
        }
        let value = Bytes::copy_from_slice(&self.buf[header..total]);
        self.buf.drain(..total);
        Some((capsule_type, value))
    }

    /// Yield the next IP packet, skipping the control capsules.
    pub fn next_packet(&mut self) -> Option<Bytes> {
        loop {
            let (capsule_type, value) = self.next_capsule()?;
            if capsule_type == CAPSULE_DATA && !value.is_empty() {
                return Some(value);
            }
        }
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn frame(capsule_type: u64, value: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        put_capsule(&mut out, capsule_type, value);
        out.to_vec()
    }

    #[test]
    fn varint_boundaries() {
        for value in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, value);
            let (got, len) = get_varint(&buf).unwrap();
            assert_eq!(got, value);
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn capsule_roundtrip() {
        let packet = b"\x45\x00\x00\x14hello";
        let mut d = CapsuleDecoder::new();
        d.push(&frame(CAPSULE_DATA, packet));
        assert_eq!(&d.next_packet().unwrap()[..], packet);
        assert!(d.next_packet().is_none());
    }

    #[test]
    fn control_capsules_are_skipped() {
        let mut d = CapsuleDecoder::new();
        d.push(&frame(CAPSULE_ADDRESS_ASSIGN, b"\x00\x01"));
        d.push(&frame(CAPSULE_DATA, b"\x45\x00"));
        assert_eq!(&d.next_packet().unwrap()[..], b"\x45\x00");
    }

    #[test]
    fn a_capsule_split_across_chunks_reassembles() {
        let full = frame(CAPSULE_DATA, b"\x45\x00\x00\x14payload");
        let mut d = CapsuleDecoder::new();
        d.push(&full[..3]);
        assert!(d.next_packet().is_none());
        d.push(&full[3..]);
        assert_eq!(&d.next_packet().unwrap()[..], b"\x45\x00\x00\x14payload");
    }
}
