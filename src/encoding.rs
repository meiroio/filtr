//! Bounded inspection decoding. The proxy forwards the original wire representation.
use axum::http::{HeaderMap, StatusCode, header};
use brotli_decompressor::{
    Allocator, BrotliDecompressStream, BrotliResult, BrotliState, SliceWrapper, SliceWrapperMut,
};
use std::{
    cell::Cell,
    io::{self, BufRead, Read},
    mem::size_of,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const CHUNK_BYTES: usize = 8 * 1024;
const MIN_BROTLI_MEMORY: usize = 1024 * 1024;
const MAX_BROTLI_MEMORY: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Identity,
    Brotli,
    Gzip,
    Deflate,
}

impl Encoding {
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Self, DecodeError> {
        let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
        let Some(value) = values.next() else {
            return Ok(Self::Identity);
        };
        if values.next().is_some() {
            return Err(DecodeError::INVALID_HEADER);
        }
        let value = value.to_str().map_err(|_| DecodeError::INVALID_HEADER)?;
        let mut count = 0;
        for token in value
            .split(',')
            .map(|token| token.trim_matches([' ', '\t']))
        {
            if token.is_empty()
                || !token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            {
                return Err(DecodeError::INVALID_HEADER);
            }
            count += 1;
        }
        if count != 1 {
            return Err(DecodeError::UNSUPPORTED);
        }
        let value = value.trim_matches([' ', '\t']);
        match value {
            value if value.eq_ignore_ascii_case("identity") => Ok(Self::Identity),
            value if value.eq_ignore_ascii_case("br") => Ok(Self::Brotli),
            value if value.eq_ignore_ascii_case("gzip") => Ok(Self::Gzip),
            value if value.eq_ignore_ascii_case("deflate") => Ok(Self::Deflate),
            _ => Err(DecodeError::UNSUPPORTED),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DecodeError {
    pub(crate) status: StatusCode,
    pub(crate) reason: &'static str,
}

impl DecodeError {
    const INVALID_HEADER: Self = Self {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid-content-encoding",
    };
    const UNSUPPORTED: Self = Self {
        status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
        reason: "unsupported-content-encoding",
    };
    const INVALID_BODY: Self = Self {
        status: StatusCode::BAD_REQUEST,
        reason: "invalid-encoded-body",
    };
    const TOO_LARGE: Self = Self {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        reason: "payload-too-large",
    };
    const MEMORY_LIMIT: Self = Self {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        reason: "body-decode-memory-limit",
    };
    const ALLOCATION_FAILED: Self = Self {
        status: StatusCode::SERVICE_UNAVAILABLE,
        reason: "body-decode-allocation-failed",
    };
    const TIMEOUT: Self = Self {
        status: StatusCode::REQUEST_TIMEOUT,
        reason: "body-decode-timeout",
    };
    const CANCELLED: Self = Self {
        status: StatusCode::REQUEST_TIMEOUT,
        reason: "body-decode-cancelled",
    };
}

struct Control<'a> {
    deadline: Instant,
    cancellation: &'a AtomicBool,
}

impl Control<'_> {
    fn check(&self) -> Result<(), DecodeError> {
        if self.cancellation.load(Ordering::Relaxed) {
            return Err(DecodeError::CANCELLED);
        }
        if Instant::now() >= self.deadline {
            return Err(DecodeError::TIMEOUT);
        }
        Ok(())
    }
}

pub(crate) fn decode(
    encoding: Encoding,
    input: &[u8],
    limit: usize,
    deadline: Instant,
    cancellation: &AtomicBool,
) -> Result<Vec<u8>, DecodeError> {
    let control = Control {
        deadline,
        cancellation,
    };
    control.check()?;
    if input.len() > limit {
        return Err(DecodeError::TOO_LARGE);
    }
    let reader = CheckedInput {
        remaining: input,
        control: &control,
    };
    match encoding {
        Encoding::Identity => read_limited(reader, limit, &control),
        Encoding::Gzip => {
            let mut decoder = flate2::bufread::MultiGzDecoder::new(reader);
            let decoded = read_limited(&mut decoder, limit, &control)?;
            require_consumed(decoder.into_inner().remaining)?;
            Ok(decoded)
        }
        Encoding::Deflate => {
            // HTTP "deflate" means a zlib-wrapped DEFLATE stream (RFC 9110 §8.4.1.2).
            let mut decoder = flate2::bufread::ZlibDecoder::new(reader);
            let decoded = read_limited(&mut decoder, limit, &control)?;
            require_consumed(decoder.into_inner().remaining)?;
            Ok(decoded)
        }
        Encoding::Brotli => decode_brotli(input, limit, &control),
    }
}

fn require_consumed(remaining: &[u8]) -> Result<(), DecodeError> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(DecodeError::INVALID_BODY)
    }
}

// Checks also happen during gzip headers/empty members, which may consume input
// without returning any decoded bytes to read_limited.
struct CheckedInput<'a, 'b> {
    remaining: &'a [u8],
    control: &'b Control<'b>,
}

impl BufRead for CheckedInput<'_, '_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.control
            .check()
            .map_err(|error| io::Error::other(error.reason))?;
        Ok(&self.remaining[..self.remaining.len().min(CHUNK_BYTES)])
    }

    fn consume(&mut self, amount: usize) {
        self.remaining = &self.remaining[amount..];
    }
}

impl Read for CheckedInput<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let amount = available.len().min(output.len());
        output[..amount].copy_from_slice(&available[..amount]);
        self.consume(amount);
        Ok(amount)
    }
}

fn read_limited(
    mut reader: impl Read,
    limit: usize,
    control: &Control<'_>,
) -> Result<Vec<u8>, DecodeError> {
    let mut output = Vec::new();
    let mut chunk = [0; CHUNK_BYTES];
    loop {
        control.check()?;
        let capacity = chunk
            .len()
            .min(limit.saturating_sub(output.len()).saturating_add(1));
        let result = reader.read(&mut chunk[..capacity]);
        control.check()?;
        let count = result.map_err(|_| DecodeError::INVALID_BODY)?;
        if count == 0 {
            return Ok(output);
        }
        append(&mut output, &chunk[..count], limit)?;
    }
}

fn append(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), DecodeError> {
    if bytes.len() > limit.saturating_sub(output.len()) {
        return Err(DecodeError::TOO_LARGE);
    }
    let required = output.len() + bytes.len();
    if required > output.capacity() {
        // Geometric growth avoids repeatedly copying a large decoded body while
        // keeping the requested capacity within the configured output limit.
        let capacity = output
            .capacity()
            .saturating_mul(2)
            .max(CHUNK_BYTES)
            .max(required)
            .min(limit);
        output
            .try_reserve_exact(capacity - output.len())
            .map_err(|_| DecodeError::ALLOCATION_FAILED)?;
    }
    output.extend_from_slice(bytes);
    Ok(())
}

struct Budget {
    limit: usize,
    used: Cell<usize>,
    failure: Cell<Option<DecodeError>>,
}

impl Budget {
    fn new(limit: usize) -> Rc<Self> {
        Rc::new(Self {
            limit,
            used: Cell::new(0),
            failure: Cell::new(None),
        })
    }

    fn reserve(&self, bytes: usize) -> bool {
        if bytes > self.limit.saturating_sub(self.used.get()) {
            self.failure.set(Some(DecodeError::MEMORY_LIMIT));
            return false;
        }
        self.used.set(self.used.get() + bytes);
        true
    }

    fn check(&self) -> Result<(), DecodeError> {
        self.failure.get().map_or(Ok(()), Err)
    }
}

struct BudgetAllocator(Rc<Budget>);

struct BudgetMemory<T> {
    data: Vec<T>,
    budget: Option<Rc<Budget>>,
    bytes: usize,
}

impl<T> Default for BudgetMemory<T> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            budget: None,
            bytes: 0,
        }
    }
}

impl<T> SliceWrapper<T> for BudgetMemory<T> {
    fn slice(&self) -> &[T] {
        &self.data
    }
}

impl<T> SliceWrapperMut<T> for BudgetMemory<T> {
    fn slice_mut(&mut self) -> &mut [T] {
        &mut self.data
    }
}

impl<T> Drop for BudgetMemory<T> {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget.used.set(budget.used.get() - self.bytes);
        }
    }
}

impl<T: Default + Clone> Allocator<T> for BudgetAllocator {
    type AllocatedMemory = BudgetMemory<T>;

    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        let Some(bytes) = len.checked_mul(size_of::<T>()) else {
            self.0.failure.set(Some(DecodeError::MEMORY_LIMIT));
            return BudgetMemory::default();
        };
        if !self.0.reserve(bytes) {
            return BudgetMemory::default();
        }
        let mut memory = BudgetMemory {
            data: Vec::new(),
            budget: Some(Rc::clone(&self.0)),
            bytes,
        };
        if memory.data.try_reserve_exact(len).is_err() {
            self.0.failure.set(Some(DecodeError::ALLOCATION_FAILED));
            return BudgetMemory::default();
        }
        // Account for any extra capacity supplied by the allocator too.
        let extra = memory.data.capacity().saturating_sub(len) * size_of::<T>();
        if !self.0.reserve(extra) {
            return BudgetMemory::default();
        }
        memory.bytes += extra;
        memory.data.resize(len, T::default());
        memory
    }

    fn free_cell(&mut self, data: Self::AllocatedMemory) {
        drop(data);
    }
}

fn decode_brotli(
    input: &[u8],
    limit: usize,
    control: &Control<'_>,
) -> Result<Vec<u8>, DecodeError> {
    // Include overlapping allocations while the RFC-sized history window grows.
    // Small requests get 1 MiB of working memory; no request gets over 32 MiB.
    let working_limit = limit
        .saturating_mul(4)
        .clamp(MIN_BROTLI_MEMORY, MAX_BROTLI_MEMORY);
    decode_brotli_with_budget(input, limit, control, Budget::new(working_limit))
}

fn decode_brotli_with_budget(
    mut input: &[u8],
    limit: usize,
    control: &Control<'_>,
    budget: Rc<Budget>,
) -> Result<Vec<u8>, DecodeError> {
    let mut state = BrotliState::new_strict(
        BudgetAllocator(Rc::clone(&budget)),
        BudgetAllocator(Rc::clone(&budget)),
        BudgetAllocator(Rc::clone(&budget)),
    );
    budget.check()?;
    let mut output = Vec::new();
    let mut chunk = [0; CHUNK_BYTES];
    let mut total_out = 0;
    loop {
        control.check()?;
        let offered = &input[..input.len().min(CHUNK_BYTES)];
        let mut available_in = offered.len();
        let mut input_offset = 0;
        let mut available_out = chunk
            .len()
            .min(limit.saturating_sub(output.len()).saturating_add(1));
        let mut output_offset = 0;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            offered,
            &mut available_out,
            &mut output_offset,
            &mut chunk,
            &mut total_out,
            &mut state,
        );
        control.check()?;
        budget.check()?;
        input = &input[input_offset..];
        append(&mut output, &chunk[..output_offset], limit)?;
        match result {
            BrotliResult::ResultSuccess => {
                require_consumed(input)?;
                return Ok(output);
            }
            BrotliResult::ResultFailure => return Err(DecodeError::INVALID_BODY),
            BrotliResult::NeedsMoreInput if input.is_empty() => {
                return Err(DecodeError::INVALID_BODY);
            }
            _ if input_offset == 0 && output_offset == 0 => return Err(DecodeError::INVALID_BODY),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::{io::Write, time::Duration};

    const BROTLI_MARKER: &[u8] = &[
        139, 5, 128, 36, 123, 106, 110, 100, 105, 58, 116, 101, 115, 116, 125, 3,
    ];
    const BROTLI_1024: &[u8] = &[27, 255, 3, 248, 37, 240, 162, 177, 64, 32, 55];

    fn decoded(encoding: Encoding, input: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
        decode(
            encoding,
            input,
            limit,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        )
    }

    fn gzip(input: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(input).expect("encode fixture");
        encoder.finish().expect("finish fixture")
    }

    #[test]
    fn parses_only_unambiguous_supported_content_encodings() {
        let mut headers = HeaderMap::new();
        assert_eq!(Encoding::parse(&headers), Ok(Encoding::Identity));
        for (name, encoding) in [
            ("identity", Encoding::Identity),
            (" BR\t", Encoding::Brotli),
            ("GZip", Encoding::Gzip),
            ("deflate", Encoding::Deflate),
        ] {
            headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(name));
            assert_eq!(Encoding::parse(&headers), Ok(encoding));
        }
        for value in ["", " ", "br,", ",gzip", "br,,gzip", "br;q=1", "br gzip"] {
            headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(value));
            assert_eq!(Encoding::parse(&headers), Err(DecodeError::INVALID_HEADER));
        }
        for value in ["zstd", "gzip, br", "identity, identity"] {
            headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(value));
            assert_eq!(Encoding::parse(&headers), Err(DecodeError::UNSUPPORTED));
        }
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        headers.append(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert_eq!(Encoding::parse(&headers), Err(DecodeError::INVALID_HEADER));
    }

    #[test]
    fn brotli_requires_a_complete_single_standard_stream() {
        assert_eq!(
            decoded(Encoding::Brotli, BROTLI_MARKER, 1024),
            Ok(b"${jndi:test}".to_vec())
        );
        assert_eq!(
            decoded(Encoding::Brotli, BROTLI_1024, 1024),
            Ok(vec![b'x'; 1024])
        );
        assert_eq!(
            decoded(Encoding::Brotli, BROTLI_1024, 1023),
            Err(DecodeError::TOO_LARGE)
        );
        for len in 0..BROTLI_MARKER.len() {
            assert_eq!(
                decoded(Encoding::Brotli, &BROTLI_MARKER[..len], 1024),
                Err(DecodeError::INVALID_BODY)
            );
        }
        let mut trailing = BROTLI_MARKER.to_vec();
        trailing.extend_from_slice(BROTLI_MARKER);
        assert_eq!(
            decoded(Encoding::Brotli, &trailing, 1024),
            Err(DecodeError::INVALID_BODY)
        );
        // 0x11 introduces the nonstandard large-window extension. Reject it
        // before any peer-selected large history buffer can be allocated.
        assert_eq!(
            decoded(Encoding::Brotli, &[0x11, 30, 0, 0, 0], 1024),
            Err(DecodeError::INVALID_BODY)
        );
    }

    #[test]
    fn gzip_inspects_every_member_and_verifies_trailers() {
        let first = gzip(&vec![b'a'; 512]);
        let second = gzip(&vec![b'b'; 512]);
        let mut combined = first.clone();
        combined.extend_from_slice(&second);
        let mut expected = vec![b'a'; 512];
        expected.extend_from_slice(&vec![b'b'; 512]);
        assert_eq!(decoded(Encoding::Gzip, &combined, 1024), Ok(expected));
        assert_eq!(
            decoded(Encoding::Gzip, &combined, 1023),
            Err(DecodeError::TOO_LARGE)
        );
        for len in 0..first.len() {
            assert_eq!(
                decoded(Encoding::Gzip, &first[..len], 1024),
                Err(DecodeError::INVALID_BODY)
            );
        }
        combined.push(0);
        assert_eq!(
            decoded(Encoding::Gzip, &combined, 1024),
            Err(DecodeError::INVALID_BODY)
        );
        let mut corrupt = first;
        let checksum_offset = corrupt.len() - 8;
        corrupt[checksum_offset] ^= 1;
        assert_eq!(
            decoded(Encoding::Gzip, &corrupt, 1024),
            Err(DecodeError::INVALID_BODY)
        );
    }

    #[test]
    fn deflate_is_zlib_wrapped_and_rejects_trailing_or_missing_bytes() {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder
            .write_all(&vec![b'x'; 1024])
            .expect("encode fixture");
        let encoded = encoder.finish().expect("finish fixture");
        assert_eq!(
            decoded(Encoding::Deflate, &encoded, 1024),
            Ok(vec![b'x'; 1024])
        );
        assert_eq!(
            decoded(Encoding::Deflate, &encoded, 1023),
            Err(DecodeError::TOO_LARGE)
        );
        for len in 0..encoded.len() {
            assert_eq!(
                decoded(Encoding::Deflate, &encoded[..len], 1024),
                Err(DecodeError::INVALID_BODY)
            );
        }
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(&encoded);
        assert_eq!(
            decoded(Encoding::Deflate, &trailing, 1024),
            Err(DecodeError::INVALID_BODY)
        );
        assert_eq!(
            decoded(Encoding::Deflate, &encoded[2..encoded.len() - 4], 1024),
            Err(DecodeError::INVALID_BODY)
        );
        let mut corrupt = encoded;
        let checksum_offset = corrupt.len() - 1;
        corrupt[checksum_offset] ^= 1;
        assert_eq!(
            decoded(Encoding::Deflate, &corrupt, 1024),
            Err(DecodeError::INVALID_BODY)
        );
    }

    #[test]
    fn decoding_observes_deadline_cancellation_and_wire_limit() {
        let cancellation = AtomicBool::new(false);
        assert_eq!(
            decode(
                Encoding::Brotli,
                BROTLI_MARKER,
                1024,
                Instant::now(),
                &cancellation
            ),
            Err(DecodeError::TIMEOUT)
        );
        cancellation.store(true, Ordering::Relaxed);
        assert_eq!(
            decode(
                Encoding::Gzip,
                &gzip(b"hello"),
                1024,
                Instant::now() + Duration::from_secs(1),
                &cancellation
            ),
            Err(DecodeError::CANCELLED)
        );
        assert_eq!(
            decoded(Encoding::Identity, b"hello", 4),
            Err(DecodeError::TOO_LARGE)
        );
        assert_eq!(
            decoded(Encoding::Identity, b"hello", 5),
            Ok(b"hello".to_vec())
        );
    }

    #[test]
    fn metadata_input_reads_check_cancellation_without_output() {
        let cancellation = AtomicBool::new(false);
        let control = Control {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation: &cancellation,
        };
        let mut reader = CheckedInput {
            remaining: &[0; CHUNK_BYTES + 1],
            control: &control,
        };
        assert_eq!(reader.fill_buf().expect("first chunk").len(), CHUNK_BYTES);
        reader.consume(CHUNK_BYTES);
        cancellation.store(true, Ordering::Relaxed);
        assert!(reader.fill_buf().is_err());
    }

    #[test]
    fn brotli_allocator_shares_a_bound_and_releases_all_allocations() {
        let budget = Budget::new(64);
        let mut bytes = BudgetAllocator(Rc::clone(&budget));
        let mut words = BudgetAllocator(Rc::clone(&budget));
        let memory: BudgetMemory<u8> = bytes.alloc_cell(32);
        assert_eq!(memory.slice().len(), 32);
        let denied: BudgetMemory<u32> = words.alloc_cell(16);
        assert!(denied.slice().is_empty());
        assert_eq!(budget.check(), Err(DecodeError::MEMORY_LIMIT));
        assert_eq!(budget.used.get(), 32);
        drop(memory);
        assert_eq!(budget.used.get(), 0);
        let overflow: BudgetMemory<u32> = words.alloc_cell(usize::MAX);
        assert!(overflow.slice().is_empty());
        assert_eq!(budget.used.get(), 0);
    }

    #[test]
    fn brotli_allocation_failure_is_a_controlled_error() {
        let cancellation = AtomicBool::new(false);
        let control = Control {
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation: &cancellation,
        };
        for bytes in [0, 4096] {
            let budget = Budget::new(bytes);
            assert_eq!(
                decode_brotli_with_budget(BROTLI_1024, 1024, &control, Rc::clone(&budget)),
                Err(DecodeError::MEMORY_LIMIT)
            );
            assert_eq!(budget.used.get(), 0);
        }
    }

    #[test]
    fn every_decoder_handles_multiple_input_and_output_chunks() {
        let body: Vec<u8> = (0..CHUNK_BYTES * 3 + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        // RFC Brotli: WBITS=22, nonfinal uncompressed metablock with a 16-bit
        // length, followed by an empty last metablock. No encoder dependency.
        let prefix = 0x0b_u32 | (((body.len() - 1) as u32) << 7) | (1 << 23);
        let mut brotli = prefix.to_le_bytes()[..3].to_vec();
        brotli.extend_from_slice(&body);
        brotli.push(3);
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::none());
        zlib.write_all(&body).expect("encode stored zlib fixture");
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
        gzip.write_all(&body).expect("encode stored gzip fixture");
        for (encoding, encoded) in [
            (Encoding::Brotli, brotli),
            (Encoding::Gzip, gzip.finish().expect("finish gzip")),
            (Encoding::Deflate, zlib.finish().expect("finish zlib")),
        ] {
            assert!(encoded.len() > CHUNK_BYTES * 3);
            assert_eq!(
                decoded(encoding, &encoded, CHUNK_BYTES * 4),
                Ok(body.clone())
            );
        }
    }
}
