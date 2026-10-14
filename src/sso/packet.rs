//! 大端、带长度前缀的二进制编解码，对齐 Lagrange 的 `BinaryPacket`。
//!
//! 两条容易踩的语义：
//!
//! * 所有整数都是**大端**（`BinaryPacket.Write<T>` 在小端机上先 `ReverseEndianness`）。
//! * `Prefix.WithPrefix` 的前缀值 = **数据长度 + 前缀字节数**（即前缀把自身也数进去）。
//!   例如一个 11 字节字符串用 4 字节前缀写入时，前缀写的是 `15`。
//!
//! 长度屏障（`EnterLengthBarrier` / `ExitLengthBarrier`）用于「先写内容、回头补长度」
//! 的字段：进入时预留前缀位置，退出时把「从预留位置到当前位置」的字节数（含前缀本身）
//! 回填进去。

use anyhow::{anyhow, Result};

/// 前缀字节数取值：2 或 4。
pub const PREFIX_I16: usize = 2;
pub const PREFIX_I32: usize = 4;

/// 递增写入器。
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
    barrier: Option<(usize, usize)>, // (起始偏移, 前缀字节数)
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// 写裸字节（无前缀）。
    pub fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn u8v(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16v(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32v(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64v(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i16v(&mut self, v: i16) {
        self.u16v(v as u16);
    }

    pub fn i32v(&mut self, v: i32) {
        self.u32v(v as u32);
    }

    /// 写「大端前缀 + 数据」，前缀值 = `data.len() + prefix_len`（含前缀自身）。
    pub fn prefixed(&mut self, data: &[u8], prefix_len: usize) {
        let value = data.len() + prefix_len;
        match prefix_len {
            PREFIX_I16 => self.u16v(value as u16),
            PREFIX_I32 => self.u32v(value as u32),
            other => panic!("不支持的前缀长度 {other}"),
        }
        self.raw(data);
    }

    /// 同 [`Writer::prefixed`]，但按 UTF-8 写字符串。
    pub fn prefixed_str(&mut self, s: &str, prefix_len: usize) {
        self.prefixed(s.as_bytes(), prefix_len);
    }

    /// 写「大端长度前缀 + 数据」，前缀值 = `data.len()`（**不含**前缀自身）。
    /// 对应 Lagrange 的 `Prefix.* | Prefix.LengthOnly`。
    pub fn prefixed_len_only(&mut self, data: &[u8], prefix_len: usize) {
        match prefix_len {
            PREFIX_I16 => self.u16v(data.len() as u16),
            PREFIX_I32 => self.u32v(data.len() as u32),
            other => panic!("不支持的前缀长度 {other}"),
        }
        self.raw(data);
    }

    /// 同 [`Writer::prefixed_len_only`]，按 UTF-8 写字符串。
    pub fn prefixed_str_len_only(&mut self, s: &str, prefix_len: usize) {
        self.prefixed_len_only(s.as_bytes(), prefix_len);
    }

    /// 预留前缀位置，之后用 [`Writer::end_barrier`] 回填长度。
    pub fn begin_barrier(&mut self, prefix_len: usize) {
        let start = self.buf.len();
        match prefix_len {
            PREFIX_I16 => self.u16v(0),
            PREFIX_I32 => self.u32v(0),
            other => panic!("不支持的前缀长度 {other}"),
        }
        self.barrier = Some((start, prefix_len));
    }

    /// 回填长度：值 = 从预留位置到当前末尾的字节数（**包含前缀本身**）。
    pub fn end_barrier(&mut self) {
        self.end_barrier_ex(true, 0);
    }

    /// 回填长度：值 = 数据长度（**不含**前缀本身）。对应 Lagrange
    /// `ExitLengthBarrier<T>(includePrefix: false)`。
    pub fn end_barrier_len_only(&mut self) {
        self.end_barrier_ex(false, 0);
    }

    /// 回填长度：值 = 从预留位置到当前末尾的字节数 + `addition`（**含前缀**）。
    /// 对应 Lagrange `ExitLengthBarrier<T>(includePrefix: true, addition)`。
    pub fn end_barrier_plus(&mut self, addition: usize) {
        self.end_barrier_ex(true, addition);
    }

    fn end_barrier_ex(&mut self, include_prefix: bool, addition: usize) {
        let (start, prefix_len) = self.barrier.take().expect("长度屏障未开始");
        let mut written = self.buf.len() - start + addition;
        if !include_prefix {
            written -= prefix_len;
        }
        match prefix_len {
            PREFIX_I16 => {
                self.buf[start..start + 2].copy_from_slice(&(written as u16).to_be_bytes())
            }
            PREFIX_I32 => {
                self.buf[start..start + 4].copy_from_slice(&(written as u32).to_be_bytes())
            }
            other => panic!("不支持的前缀长度 {other}"),
        }
    }
}

/// 顺序读取器。
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn u8v(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16v(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32v(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32v(&mut self) -> Result<i32> {
        Ok(self.u32v()? as i32)
    }

    pub fn u64v(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// 读 `n` 个裸字节。
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow!("读取长度溢出"))?;
        if end > self.data.len() {
            return Err(anyhow!(
                "包体越界：需要 {n} 字节，剩余 {}",
                self.remaining()
            ));
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// 剩下全部字节。
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.pos..];
        self.pos = self.data.len();
        out
    }

    /// 读「前缀 + 数据」；返回去掉前缀的数据（前缀值需减去前缀字节数）。
    pub fn prefixed(&mut self, prefix_len: usize) -> Result<&'a [u8]> {
        let value = match prefix_len {
            PREFIX_I16 => self.u16v()? as usize,
            PREFIX_I32 => self.u32v()? as usize,
            other => return Err(anyhow!("不支持的前缀长度 {other}")),
        };
        if value < prefix_len {
            return Err(anyhow!("前缀长度 {value} 小于前缀字节数 {prefix_len}"));
        }
        self.bytes(value - prefix_len)
    }

    /// 读「大端长度前缀 + 数据」；前缀值即数据长度（**不含**前缀自身）。
    /// 对应 Lagrange 的 `ReadBytes(Prefix.* | Prefix.LengthOnly)`。
    pub fn prefixed_len_only(&mut self, prefix_len: usize) -> Result<&'a [u8]> {
        let value = match prefix_len {
            PREFIX_I16 => self.u16v()? as usize,
            PREFIX_I32 => self.u32v()? as usize,
            other => return Err(anyhow!("不支持的前缀长度 {other}")),
        };
        self.bytes(value)
    }

    /// 同 [`Reader::prefixed`]，按 UTF-8 解析。
    pub fn prefixed_str(&mut self, prefix_len: usize) -> Result<String> {
        Ok(String::from_utf8_lossy(self.prefixed(prefix_len)?).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_includes_its_own_size() {
        let mut w = Writer::new();
        w.prefixed(b"hello", PREFIX_I32);
        assert_eq!(&w.as_slice()[..4], &9u32.to_be_bytes());
        assert_eq!(&w.as_slice()[4..], b"hello");
    }

    #[test]
    fn integers_are_big_endian() {
        let mut w = Writer::new();
        w.u16v(0x1234);
        w.u32v(0x1234_5678);
        assert_eq!(w.as_slice(), &[0x12, 0x34, 0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn barrier_length_includes_the_prefix() {
        let mut w = Writer::new();
        w.begin_barrier(PREFIX_I32);
        w.u8v(0xAA); // 1 byte of payload
        w.end_barrier();
        assert_eq!(w.as_slice(), &[0, 0, 0, 5, 0xAA]);
    }

    #[test]
    fn prefixed_round_trips() {
        let mut w = Writer::new();
        w.prefixed_str("1707889225", PREFIX_I32);
        w.prefixed(b"", PREFIX_I32);
        w.u8v(7);

        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        assert_eq!(r.prefixed_str(PREFIX_I32).unwrap(), "1707889225");
        assert_eq!(r.prefixed(PREFIX_I32).unwrap(), b"");
        assert_eq!(r.u8v().unwrap(), 7);
        assert!(r.is_empty());
    }

    #[test]
    fn reader_rejects_out_of_bounds() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.bytes(4).is_err());
        assert!(r.u32v().is_err());
    }

    #[test]
    fn nested_barriers_compose() {
        // 外层屏障里再套一个内层屏障，长度各自独立。
        let mut inner = Writer::new();
        inner.prefixed(b"abc", PREFIX_I32);

        let mut w = Writer::new();
        w.begin_barrier(PREFIX_I32);
        w.u8v(1);
        w.raw(inner.as_slice());
        w.end_barrier();
        // 4(前缀) + 1(0x01) + 7(内层 prefixed 的 4+3) = 12
        assert_eq!(&w.as_slice()[..4], &12u32.to_be_bytes());
    }
}
