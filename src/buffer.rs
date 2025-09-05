use crate::bytes_to_u64;

#[derive(Clone, Debug)]
pub(crate) struct Buffer {
    data: u64,
    len: usize,
}

impl Buffer {
    const CAPACITY: usize = 8;

    #[inline]
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { data: 0, len: 0 }
    }

    #[inline]
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    #[must_use]
    pub(crate) const fn available(&self) -> usize {
        Self::CAPACITY - self.len
    }

    #[inline]
    #[must_use]
    pub(crate) const fn take(&mut self) -> u64 {
        let data = self.data;
        self.len = 0;
        self.data = 0;
        data
    }

    #[inline]
    #[must_use]
    pub(crate) const fn write(&mut self, x: u64, size: usize) -> Option<u64> {
        debug_assert!(size <= Self::CAPACITY);
        debug_assert!(self.len < Self::CAPACITY);
        if size < Self::CAPACITY {
            // Ensure the input is zero-padded
            debug_assert!(x >> (size * 8) == 0);
        }

        let len = self.len + size;
        let data = self.data | (x << (self.len * 8));

        if len >= 8 {
            self.len = len - 8;
            self.data = x.unbounded_shr((size - self.len) as u32 * 8);
            Some(data)
        } else {
            self.len = len;
            self.data = data;
            None
        }
    }

    #[inline]
    #[must_use]
    pub(crate) const fn write_bytes(&mut self, bytes: &[u8]) -> Option<u64> {
        let x = bytes_to_u64(bytes);
        self.write(x, bytes.len())
    }
}

impl Default for Buffer {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::buffer::Buffer;

    #[test]
    fn write_u8() {
        let mut buf = Buffer::default();
        assert_eq!(buf.write(0x11, 1), None);
        assert_eq!(buf.write(0x22, 1), None);
        assert_eq!(buf.write(0x33, 1), None);
        assert_eq!(buf.write(0x44, 1), None);
        assert_eq!(buf.write(0x55, 1), None);
        assert_eq!(buf.write(0x66, 1), None);
        assert_eq!(buf.write(0x77, 1), None);
        assert_eq!(buf.write(0x88, 1), Some(0x8877665544332211));
        assert_eq!(buf.take(), 0);
    }

    #[test]
    fn write_u16() {
        let mut buf = Buffer::default();
        assert_eq!(buf.write(0x1111, 2), None);
        assert_eq!(buf.write(0x2222, 2), None);
        assert_eq!(buf.write(0x3333, 2), None);
        assert_eq!(buf.write(0x4444, 2), Some(0x4444333322221111));
        assert_eq!(buf.take(), 0);
    }

    #[test]
    fn write_u32() {
        let mut buf = Buffer::default();
        assert_eq!(buf.write(0x11111111, 4), None);
        assert_eq!(buf.write(0x44444444, 4), Some(0x4444444411111111));
        assert_eq!(buf.take(), 0);
    }

    #[test]
    fn write_u64() {
        let mut buf = Buffer::default();
        assert_eq!(buf.write(0x1111111111111111, 8), Some(0x1111111111111111));
        assert_eq!(buf.take(), 0);
    }

    #[test]
    fn write_mixed() {
        let mut buf = Buffer::default();
        assert_eq!(buf.write(0x11, 1), None);
        assert_eq!(buf.write(0x2222, 2), None);
        assert_eq!(buf.write(0x44444444, 4), None);
        assert_eq!(buf.write(0x5555555555555555, 8), Some(0x5544444444222211));
        assert_eq!(buf.take(), 0x55555555555555);
    }
}
