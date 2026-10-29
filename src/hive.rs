//! A reader of registry hive files (REGF): the SOFTWARE hive's account and Wi-Fi names for
//! `parse-srum`, and every key and value for `parse-registry`. Every offset, count and length is
//! checked against the file, and the cells read are counted: a damaged or crafted hive gives
//! errors, never a panic, a hang or an allocation larger than the file.

use std::cell::Cell;
use std::path::Path;

/// The base block before the hive bins.
const BASE_BLOCK: usize = 4096;
/// The most bytes a value keeps in its own cell; larger ones are split in `db` segments.
const BIG_DATA_SEGMENT: usize = 16_344;
/// A key node's fixed part, before its name.
const NK_FIXED: usize = 76;
/// A value's fixed part, before its name.
const VK_FIXED: usize = 20;
/// The smallest cell: its size and 4 bytes.
const MIN_CELL: usize = 8;

pub type Result<T> = std::result::Result<T, String>;

/// A hive file, in memory.
pub struct Hive {
    data: Vec<u8>,
    root: u32,
    /// Cells that may still be read: a few times as many as the file can hold, so that keys
    /// sharing their subkeys (one list of thousands under thousands of keys) can't make the
    /// reading endless.
    budget: Cell<usize>,
}

impl Hive {
    pub fn from_path(path: &Path) -> Result<Self> {
        Self::from_bytes(std::fs::read(path).map_err(|e| e.to_string())?)
    }

    /// A hive: the `regf` signature and a root key. The base block's checksum is not checked
    /// (a hive copied from a running system may not have a current one).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < BASE_BLOCK || &data[..4] != b"regf" {
            return Err("not a registry hive (no regf signature)".into());
        }
        let root = u32_at(&data, 36).ok_or("the base block is cut short")?;
        let budget = Cell::new((data.len() / MIN_CELL).saturating_mul(4));
        let hive = Hive { data, root, budget };
        hive.root()?;
        Ok(hive)
    }

    pub fn root(&self) -> Result<Key<'_>> {
        Key::at(self, self.root)
    }

    /// The name the base block records for the hive (the end of its path,
    /// `\??\C:\Windows\System32\config\SYSTEM` or `emRoot\System32\Config\SOFTWARE`), its last
    /// component.
    pub fn base_name(&self) -> String {
        base_name(&self.data)
    }

    /// The key at `path` (`Microsoft\Windows NT\CurrentVersion`, names in any case) under the
    /// root key.
    pub fn open(&self, path: &str) -> Result<Option<Key<'_>>> {
        let mut key = self.root()?;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            match key.subkey(part)? {
                Some(k) => key = k,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }

    /// The key at `path`, like [`Hive::open`], but found among the subkeys that can be read: a
    /// damaged sibling doesn't hide it.
    pub fn find(&self, path: &str) -> Option<Key<'_>> {
        let mut key = self.root().ok()?;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            key = key
                .subkeys_and_problems()
                .0
                .into_iter()
                .find(|k| same_name(&k.name(), part))?;
        }
        Some(key)
    }

    /// The data of the cell at `offset` (from the first hive bin), after its size.
    fn cell(&self, offset: u32) -> Result<&[u8]> {
        let left = self.budget.get();
        if left == 0 {
            return Err("the hive refers to its cells more often than it has cells".into());
        }
        self.budget.set(left - 1);
        // cells are 8-byte aligned
        let at = usize::try_from(offset)
            .ok()
            .filter(|o| o % 8 == 0)
            .and_then(|o| o.checked_add(BASE_BLOCK))
            .ok_or_else(|| format!("cell offset {offset:#x} is not a cell"))?;
        let size = self
            .data
            .get(at..at.saturating_add(4))
            .filter(|b| b.len() == 4)
            .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| format!("cell {offset:#x} is past the end of the hive"))?;
        let size = size.unsigned_abs() as usize;
        if size < MIN_CELL {
            return Err(format!("cell {offset:#x} has a size of {size} bytes"));
        }
        self.data
            .get(at + 4..at.saturating_add(size))
            .ok_or_else(|| format!("cell {offset:#x} runs past the end of the hive"))
    }
}

/// A key (an `nk` cell).
pub struct Key<'h> {
    hive: &'h Hive,
    cell: &'h [u8],
    offset: u32,
}

impl<'h> Key<'h> {
    fn at(hive: &'h Hive, offset: u32) -> Result<Self> {
        let cell = hive.cell(offset)?;
        if cell.len() < NK_FIXED || &cell[..2] != b"nk" {
            return Err(format!("cell {offset:#x} is not a key"));
        }
        Ok(Key { hive, cell, offset })
    }

    /// Where its cell is in the hive bins: the same key listed twice has the same one.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// When it was last written (a FILETIME).
    pub fn last_written(&self) -> u64 {
        u64_at(self.cell, 4).unwrap_or(0)
    }

    /// The subkeys that can be read, and what keeps the others from being read: a damaged
    /// subkey or list doesn't hide the rest.
    pub fn subkeys_and_problems(&self) -> (Vec<Key<'h>>, Vec<String>) {
        let count = u32_at(self.cell, 20).unwrap_or(0);
        let list = u32_at(self.cell, 28).unwrap_or(u32::MAX);
        let mut problems = Vec::new();
        if count == 0 || list == u32::MAX {
            return (Vec::new(), problems);
        }
        let limit = (count as usize).min(self.hive.data.len() / NK_FIXED);
        let mut offsets = Vec::new();
        if let Err(e) = self.collect_subkeys(list, true, limit, &mut offsets) {
            problems.push(e);
        }
        if offsets.len() < count as usize {
            problems.push(format!(
                "{} of its {count} subkeys are listed",
                offsets.len()
            ));
        }
        let mut keys = Vec::new();
        for offset in offsets {
            match Key::at(self.hive, offset) {
                Ok(key) => keys.push(key),
                Err(e) => problems.push(format!("a subkey: {e}")),
            }
        }
        (keys, problems)
    }

    /// The values that can be read, and what keeps the others from being read.
    pub fn values_and_problems(&self) -> (Vec<Value<'h>>, Vec<String>) {
        let count = u32_at(self.cell, 36).unwrap_or(0) as usize;
        let list = u32_at(self.cell, 40).unwrap_or(u32::MAX);
        if count == 0 || list == u32::MAX {
            return (Vec::new(), Vec::new());
        }
        let cell = match self.hive.cell(list) {
            Ok(cell) => cell,
            Err(e) => return (Vec::new(), vec![format!("its value list: {e}")]),
        };
        let mut problems = Vec::new();
        let listed = (cell.len() / 4).min(count);
        if listed < count {
            problems.push(format!("{listed} of its {count} values are listed"));
        }
        let mut values = Vec::new();
        for entry in cell[..listed * 4].as_chunks::<4>().0 {
            match Value::at(self.hive, u32::from_le_bytes(*entry)) {
                Ok(value) => values.push(value),
                Err(e) => problems.push(format!("a value: {e}")),
            }
        }
        (values, problems)
    }

    /// The key's name (ASCII when flagged so, otherwise UTF-16); what fits in the cell.
    pub fn name(&self) -> String {
        let flags = u16_at(self.cell, 2).unwrap_or(0);
        let length = usize::from(u16_at(self.cell, 72).unwrap_or(0));
        let bytes = &self.cell[NK_FIXED..(NK_FIXED + length).min(self.cell.len())];
        text(bytes, flags & 0x20 != 0)
    }

    /// The subkeys, in the order of the key's list.
    pub fn subkeys(&self) -> Result<Vec<Key<'h>>> {
        let count = u32_at(self.cell, 20).unwrap_or(0);
        let list = u32_at(self.cell, 28).unwrap_or(u32::MAX);
        if count == 0 || list == u32::MAX {
            return Ok(Vec::new());
        }
        // no more than the key says it has, nor than the file could hold
        let limit = (count as usize).min(self.hive.data.len() / NK_FIXED);
        let mut offsets = Vec::new();
        self.collect_subkeys(list, true, limit, &mut offsets)?;
        offsets
            .into_iter()
            .map(|offset| Key::at(self.hive, offset))
            .collect()
    }

    /// The key offsets of a subkey list, up to `limit`: `lf` and `lh` (offset and hash), `li`
    /// (offsets), or an `ri` list of those (which can't hold another `ri`).
    fn collect_subkeys(
        &self,
        list: u32,
        top: bool,
        limit: usize,
        out: &mut Vec<u32>,
    ) -> Result<()> {
        let cell = self.hive.cell(list)?;
        let count = usize::from(u16_at(cell, 2).ok_or("a subkey list is cut short")?);
        let (stride, nested) = match cell.get(..2) {
            Some(b"lf" | b"lh") => (8, false),
            Some(b"li") => (4, false),
            Some(b"ri") if top => (4, true),
            _ => return Err(format!("cell {list:#x} is not a subkey list")),
        };
        let entries = cell
            .get(4..4 + count * stride)
            .ok_or_else(|| format!("subkey list {list:#x} holds fewer than {count} keys"))?;
        for entry in entries.chunks_exact(stride) {
            if out.len() >= limit {
                break;
            }
            let offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            if nested {
                self.collect_subkeys(offset, false, limit, out)?;
            } else {
                out.push(offset);
            }
        }
        Ok(())
    }

    /// The subkey named `name`, ignoring case.
    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h>>> {
        Ok(self
            .subkeys()?
            .into_iter()
            .find(|k| same_name(&k.name(), name)))
    }

    pub fn values(&self) -> Result<Vec<Value<'h>>> {
        let count = u32_at(self.cell, 36).unwrap_or(0) as usize;
        let list = u32_at(self.cell, 40).unwrap_or(u32::MAX);
        if count == 0 || list == u32::MAX {
            return Ok(Vec::new());
        }
        let cell = self.hive.cell(list)?;
        let entries = cell
            .get(..count.saturating_mul(4))
            .ok_or_else(|| format!("value list {list:#x} holds fewer than {count} values"))?;
        entries
            .as_chunks::<4>()
            .0
            .iter()
            .map(|e| Value::at(self.hive, u32::from_le_bytes(*e)))
            .collect()
    }

    /// The value named `name`, ignoring case.
    pub fn value(&self, name: &str) -> Result<Option<Value<'h>>> {
        Ok(self
            .values()?
            .into_iter()
            .find(|v| same_name(&v.name(), name)))
    }
}

/// A value (a `vk` cell).
pub struct Value<'h> {
    hive: &'h Hive,
    cell: &'h [u8],
}

impl<'h> Value<'h> {
    fn at(hive: &'h Hive, offset: u32) -> Result<Self> {
        let cell = hive.cell(offset)?;
        if cell.len() < VK_FIXED || &cell[..2] != b"vk" {
            return Err(format!("cell {offset:#x} is not a value"));
        }
        Ok(Value { hive, cell })
    }

    /// The size of its data, as it records it.
    pub fn size(&self) -> usize {
        (u32_at(self.cell, 4).unwrap_or(0) & 0x7fff_ffff) as usize
    }

    /// Its type (`REG_SZ` is 1, `REG_DWORD` 4).
    pub fn data_type(&self) -> u32 {
        u32_at(self.cell, 12).unwrap_or(0)
    }

    pub fn name(&self) -> String {
        let length = usize::from(u16_at(self.cell, 2).unwrap_or(0));
        let flags = u16_at(self.cell, 16).unwrap_or(0);
        let bytes = &self.cell[VK_FIXED..(VK_FIXED + length).min(self.cell.len())];
        text(bytes, flags & 1 != 0)
    }

    /// The value's data: kept in the value itself (up to 4 bytes), in a cell, or in the
    /// segments of a big data (`db`) cell.
    pub fn data(&self) -> Result<Vec<u8>> {
        let size = u32_at(self.cell, 4).unwrap_or(0);
        if size & 0x8000_0000 != 0 {
            let length = (size & 0x7fff_ffff).min(4) as usize;
            return Ok(self.cell[8..8 + length].to_vec());
        }
        let size = size as usize;
        let offset = u32_at(self.cell, 8).unwrap_or(u32::MAX);
        let cell = self.hive.cell(offset)?;
        if size > BIG_DATA_SEGMENT && cell.get(..2) == Some(b"db") {
            return self.big_data(cell, size);
        }
        cell.get(..size)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| format!("the data of a value is cut short ({size} bytes declared)"))
    }

    /// Data split in segments; never more than the declared size or the hive's own size.
    fn big_data(&self, db: &[u8], size: usize) -> Result<Vec<u8>> {
        let count = usize::from(u16_at(db, 2).unwrap_or(0));
        let list = self.hive.cell(u32_at(db, 4).unwrap_or(u32::MAX))?;
        let segments = list
            .get(..count * 4)
            .ok_or("a big data segment list is cut short")?;
        let size = size.min(self.hive.data.len());
        let mut data = Vec::new();
        for s in segments.as_chunks::<4>().0 {
            let segment = self.hive.cell(u32::from_le_bytes(*s))?;
            let take = (size - data.len()).min(BIG_DATA_SEGMENT).min(segment.len());
            data.extend_from_slice(&segment[..take]);
            if data.len() == size {
                return Ok(data);
            }
        }
        Err(format!(
            "the data of a value is cut short ({size} bytes declared)"
        ))
    }

    /// The data as a string (`REG_SZ`, `REG_EXPAND_SZ`): UTF-16, up to its first NUL.
    pub fn string(&self) -> Result<String> {
        let data = self.data()?;
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|u| u16::from_le_bytes(*u))
            .take_while(|&u| u != 0)
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    /// The data as a `REG_DWORD`.
    pub fn dword(&self) -> Result<u32> {
        u32_at(&self.data()?, 0).ok_or_else(|| "a DWORD value has fewer than 4 bytes".into())
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    b.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Whether a hive's base block says it is dirty: its two sequence numbers differ (Windows
/// hadn't finished writing it).
pub fn is_dirty(data: &[u8]) -> bool {
    u32_at(data, 4) != u32_at(data, 8)
}

/// The last component of the path the base block records for the hive (UTF-16, 64 bytes at 48).
pub fn base_name(data: &[u8]) -> String {
    let path = text(data.get(48..112).unwrap_or_default(), false);
    let path = path.split('\0').next().unwrap_or_default();
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_string()
}

/// A name: one byte per character (Latin-1) or UTF-16.
fn text(bytes: &[u8], one_byte: bool) -> String {
    if one_byte {
        bytes.iter().map(|&b| char::from(b)).collect()
    } else {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|u| u16::from_le_bytes(*u))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// Registry names compare ignoring case.
fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || a.to_uppercase() == b.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_hives() {
        assert!(Hive::from_bytes(Vec::new()).is_err());
        assert!(Hive::from_bytes(vec![0; 8192]).is_err());
        let mut no_root = vec![0; 8192];
        no_root[..4].copy_from_slice(b"regf");
        no_root[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Hive::from_bytes(no_root).is_err());
    }

    #[test]
    fn names() {
        assert_eq!(text(b"ProfileList", true), "ProfileList");
        assert_eq!(text(&[0x41, 0, 0xe9, 0], false), "Aé");
        assert!(same_name("WLANSVC", "WlanSvc"));
        assert!(same_name("Ä", "ä"));
        assert!(!same_name("Profiles", "Profile"));
    }
}
