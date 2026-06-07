use std::fs::File;
use std::io::Write;

use memmap2::Mmap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let src = &args[1];
    let dst = &args[2];
    let max_packets: usize = args[3].parse().expect("max_packets usize");

    eprintln!("[slice] mmap {}", src);
    let file = File::open(src).expect("open input");
    let mmap = unsafe { Mmap::map(&file) }.expect("mmap input");
    let total = mmap.len();
    eprintln!("[slice] mmap ok {} MB", total / 1_000_000);

    let mut output = File::create(dst).expect("create output");

    let mut offset: usize = 0;
    let mut packet_count: usize = 0;
    let mut total_written: usize = 0;
    let mut wrote_shb = false;
    let mut wrote_idb = false;

    while offset + 8 <= total {
        let block_type = u32::from_le_bytes([
            mmap[offset],
            mmap[offset + 1],
            mmap[offset + 2],
            mmap[offset + 3],
        ]);
        let block_len = u32::from_le_bytes([
            mmap[offset + 4],
            mmap[offset + 5],
            mmap[offset + 6],
            mmap[offset + 7],
        ]) as usize;

        if block_len < 12 || offset + block_len > total {
            eprintln!(
                "[slice] stopping at offset={}: type=0x{:08x} len={} (out of bounds)",
                offset, block_type, block_len
            );
            break;
        }

        let block_type_name = match block_type {
            0x0A0D0D0A => "shb",
            0x00000001 => "idb",
            0x00000006 => "epb",
            0x00000003 => "spb",
            0x00000004 => "nrb",
            0x00000005 => "isb",
            0x00000002 => "pb",
            _ => "other",
        };

        let is_shb = block_type == 0x0A0D0D0A;
        let is_idb = block_type == 0x00000001;
        let is_packet = block_type == 0x00000006 || block_type == 0x00000003;

        let take = if is_shb {
            wrote_shb = true;
            true
        } else if is_idb && !wrote_idb {
            wrote_idb = true;
            true
        } else if is_packet {
            packet_count < max_packets
        } else {
            true
        };

        if take {
            output
                .write_all(&mmap[offset..offset + block_len])
                .expect("write block");
            total_written += block_len;
            if is_shb || is_idb || is_packet {
                eprintln!(
                    "[slice] wrote {} offset={} len={}B total={}MB",
                    block_type_name,
                    offset,
                    block_len,
                    total_written / 1_000_000
                );
            }
        }

        if is_packet {
            if packet_count < max_packets {
                packet_count += 1;
                if packet_count % 50_000 == 0 {
                    eprintln!(
                        "[slice] packets={} offset={}MB total={}MB",
                        packet_count,
                        offset / 1_000_000,
                        total_written / 1_000_000
                    );
                }
            } else {
                break;
            }
        }

        offset += block_len;
    }

    eprintln!(
        "[slice] done packets={} total_written={}MB shb={} idb={}",
        packet_count,
        total_written / 1_000_000,
        wrote_shb,
        wrote_idb
    );
}
