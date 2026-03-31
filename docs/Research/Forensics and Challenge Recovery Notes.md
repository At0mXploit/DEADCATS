---
title: Forensics and Challenge Recovery Notes
slug: /Research/Forensics-and-Challenge-Recovery-Notes
sidebar_position: 4
custom_edit_url: null
---

This page collects selected research notes centered on packet capture analysis, protocol inspection, firmware recovery, USB artifact decoding, and steganographic extraction. The emphasis is on the practical path from noisy evidence to a reproducible result.

## Large PCAP Noise Analysis

### Summary

- Challenge file: `1 GB` PCAP
- Recovered output: `[redacted output]`

### Initial Scanning

Initial surface scanning with tools such as `strings` showed large amounts of noisy payload data and little directly useful text. The dataset was intentionally padded to make casual inspection expensive and misleading.

### Main Hint

Using `capinfos` showed that the large capture was effectively built from three merged sources:

- `massive.pcap`: bulk random payloads used to inflate file size
- `decoy_trap.pcap`: contained the fake output token `[redacted output]`
- `covert_timing_2.pcap`: the meaningful stream, where packet timing carried the signal

The main point was that the file size itself was part of the misdirection.

### Solving Method

The useful path was to isolate the raw IPv4 signal and examine timing rather than payload content.

Extract raw IPv4 packets:

```bash
tshark -r Breathing_Void.pcap -Y "frame.encap_type == 129" -w raw_signal.pcap
```

Extract interface `2` traffic:

```bash
tshark -r Breathing_Void.pcap -Y "frame.interface_id == 2" -w interface2.pcap
```

Analyze timestamps and lengths:

```bash
tshark -r raw_signal.pcap -V > raw_packets.txt
tshark -r raw_signal.pcap -T fields -e frame.time_epoch -e frame.len -e ip.src -e ip.dst -e data > timing_data.txt
```

Timing decoder:

```python
timestamps = []
with open('timing_data.txt', 'r') as f:
    for line in f:
        parts = line.strip().split('\t')
        if parts[0]:
            timestamps.append(float(parts[0]))

delays = []
for i in range(1, len(timestamps)):
    delays.append(timestamps[i] - timestamps[i - 1])

threshold = sum(delays) / len(delays)
binary = ''.join('1' if d > threshold else '0' for d in delays)

chars = []
for i in range(0, len(binary) - 7, 8):
    chars.append(chr(int(binary[i:i + 8], 2)))

print(''.join(chars))
```

Recovered output:

`ÅH4X{pc@p5_@re_of+en_mo5+1y_noi5e}`

After correcting the leading character to match the expected output format, the final result was:

`[redacted output]`

## Final Boss

### Files

- `capture.pcapng`

### Goal

Recover the complete hidden output from a USB packet capture.

### Initial Inspection

The capture contains only USB traffic. Basic triage showed:

- USBPcap capture
- one USB device
- Microsoft Xbox controller

Useful traffic:

- Device to host: endpoint `0x82`, `44-byte` reports
- Host to device: endpoint `0x02`, `13-byte` reports

### Stage 1: Button Report Decoding

The `0x82 / 44-byte` reports contain a changing byte for controller face-button presses:

- `0x10`
- `0x20`
- `0x40`
- `0x80`

Those values map to base-4 digits:

- `0x10 -> 0`
- `0x20 -> 3`
- `0x40 -> 1`
- `0x80 -> 2`

Grouping the digits into bytes recovers the first recovered token fragment:

`CodeVinci{17_w45_V3rY_d1ff1cUL7_t0_b34t_7H3_F1N4l_8055_`

### Stage 2: Rumble Stream Decoding

The later `0x02 / 13-byte` host-to-device reports use a pair of state bytes that encode symbols:

- `(100, 0)` -> `L`
- `(0, 100)` -> `R`
- `(100, 100)` -> `B`
- `(0, 0)` -> idle, ignored

After removing idle events, `B` acts as a separator and `L/R` encode Morse using:

- `L = .`
- `R = -`

This yields the second fragment:

`MY_H4ND5_4R3_571LL_5H4K1NG`

### Final Flag

`CodeVinci{17_w45_V3rY_d1ff1cUL7_t0_b34t_7H3_F1N4l_8055_MY_H4ND5_4R3_571LL_5H4K1NG}`

### Reproducible Solver

```python
import subprocess


def tshark_fields(*fields, display_filter=None):
    cmd = ["tshark", "-r", "capture.pcapng"]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields"]
    for field in fields:
        cmd += ["-e", field]
    out = subprocess.check_output(cmd, text=True)
    return [line for line in out.splitlines() if line.strip()]


def decode_stage1():
    mapping = {0x10: 0, 0x20: 3, 0x40: 1, 0x80: 2}
    digits = []
    rows = tshark_fields(
        "usb.capdata",
        display_filter="usb.endpoint_address == 0x82 && usb.data_len == 44",
    )
    for hexdata in rows:
        report = bytes.fromhex(hexdata)
        button = report[4]
        if button:
            digits.append(mapping[button])

    out = []
    for i in range(0, len(digits), 4):
        chunk = digits[i:i + 4]
        if len(chunk) < 4:
            break
        value = chunk[0] * 64 + chunk[1] * 16 + chunk[2] * 4 + chunk[3]
        out.append(chr(value))
    return "".join(out)


def decode_stage2():
    morse = {
        ".-": "A",
        "-...": "B",
        "-.-.": "C",
        "-..": "D",
        ".": "E",
        "..-.": "F",
        "--.": "G",
        "....": "H",
        "..": "I",
        ".---": "J",
        "-.-": "K",
        ".-..": "L",
        "--": "M",
        "-.": "N",
        "---": "O",
        ".--.": "P",
        "--.-": "Q",
        ".-.": "R",
        "...": "S",
        "-": "T",
        "..-": "U",
        "...-": "V",
        ".--": "W",
        "-..-": "X",
        "-.--": "Y",
        "--..": "Z",
        "-----": "0",
        ".----": "1",
        "..---": "2",
        "...--": "3",
        "....-": "4",
        ".....": "5",
        "-....": "6",
        "--...": "7",
        "---..": "8",
        "----.": "9",
        "..--.-": "_",
    }

    state_map = {
        (100, 0): "L",
        (0, 100): "R",
        (100, 100): "B",
    }

    rows = tshark_fields(
        "usb.capdata",
        display_filter="usb.endpoint_address == 0x02 && usb.data_len == 13 && frame.number >= 1237",
    )

    symbols = []
    for hexdata in rows:
        report = bytes.fromhex(hexdata)
        state = (report[8], report[9])
        if state != (0, 0):
            symbols.append(state_map[state])

    text = "".join(symbols)
    chunks = [chunk for chunk in text.split("B") if chunk]

    decoded = []
    for chunk in chunks:
        code = chunk.replace("L", ".").replace("R", "-")
        decoded.append(morse[code])
    return "".join(decoded)


def main():
    stage1 = decode_stage1()
    stage2 = decode_stage2()
    recovered = stage1 + stage2 + "}"
    print("Stage 1:", stage1)
    print("Stage 2:", stage2)
    print("Recovered value:", recovered)


if __name__ == "__main__":
    main()
```

## Damaged Embedded CNC Controller

### Summary

File provided:

- `controller_fw.bin`

The prompt states that a CNC machine was engraving something important before power loss. The task is to recover what it was engraving and derive the final protected value.

### Initial Triage

Quick inspection:

```bash
file controller_fw.bin
strings -n 4 controller_fw.bin | head -n 40
```

Interesting strings:

- `JBUFHDR5SEG4`
- `job_buffer: packet format [4B:length][1B:seg_id][NB:data] x4 segments`
- debug text from the AXIOM controller firmware

That strongly suggests a packetized job buffer with four embedded segments.

### Packet Structure

At offset `0x1000`, the header begins with:

- magic: `JBUFHDR5SEG4`
- four records of:
  - `uint32 length` in little-endian
  - `uint8 seg_id`
  - `length` bytes of data

After sorting by `seg_id`, the segment lengths were:

- `sid 0`: 1580 bytes
- `sid 1`: 246 bytes
- `sid 2`: 2767 bytes
- `sid 3`: 3986 bytes

### Payload Deobfuscation

The payloads do not start as plaintext, but each segment decodes cleanly with an 8-byte repeating XOR key that resets at the start of every segment:

`F1 4C 3B A7 2E 91 C4 08`

Once decoded, the content becomes readable G-code including:

- `(seg:1/4)`
- `G00`
- `G01`
- `G02`
- `G03`

Reconstructing the toolpath shows that the machine was engraving:

`f'GS`

### Final Value

The recovery note states that if the engraving is `f'XYZ...`, the output format is:

`[redacted output]`

Recovered output:

`[redacted output]`

## Beneath the Armor

### Research Theme

This image-analysis task hides a protected string inside a PNG file using a modified LSB steganography scheme.

### Why Standard LSB Fails

A normal LSB extractor reads bit `0` from each RGB channel. Running `zsteg` confirms that hidden data exists, but the output is garbled:

```text
b1,r,lsb,xy  .. text: "QR{f>_YG"
```

That indicates the extraction model is close, but not correct.

### Hint Interpretation

The guiding hints included the ideas of:

- history repeating itself
- cycles
- a standard method with a slight change

The correct interpretation is that the bit plane does not stay fixed. Instead, it cycles through:

`0 -> 1 -> 2 -> 0 -> 1 -> 2`

So the extraction pattern becomes:

- Pixel 0, Red: bit `0`
- Pixel 0, Green: bit `1`
- Pixel 0, Blue: bit `2`
- Pixel 1, Red: bit `0`
- and so on

### Solve Script

```python
from PIL import Image
import numpy as np

img = Image.open('challenge.png')
pixels = np.array(img).reshape(-1, 3)

cycle = [0, 1, 2]

bits = []
for i in range(len(pixels)):
    for ch in range(3):
        bit_plane = cycle[(i * 3 + ch) % 3]
        bit = (int(pixels[i, ch]) >> bit_plane) & 1
        bits.append(bit)

output = []
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    output.append(byte)

message = bytes(output)
start = message.find(b'<token-prefix>{')
end = message.find(b'}', start) + 1
print(message[start:end].decode())
```

Recovered output:

`[redacted output]`

### Key Takeaway

This is a good example of an analysis task that stays close to a standard technique while altering just one assumption. The extraction logic remained ordinary LSB steganography, but the bit position rotated in a predictable cycle instead of staying fixed.
