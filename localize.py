#!/usr/bin/env python3
"""Apply the version-locked WQ Files 0.7 Simplified Chinese translation."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import zipfile

SOURCE_SHA256 = 'a02167446b03bca24b688bd33d57b4bec967f637e854084aba60e808df4fdaa3'
APP = 'Payload/WQFiles.app/'
CFSTRING_OFFSET = 366952
CFSTRING_SIZE = 40544
TARGET_MASK = (1 << 36) - 1
PLACEHOLDER = re.compile(r'%(?:\d+\$)?[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:ll|l|hh|h|z|t|j)?[@diuoxXfFeEgGaAcCsSp%]')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_strings(binary):
    rows = []
    for offset in range(CFSTRING_OFFSET, CFSTRING_OFFSET + CFSTRING_SIZE, 32):
        _, flags, pointer, length = struct.unpack_from('<QQQQ', binary, offset)
        require(flags in (0x7c8, 0x7d0), 'Unexpected CFString encoding')
        address = pointer & TARGET_MASK
        width, encoding = (2, 'utf-16le') if flags == 0x7d0 else (1, 'utf-8')
        require(address + length * width <= len(binary), 'CFString outside file')
        text = binary[address:address + length * width].decode(encoding)
        rows.append((offset, text))
    return rows


def patch(binary, entries):
    # Version-specific mapped padding; retain every instruction and load command.
    regions = [(415640, 425984), (8192, 16384)]
    for start, end in regions:
        require(not any(binary[start:end]), 'Expected padding is not empty')
    rows = read_strings(binary)
    patched = bytearray(binary)
    region, cursor = 0, regions[0][0]
    seen = set()
    for entry in entries:
        index, source, translation = entry['index'], entry['source'], entry['translation']
        require(isinstance(index, int) and 0 <= index < len(rows), 'Invalid translation index')
        require(index not in seen, f'Duplicate translation: {index}')
        seen.add(index)
        offset, original = rows[index]
        require(source == original, f'Source mismatch at {index}')
        require(PLACEHOLDER.findall(source) == PLACEHOLDER.findall(translation), f'Format placeholder mismatch at {index}')
        require('\0' not in translation, f'NUL in translation at {index}')
        encoded = translation.encode('utf-16le')
        data = encoded + b'\0\0'
        if cursor + len(data) > regions[region][1]:
            region += 1
            require(region < len(regions), 'Translations exceed available padding')
            cursor = regions[region][0]
        require(cursor + len(data) <= regions[region][1], 'Translation exceeds padding region')
        patched[cursor:cursor + len(data)] = data
        pointer = struct.unpack_from('<Q', patched, offset + 16)[0]
        require(pointer >> 63 == 0, 'Expected chained rebase, found bind')
        # DYLD_CHAINED_PTR_64_OFFSET: only replace the target offset.
        struct.pack_into('<Q', patched, offset + 8, 0x7d0)
        struct.pack_into('<Q', patched, offset + 16, (pointer & ~TARGET_MASK) | cursor)
        struct.pack_into('<Q', patched, offset + 24, len(encoded) // 2)
        cursor += len(data)
    actual = read_strings(patched)
    expected = {entry['index']: entry['translation'] for entry in entries}
    for i, (offset, source) in enumerate(rows):
        require(actual[i][1] == expected.get(i, source), f'Readback mismatch at {i}')
        old = struct.unpack_from('<Q', binary, offset + 16)[0]
        new = struct.unpack_from('<Q', patched, offset + 16)[0]
        require(old >> 36 == new >> 36, f'Chained pointer metadata changed at {i}')
    require(binary[:3952] == patched[:3952], 'Mach-O header or load commands changed')
    require(binary[16384:259320] == patched[16384:259320], 'Machine instructions changed')
    return bytes(patched)


def build(source, output, translations):
    require(source.resolve() != output.resolve(), 'Input and output must be different')
    require(not output.exists(), 'Output already exists; choose a new path')
    # Keep the bytes hashed here as the exact input used below.
    import io
    input_bytes = source.read_bytes()
    require(hashlib.sha256(input_bytes).hexdigest() == SOURCE_SHA256,
            'Unsupported IPA: SHA-256 mismatch. Only the documented 0.7 build 26 is supported.')
    entries = json.loads(translations.read_text(encoding='utf-8'))
    with zipfile.ZipFile(io.BytesIO(input_bytes)) as archive:
        binary = patch(archive.read(APP + 'WQFiles'), entries)
        info = plistlib.loads(archive.read(APP + 'Info.plist'))
        info.update(CFBundleDevelopmentRegion='zh_CN', CFBundleLocalizations=['zh-Hans', 'en'], CFBundleDisplayName='WQ 文件')
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as target:
            for member in archive.infolist():
                data = archive.read(member.filename)
                if member.filename == APP + 'WQFiles':
                    data = binary
                elif member.filename == APP + 'Info.plist':
                    data = plistlib.dumps(info, fmt=plistlib.FMT_BINARY)
                target.writestr(member, data)
            target.writestr(APP + 'zh-Hans.lproj/InfoPlist.strings',
                            '"CFBundleDisplayName" = "WQ 文件";\n'.encode('utf-16'))
    with zipfile.ZipFile(output) as verify:
        require(verify.testzip() is None, 'ZIP integrity check failed')
        require(verify.read(APP + 'WQFiles') == binary, 'Archived binary differs')
    with output.with_suffix('.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['英文原文', '简体中文'])
        writer.writerows((e['source'], e['translation']) for e in entries)
    report = {
        'input_sha256': SOURCE_SHA256,
        'output_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
        'translations': len(entries),
        'cfstrings_verified': CFSTRING_SIZE // 32,
        'instructions_unchanged': True,
        'load_commands_unchanged': True,
        'zip_integrity': 'passed',
        'signature': 'invalidated; re-signing required; original metadata retained',
        'runtime_tested': False,
    }
    output.with_suffix('.validation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='Original WQFiles.ipa (0.7 build 26)')
    parser.add_argument('-o', '--output', type=Path, default=Path('dist/WQFiles_0.7_zh-Hans_unsigned.ipa'))
    parser.add_argument('--translations', type=Path, default=Path(__file__).resolve().parent / 'translations/zh-Hans.json')
    args = parser.parse_args()
    try:
        report = build(args.input, args.output, args.translations)
    except (ValueError, OSError, zipfile.BadZipFile, KeyError, TypeError, struct.error) as error:
        parser.exit(1, f'Error: {error}\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f'Created: {args.output}\nRe-sign with App Group entitlements before installing.')


if __name__ == '__main__':
    main()
