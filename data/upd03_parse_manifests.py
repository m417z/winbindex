import xml.etree.ElementTree as ET
from struct import unpack
from pathlib import Path
import hashlib
import base64
import json
import re

import config

file_hashes = {}


def update_info_source(old, new):
    sources = [
        'none',
        'delta',
        'delta+',
        'pe',
        'vt',
        'file',
    ]

    if old is None or sources.index(new) > sources.index(old):
        return new

    return old


def update_file_hashes():
    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    for name in file_hashes:
        file_info_sources = info_sources.setdefault(name, {})

        for file_hash in file_hashes[name]:
            old = file_info_sources.get(file_hash)
            new = file_hashes[name][file_hash]
            file_info_sources[file_hash] = update_info_source(old, new)

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)

    file_hashes.clear()


# https://stackoverflow.com/a/44873382
def md5sum(filename):
    h  = hashlib.md5()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def get_delta_data_for_manifest_file(manifest_path: Path, name: str):
    delta_path = manifest_path.parent.joinpath(manifest_path.stem, 'f', name + '.dd.txt')
    if not delta_path.exists():
        return None

    delta_data_raw = delta_path.read_text()

    delta_data = {}
    key_value = re.findall(r'^(\w+):(.*)$', delta_data_raw, re.MULTILINE)
    for key, value in key_value:
        delta_data[key] = value.strip()

    result = {}

    result['size'] = int(delta_data['TargetSize'])

    assert delta_data['HashAlgorithm'] == 'CALG_MD5'
    result['md5'] = delta_data['Hash'].lower()

    if delta_data['Code'] != 'Raw':
        machine_type_values = {
            'CLI4_I386': 332,
            'CLI4_AMD64': 34404,
            'CLI4_ARM': 452,
            'CLI4_ARM64': 43620,
        }
        assert delta_data['Code'] in config.delta_machine_type_values_supported
        result['machineType'] = machine_type_values[delta_data['Code']]

        result['timestamp'] = int(delta_data['TimeStamp'])

        rift_table = delta_data['RiftTable']
        rift_table_last = rift_table.split(';')[-1].split(',')

        result['lastSectionVirtualAddress'] = int(rift_table_last[0])
        result['lastSectionPointerToRawData'] = int(rift_table_last[1])

    return result


def get_file_data_for_manifest_file(manifest_path: Path, name: str):
    file_path = manifest_path.parent.joinpath(manifest_path.stem, 'n', name)
    if not file_path.exists():
        file_path = manifest_path.parent.joinpath(manifest_path.stem, name)
        if not file_path.exists():
            return None

    size = file_path.stat().st_size

    result = {
        'size': size,
        'md5': md5sum(file_path),
    }

    if size >= 0x40:
        # https://gist.github.com/geudrik/03152ba1a148d9475e81
        with open(file_path, 'rb') as handle:
            if handle.read(2) == b'MZ':
                # Get PE offset from DOS header.
                handle.seek(0x3c)
                offset = handle.read(4)
                offset = unpack('<I', offset)[0]

                if size >= offset + 0x54:
                    handle.seek(offset)
                    # Check if PE signature is valid.
                    if handle.read(4) == b'PE\0\0':
                        word = handle.read(2)
                        result['machineType'] = unpack('<H', word)[0]

                        handle.seek(offset + 8)
                        dword = handle.read(4)
                        result['timestamp'] = unpack('<I', dword)[0]

                        handle.seek(offset + 0x50)
                        dword = handle.read(4)
                        result['virtualSize'] = unpack('<I', dword)[0]

    return result


def parse_manifest_file(manifest_path, file_el):
    hashes = list(file_el.findall('hash'))
    if len(hashes) != 1:
        raise Exception('Expected to have a single hash tag')

    hash_el = hashes[0]

    digest_methods = list(hash_el.findall('DigestMethod'))
    if len(digest_methods) != 1:
        raise Exception('Expected to have a single DigestMethod tag')

    digest_method_el = digest_methods[0]
    attrib = digest_method_el.attrib

    if attrib['Algorithm'] == 'http://www.w3.org/2000/09/xmldsig#sha1':
        algorithm = 'sha1'
    elif attrib['Algorithm'] == 'http://www.w3.org/2000/09/xmldsig#sha256':
        algorithm = 'sha256'
    else:
        raise Exception('Expected Algorithm to be sha1 or sha256')

    digest_values = list(hash_el.findall('DigestValue'))
    if len(digest_values) != 1:
        raise Exception('Expected to have a single DigestValue tag')

    digest_value_el = digest_values[0]
    hash = base64.b64decode(digest_value_el.text).hex()

    result = {
        algorithm: hash,
        'attributes': dict(file_el.attrib.items()),
    }

    info_source = 'none'

    file_info = get_file_data_for_manifest_file(manifest_path, file_el.attrib['name'])
    if file_info:
        info_source = 'pe'
    else:
        file_info = get_delta_data_for_manifest_file(manifest_path, file_el.attrib['name'])
        if file_info:
            info_source = 'delta'

    if file_info:
        result['fileInfo'] = file_info

    if algorithm == 'sha256':
        filename = file_el.attrib['name'].split('\\')[-1].lower()
        if (re.search(r'\.(exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv)$', filename)):
            if hash in config.file_hashes_non_pe:
                if file_info:
                    assert info_source == 'delta' and file_info.keys() == {'size', 'md5'}
                else:
                    assert info_source == 'none'
                assert hash not in file_hashes.get(filename, {})
            else:
                assert info_source == 'none' or (file_info and 'machineType' in file_info), (filename, hash)
                file_hashes_for_filename = file_hashes.setdefault(filename, {})
                old_info_source = file_hashes_for_filename.get(hash)
                file_hashes_for_filename[hash] = update_info_source(old_info_source, info_source)

    return result


def parse_manifest(manifest_path: Path):
    #root = ET.parse(str(manifest_path)).getroot()
    # Strip namespaces.
    # https://stackoverflow.com/a/33997423
    it = ET.iterparse(str(manifest_path))
    for _, el in it:
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]  # strip all namespaces
        if el.tag != 'assembly':  # assembly tag has same attributes with multiple namespaces
            for at in list(el.attrib.keys()):  # strip namespaces of attributes too
                if '}' in at:
                    newat = at.split('}', 1)[1]
                    if newat in el.attrib:
                        raise Exception(f'XML attribute already exists: {newat}')
                    el.attrib[newat] = el.attrib[at]
                    del el.attrib[at]
    root = it.root

    assembly_identities = list(root.findall('assemblyIdentity'))
    if len(assembly_identities) != 1:
        raise Exception('Expected to have a single assemblyIdentity tag')

    assembly_identity = assembly_identities[0]

    files = []
    for file_el in root.findall('file'):
        parsed = parse_manifest_file(manifest_path, file_el)
        files.append(parsed)

    result = {
        'assemblyIdentity': {key: value for (key, value) in assembly_identity.attrib.items()},
        'files': files
    }

    return result


def parse_manifests(manifests_dir: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    for path in manifests_dir.glob('*.manifest'):
        if not path.is_file():
            continue

        try:
            parsed = parse_manifest(path)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            print(f'ERROR: failed to process {path}')
            print(f'       {e}')
            if config.exit_on_first_error:
                raise
            continue

        if not parsed or len(parsed['files']) == 0:
            continue

        output_filename = output_dir.joinpath(path.name).with_suffix('.json')
        with open(output_filename, 'w') as f:
            json.dump(parsed, f, indent=4)


def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = json.load(f)

    for windows_version in updates:
        print(f'Processing Windows version {windows_version}:')

        for update_kb in updates[windows_version]:
            manifests_dir = config.out_path.joinpath('manifests', windows_version, update_kb)
            if manifests_dir.is_dir():
                output_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
                parse_manifests(manifests_dir, output_dir)
                print('  ' + update_kb)

    update_file_hashes()


if __name__ == '__main__':
    main()
