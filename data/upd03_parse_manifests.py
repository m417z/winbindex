import xml.etree.ElementTree as ET
from pathlib import Path
import base64
import json
import re

import config

file_hashes = {}


def update_file_hashes():
    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    for name in file_hashes:
        for file_hash in file_hashes[name]:
            info_sources.setdefault(name, {}).setdefault(file_hash, 'none')

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f)

    file_hashes.clear()


def get_delta_data_for_manifest_file(manifest_path: Path, filename: str):
    delta_path = manifest_path.parent.joinpath(manifest_path.stem, 'f', filename + '.dd.txt')
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
            'CLI4_ARM64': 43620,
        }
        result['machineType'] = machine_type_values[delta_data['Code']]

        result['timestamp'] = int(delta_data['TimeStamp'])

        rift_table = delta_data['RiftTable']
        rift_table_last = rift_table.split(';')[-1].split(',')

        result['lastSectionVirtualAddress'] = int(rift_table_last[0])
        result['lastSectionPointerToRawData'] = int(rift_table_last[1])

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

    filename = file_el.attrib['name'].split('\\')[-1].lower()
    if algorithm == 'sha256':
        if (re.search(r'\.(exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv)$', filename)):
            file_hashes.setdefault(filename, set()).add(hash)

    result = {
        algorithm: hash,
        'attributes': dict(file_el.attrib.items()),
    }

    delta_data = get_delta_data_for_manifest_file(manifest_path, filename)
    if delta_data:
        result['delta'] = delta_data

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
