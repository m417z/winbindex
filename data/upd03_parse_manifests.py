import xml.etree.ElementTree as ET
from pathlib import Path
import base64
import json

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

def parse_manifest_file(file_el):
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
    sha256 = base64.b64decode(digest_value_el.text).hex()

    filename = file_el.attrib['name'].split('\\')[-1].lower()
    if (filename.endswith('.exe') or
        filename.endswith('.dll') or
        filename.endswith('.sys')):
        file_hashes.setdefault(filename, set()).add(sha256)

    result = {
        algorithm: sha256,
        'attributes': dict(file_el.attrib.items()),
    }

    return result

def parse_manifest(filename):
    #root = ET.parse(filename).getroot()
    # Strip namespaces.
    # https://stackoverflow.com/a/33997423
    it = ET.iterparse(filename)
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
        parsed = parse_manifest_file(file_el)
        files.append(parsed)

    result = {
        'assemblyIdentity': {key: value for (key, value) in assembly_identity.attrib.items()},
        'files': files
    }

    return result

def parse_manifests(manifests_dir, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    for path in manifests_dir.glob('*.manifest'):
        if not path.is_file():
            continue

        try:
            parsed = parse_manifest(str(path))
        except Exception as e:
            print(f'ERROR: failed to process {path}')
            print('    ' + str(e))
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
        print(f'Processing Windows version {windows_version}:', end='', flush=True)

        for update_kb in updates[windows_version]:
            manifests_dir = config.out_path.joinpath('manifests', windows_version, update_kb)
            if manifests_dir.is_dir():
                output_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
                parse_manifests(manifests_dir, output_dir)
                print(' ' + update_kb, end='', flush=True)

        print()

    update_file_hashes()

if __name__ == '__main__':
    main()
