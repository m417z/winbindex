from signify.authenticode.signed_pe import SignedPEFile
import xml.etree.ElementTree as ET
from struct import unpack
from pathlib import Path
from typing import List
import fnmatch
import hashlib
import signify
import base64
import ctypes
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
def hash_sum(filename: Path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    b = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            hash_md5.update(mv[:n])
            hash_sha1.update(mv[:n])
            hash_sha256.update(mv[:n])
    return hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest()


# returns the requested version information from the given file
#
# if language, codepage are None, the first translation in the translation table
# is used instead, as well as common fallback translations
#
# Reference: https://stackoverflow.com/a/56266129
def get_file_version_info(pathname: Path, prop_names: List[str],
                          language: int | None = None, codepage: int | None = None):
    # VerQueryValue() returns an array of that for VarFileInfo\Translation
    #
    class LANGANDCODEPAGE(ctypes.Structure):
        _fields_ = [
            ("wLanguage", ctypes.c_uint16),
            ("wCodePage", ctypes.c_uint16)]

    # avoid some path length limitations by using a resolved path
    wstr_file = ctypes.wstring_at(str(pathname.resolve(strict=True)))

    # getting the size in bytes of the file version info buffer
    size = ctypes.windll.version.GetFileVersionInfoSizeExW(2, wstr_file, None)
    if size == 0:
        e = ctypes.WinError()
        if e.winerror == 1813:
            # ERROR_RESOURCE_TYPE_NOT_FOUND
            return {}
        raise e

    buffer = ctypes.create_string_buffer(size)

    # getting the file version info data
    if ctypes.windll.version.GetFileVersionInfoExW(2, wstr_file, None, size, buffer) == 0:
        raise ctypes.WinError()

    # VerQueryValue() wants a pointer to a void* and DWORD; used both for
    # getting the default translation (if necessary) and getting the actual data
    # below
    value = ctypes.c_void_p(0)
    value_size = ctypes.c_uint(0)

    translations = []

    if language is None and codepage is None:
        # file version information can contain much more than the version
        # number (copyright, application name, etc.) and these are all
        # translatable
        #
        # the following arbitrarily gets the first language and codepage from
        # the list
        ret = ctypes.windll.version.VerQueryValueW(
            buffer, ctypes.wstring_at(R"\VarFileInfo\Translation"),
            ctypes.byref(value), ctypes.byref(value_size))

        if ret == 0:
            e = ctypes.WinError()
            if e.winerror == 1813:
                # ERROR_RESOURCE_TYPE_NOT_FOUND
                first_language, first_codepage = None, None
            else:
                raise e
        else:
            # value points to a byte inside buffer, value_size is the size in bytes
            # of that particular section

            # casting the void* to a LANGANDCODEPAGE*
            lcp = ctypes.cast(value, ctypes.POINTER(LANGANDCODEPAGE))

            first_language, first_codepage = lcp.contents.wLanguage, lcp.contents.wCodePage

            translation = first_language, first_codepage
            translations.append(translation)

        # use fallback values the same way sigcheck does
        translation = first_language, 1252
        if first_language and translation not in translations:
            translations.append(translation)

        translation = 1033, 1252
        if translation not in translations:
            translations.append(translation)

        translation = 1033, first_codepage
        if first_codepage and translation not in translations:
            translations.append(translation)
    else:
        assert language is not None and codepage is not None
        translation = language, codepage
        translations.append(translation)

    # getting the actual data
    result = {}
    for prop_name in prop_names:
        for language_id, codepage_id in translations:
            # formatting language and codepage to something like "040904b0"
            translation = "{0:04x}{1:04x}".format(language_id, codepage_id)

            res = ctypes.windll.version.VerQueryValueW(
                buffer, ctypes.wstring_at("\\StringFileInfo\\" + translation + "\\" + prop_name),
                ctypes.byref(value), ctypes.byref(value_size))

            if res == 0:
                e = ctypes.WinError()
                if e.winerror == 1813:
                    # ERROR_RESOURCE_TYPE_NOT_FOUND
                    continue
                raise e

            # value points to a string of value_size characters, minus one for the
            # terminating null
            prop = ctypes.wstring_at(value.value, value_size.value - 1)

            # some resource strings contain null characters, but they indicate the
            # end of the string for most tools; removing them
            #
            # example:
            # imjppsgf.fil
            # https://www.virustotal.com/gui/file/42deb76551bc087d791eac266a6570032246ec78f4471e7a8922ceb7eb2e91c3/details
            # FileVersion: '15.0.2271.1000\x001000'
            # FileDescription: '\u5370[...]\u3002\x00System Dictionary File'
            prop = prop.split('\0', 1)[0]

            result[prop_name] = prop
            break

    return result


# Reference:
# https://signify.readthedocs.io/en/latest/authenticode.html
def get_file_signing_times(pathname: Path):
    signing_times = []
    with open(pathname, 'rb') as f:
        pefile = SignedPEFile(f)
        for signed_data in pefile.signed_datas:
            if signed_data.signer_info.countersigner is not None:
                signing_time = signed_data.signer_info.countersigner.signing_time
                signing_times.append(signing_time.isoformat().removesuffix('+00:00'))

    return signing_times


def get_delta_data_for_manifest_file(manifest_path: Path, name: str):
    delta_path = manifest_path.parent.joinpath(manifest_path.stem, 'f', name + '.dd.txt')
    if not delta_path.exists():
        return None

    delta_data_raw = delta_path.read_text()

    delta_data = {}
    key_value = re.findall(r'^(\w+):(.*)$', delta_data_raw, re.MULTILINE)
    for key, value in key_value:
        delta_data[key] = value.strip()

    # Skip delta files without RiftTable. In this case, it was also observed
    # that machineType doesn't have the correct value.
    if delta_data['Code'] != 'Raw' and delta_data['RiftTable'] == '(none)':
        assert any(fnmatch.fnmatch(name.lower(), p) for p in config.delta_data_without_rift_table_names), name
        assert int(delta_data['TimeStamp']) == 0
        return None

    result = {}

    result['size'] = int(delta_data['TargetSize'])

    if delta_data['HashAlgorithm'] == 'CALG_MD5':
        result['md5'] = delta_data['Hash'].lower()
    elif delta_data['HashAlgorithm'] == 'CALG_SHA_256':
        result['sha256'] = delta_data['Hash'].lower()
    else:
        assert False, delta_data['HashAlgorithm']

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


def get_file_data_for_manifest_file(manifest_path: Path, name: str, algorithm_to_assert: str, hash_to_assert: str):
    file_path = manifest_path.parent.joinpath(manifest_path.stem, 'n', name)
    if not file_path.exists():
        file_path = manifest_path.parent.joinpath(manifest_path.stem, name)
        if not file_path.exists():
            return None

    size = file_path.stat().st_size
    md5, sha1, sha256 = hash_sum(file_path)

    if algorithm_to_assert == 'md5':
        assert md5 == hash_to_assert
    elif algorithm_to_assert == 'sha1':
        assert sha1 == hash_to_assert
    elif algorithm_to_assert == 'sha256':
        assert sha256 == hash_to_assert
    else:
        assert False

    result = {
        'size': size,
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
    }

    is_pe_file = False

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
                        is_pe_file = True

                        word = handle.read(2)
                        result['machineType'] = unpack('<H', word)[0]

                        handle.seek(offset + 8)
                        dword = handle.read(4)
                        result['timestamp'] = unpack('<I', dword)[0]

                        handle.seek(offset + 0x50)
                        dword = handle.read(4)
                        result['virtualSize'] = unpack('<I', dword)[0]

    if is_pe_file:
        version_info = get_file_version_info(file_path, ['FileVersion', 'FileDescription'])

        if version_info.get('FileVersion'):
            result['version'] = version_info['FileVersion']

        if version_info.get('FileDescription'):
            result['description'] = version_info['FileDescription']

        try:
            signing_times = get_file_signing_times(file_path)
            result['signingStatus'] = 'Unknown'  # Verification is too time consuming.
            result['signatureType'] = 'Overlay'
            result['signingDate'] = signing_times
        except signify.exceptions.SignedPEParseError as e:
            if str(e) != 'The PE file does not contain a certificate table.':
                raise
            result['signingStatus'] = 'Unsigned'

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

    file_info = get_file_data_for_manifest_file(manifest_path, file_el.attrib['name'], algorithm, hash)
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
            is_pe_file = hash not in config.file_hashes_non_pe
            if (is_pe_file and
                file_info and
                info_source in ['pe', 'delta'] and
                file_info.keys() in [{'size', 'md5'}, {'size', 'md5', 'sha1', 'sha256'}]):
                if config.allow_unknown_non_pe_files:
                    is_pe_file = False
                else:
                    raise Exception(f'Unknown non-pe file {filename} with hash {hash}')

            if not is_pe_file:
                if file_info:
                    assert info_source in ['pe', 'delta'] and file_info.keys() in [{'size', 'md5'}, {'size', 'md5', 'sha1', 'sha256'}]
                else:
                    assert info_source == 'none'
                assert hash not in file_hashes.get(filename, {})
                print(f'Skipping non-pe file {filename} with hash {hash}')
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
