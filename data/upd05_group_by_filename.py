from isal import igzip as gzip
from datetime import datetime
from pathlib import Path
import itertools
import bisect
import orjson
import json
import re

import config

file_info_data = {}


def write_to_gzip_file(file, data):
    with open(file, 'wb') as fd:
        with gzip.GzipFile(fileobj=fd, mode='w', compresslevel=config.compression_level, filename='', mtime=0) as gz:
            gz.write(data)


def write_all_file_info():
    output_dir = config.out_path.joinpath('by_filename_compressed')

    for filename in file_info_data:
        data = file_info_data[filename]

        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))

    file_info_data.clear()

    all_filenames = sorted(path.with_suffix('').stem for path in output_dir.glob('*.json.gz'))

    with open(config.out_path.joinpath('filenames.json'), 'w') as f:
        json.dump(all_filenames, f, indent=0, sort_keys=True)


def get_file_info_type(file_info):
    if file_info.keys() == {
        'size',
        'md5',
    }:
        return 'raw'

    if file_info.keys() == {
        'size',
        'md5',
        'machineType',
        'timestamp',
        'lastSectionVirtualAddress',
        'lastSectionPointerToRawData',
    }:
        return 'delta'

    if file_info.keys() == {
        'size',
        'md5',
        'machineType',
        'timestamp',
        'lastSectionVirtualAddress',
        'lastSectionPointerToRawData',
        'virtualSize',
    }:
        return 'delta+'

    if file_info.keys() == {
        'size',
        'md5',
        'machineType',
        'timestamp',
        'virtualSize',
    }:
        return 'pe'

    assert 'lastSectionVirtualAddress' not in file_info
    assert 'lastSectionPointerToRawData' not in file_info
    return 'vt_or_file'


def assert_file_info_close_enough(file_info_1, file_info_2, multiple_sign_times=False):
    def canonical_file_info(file_info):
        if 'signingStatus' not in file_info or file_info['signingStatus'] == 'Unsigned':
            return file_info

        file_info = file_info.copy()

        # Nullify Catalog file based data since it depends on the computer the scan ran on.
        if file_info['signatureType'] == 'Catalog file':
            assert 'signingDate' not in file_info
            file_info['signingStatus'] = 'Unsigned'
            del file_info['signatureType']
            return file_info

        # There might be several dates, choose one.
        if 'signingDate' in file_info:
            dates = file_info['signingDate']

            # Assert that all signatures represent the same time,
            # unless the file is known to be signed several times at different times.
            if not multiple_sign_times:
                datetime1 = datetime.fromisoformat(dates[0])
                for date in dates[1:]:
                    datetime2 = datetime.fromisoformat(date)
                    difference = datetime1 - datetime2
                    minutes = abs(difference.total_seconds()) / 60
                    assert minutes <= 10

            file_info['signingDate'] = dates[0]
            return file_info

        # If the signature is invalid (but exists), VirusTotal doesn't return dates, but we do.
        if file_info['signingStatus'] != 'Signed':
            file_info['signingDate'] = '???'

        return file_info

    # Must be equal for all information sources.
    assert file_info_1['size'] == file_info_2['size']

    # Non-PE file.
    if 'machineType' not in file_info_1:
        non_pe_keys = {
            'md5',
            'sha1',
            'sha256',
            'size',
        }
        assert file_info_1.keys() <= non_pe_keys
        assert file_info_2.keys() <= non_pe_keys
        for key in file_info_1.keys() & file_info_2.keys():
            assert file_info_1[key] == file_info_2[key]
        return

    # Must be equal for all information sources.
    assert file_info_1['machineType'] == file_info_2['machineType']
    assert file_info_1['timestamp'] == file_info_2['timestamp']

    delta_or_pe_types = ['delta', 'delta+', 'pe']
    if get_file_info_type(file_info_1) in delta_or_pe_types or get_file_info_type(file_info_2) in delta_or_pe_types:
        for key in file_info_1.keys() & file_info_2.keys():
            assert file_info_1[key] == file_info_2[key]
        return

    file_info_1 = canonical_file_info(file_info_1)
    file_info_2 = canonical_file_info(file_info_2)

    assert file_info_1.keys() == file_info_2.keys()

    for key in file_info_1.keys() - {'signingDate'}:
        assert file_info_1[key] == file_info_2[key]

    if 'signingDate' in file_info_1 and file_info_1['signingDate'] != '???' and file_info_2['signingDate'] != '???':
        datetime1 = datetime.fromisoformat(file_info_1['signingDate'])
        datetime2 = datetime.fromisoformat(file_info_2['signingDate'])
        difference = datetime1 - datetime2
        hours = abs(difference.total_seconds()) / 3600

        # VirusTotal returns the time in a local, unknown timezone.
        # "the maximum difference could be over 30 hours", https://stackoverflow.com/a/8131056
        assert hours <= 32, f'{hours} {file_info_1["sha256"]}'


def update_file_info(existing_file_info, delta_or_pe_file_info, virustotal_file_info, real_file_info, multiple_sign_times=False):
    file_infos = [existing_file_info, delta_or_pe_file_info, virustotal_file_info, real_file_info]
    file_infos = [x for x in file_infos if x is not None]

    for file_info_1, file_info_2 in itertools.combinations(file_infos, 2):
        assert_file_info_close_enough(file_info_1, file_info_2, multiple_sign_times)

    new_file_info = None
    new_file_info_type = None

    if real_file_info:
        new_file_info = real_file_info
        new_file_info_type = 'file'
    elif virustotal_file_info:
        new_file_info = virustotal_file_info
        new_file_info_type = 'vt'
    elif delta_or_pe_file_info:
        new_file_info = delta_or_pe_file_info
        new_file_info_type = get_file_info_type(delta_or_pe_file_info)
        assert new_file_info_type in ['raw', 'delta', 'delta+', 'pe']

    if not new_file_info:
        return existing_file_info

    if not existing_file_info:
        return new_file_info

    existing_file_info_type = get_file_info_type(existing_file_info)

    sources = [
        'raw',
        'delta',
        'delta+',
        'pe',
        'vt',
        'vt_or_file',
        'file',
    ]

    if sources.index(new_file_info_type) > sources.index(existing_file_info_type):
        return new_file_info

    return existing_file_info


def add_file_info_from_update(filename, output_dir, *,
                              file_hash,
                              virustotal_file_info,
                              windows_version,
                              update_kb,
                              update_info,
                              manifest_name,
                              assembly_identity,
                              attributes,
                              delta_or_pe_file_info):
    data = None
    data_file = None
    json_data_file_before = None
    json_data_file_after = None

    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rb') as f:
                json_data = f.read()

            # Try an optimization - operate only on the relevant part of the json.
            match = None
            if not config.high_mem_usage_for_performance:
                match = re.search(rb'"' + file_hash.encode() + rb'":({.*?})(?:,"[0-9a-f]{64}":{|}$)', json_data)

            if match:
                data_file = orjson.loads(match.group(1))
                json_data_file_before = json_data[:match.start(1)]
                json_data_file_after = json_data[match.end(1):]
            else:
                data = orjson.loads(json_data)
        else:
            data = {}

    if data_file is not None:
        assert data is None
        x = data_file
    else:
        x = data.setdefault(file_hash, {})

    updated_file_info = update_file_info(x.get('fileInfo'), delta_or_pe_file_info, virustotal_file_info, None)
    if updated_file_info:
        x['fileInfo'] = updated_file_info

    x = x.setdefault('windowsVersions', {})
    x = x.setdefault(windows_version, {})
    x = x.setdefault(update_kb, {})

    if 'updateInfo' not in x:
        x['updateInfo'] = update_info
    else:
        assert x['updateInfo'] == update_info

    x = x.setdefault('assemblies', {})
    x = x.setdefault(manifest_name, {})

    if 'assemblyIdentity' not in x:
        x['assemblyIdentity'] = assembly_identity
    else:
        assert x['assemblyIdentity'] == assembly_identity

    x = x.setdefault('attributes', [])

    if attributes not in x:
        x.append(attributes)

    if config.high_mem_usage_for_performance:
        assert data is not None
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')

        if data_file is not None:
            json_data = json_data_file_before + orjson.dumps(data_file) + json_data_file_after
        else:
            json_data = orjson.dumps(data)

        write_to_gzip_file(output_path, json_data)


virustotal_info_cache = {}


def get_virustotal_info(file_hash):
    # https://stackoverflow.com/a/57027610
    def is_power_of_two(n):
        return (n != 0) and (n & (n-1) == 0)

    def align_by(n, alignment):
        return ((n + alignment - 1) // alignment) * alignment

    if config.high_mem_usage_for_performance and file_hash in virustotal_info_cache:
        return virustotal_info_cache[file_hash]

    filename = config.out_path.joinpath('virustotal', file_hash + '.json')
    if not filename.is_file():
        if config.high_mem_usage_for_performance:
            virustotal_info_cache[file_hash] = None
        return None

    with open(filename) as f:
        data = json.load(f)

    attr = data['data']['attributes']

    first_section = attr['pe_info']['sections'][0]

    # Handle special cases.
    if attr.get('signature_info', {}).get('description') == 'TCB Launcher':
        assert first_section['virtual_address'] in [0x3000, 0x4000]
        section_alignment = 0x1000
    elif file_hash == 'ede86c8d8c6b9256b926701f4762bd6f71e487f366dfc7db8d74b8af57e79bbb':  # ftdibus.sys
        assert first_section['virtual_address'] == 0x380
        section_alignment = 0x80
    elif file_hash == '5bec55192eaef43b0fade13bbadfdf77eb0d45b4b281ae19d4b0b7a0c2350836':  # onnxruntime.dll
        assert first_section['virtual_address'] == 0x2d0
        section_alignment = 0x10
    elif file_hash == '09ced31cad8547a9ee5dcf739565def2f4359075e56a7b699cc85971e0905864':  # onnxruntime.dll
        assert first_section['virtual_address'] == 0x310
        section_alignment = 0x10
    else:
        section_alignment = first_section['virtual_address']
        assert is_power_of_two(section_alignment), file_hash

    virtual_size = first_section['virtual_address']
    for section in attr['pe_info']['sections']:
        assert virtual_size == section['virtual_address'], file_hash
        virtual_size += align_by(section['virtual_size'], section_alignment)

    if 'timestamp' in attr['pe_info']:
        timestamp = attr['pe_info']['timestamp']
    else:
        # Zero timestamp.
        assert file_hash in [
            '18dd945c04ce0fbe882cd3f234c2da2d0faa12b23bd6df7b1edc31faecf51c69',  # brlapi-0.8.dll
            '7a9113d00a274c075c58b22a3ebacf1754e7da7cfb4d3334b90367b602158d78',  # brltty.exe
        ], file_hash
        timestamp = 0

    info = {
        'size': attr['size'],
        'md5': attr['md5'],
        'sha1': attr['sha1'],
        'sha256': attr['sha256'],
        'machineType': attr['pe_info']['machine_type'],
        'timestamp': timestamp,
        'virtualSize': virtual_size,
    }

    has_signature_overlay = False
    if 'overlay' in attr['pe_info']:
        overlay_size = attr['pe_info']['overlay']['size']
        if overlay_size < 0x20:
            # Small non-signature overlay.
            assert file_hash in [
                '11efef27aea856060bdeb6d2f0d62c68088eb891997d4e99de708a6b51743148',  # brlapi-0.6.dll
                'b175123eff88d1573f451b286cd5370003a0839e53c7ae86bf22b35b7e77bad3',  # brlapi-0.6.dll
                '18dd945c04ce0fbe882cd3f234c2da2d0faa12b23bd6df7b1edc31faecf51c69',  # brlapi-0.8.dll
                '3eaa62334520b41355c5103dcd663744ba26caae3496bd9015bc399fbaf42fce',  # brltty.exe
                '69f83db2fda7545ab0a1c60056aee472bf3c70a0af7454c51e1cd449b5c7f43b',  # brltty.exe
                '7a9113d00a274c075c58b22a3ebacf1754e7da7cfb4d3334b90367b602158d78',  # brltty.exe
                'b4cc93cf4d7c2906c1929c079cd98ef00c7a33832e132ac57adde71857082e36',  # libgcc_s_dw2-1.dll
            ], file_hash
        else:
            unsigned_with_overlay = [
                'cf54a8504f2dbdd7bea3acdcd065608d21f5c06924baf647955cc28b8637ae68',  # libiconv-2.dll
                'ee1df918ca67581f21eac49ae4baffca959f71d1a0676d7c35bc5fb96bea3a48',  # libiconv-2.dll
                '9eec7e5188d1a224325281e4d0e6e1d5f9f034f02bd1fadeb792d3612c72319e',  # libpdcurses.dll
                'f9b385e19b9d57a1d1831e744ed2d1c3bb8396d28f48d10120cecfe72595b222',  # libpdcursesu.dll
                '787d5c07ab0bb782dede7564840e86c468e3728e81266dae23eb8ad614bcee95',  # libpdcursesw.dll
            ]
            if file_hash not in unsigned_with_overlay:
                has_signature_overlay = True

    info['signingStatus'] = 'Unsigned'
    file_signed = False

    if 'signature_info' in attr:
        signature_info = attr['signature_info']

        if 'file version' in signature_info:
            info['version'] = signature_info['file version']

        if 'description' in signature_info:
            info['description'] = signature_info['description']

        signing_date_reliable = False
        if 'verified' in signature_info:
            info['signingStatus'] = signature_info['verified']
            info['signatureType'] = 'Overlay' if has_signature_overlay else 'Catalog file'
            file_signed = True

            # If the value is something else, the "signing date" is often the analysis (file modified?) date.
            if signature_info['verified'] == 'Signed':
                signing_date_reliable = True

        if has_signature_overlay and 'signing date' in signature_info and signing_date_reliable:
            spaces = signature_info['signing date'].count(' ')
            if spaces == 1:
                # Examples:
                # 9:51 09/05/2020
                # 13:18 21/02/2020
                date_format = '%H:%M %d/%m/%Y'
            else:
                assert spaces == 2, file_hash
                # Examples:
                # 8:30 AM 2/7/2020
                # 5:47 PM 9/19/2019
                date_format = '%I:%M %p %m/%d/%Y'

            datetime_object = datetime.strptime(signature_info['signing date'], date_format)
            info['signingDate'] = [datetime_object.isoformat()]

    assert not has_signature_overlay or file_signed, file_hash

    if config.high_mem_usage_for_performance:
        virustotal_info_cache[file_hash] = info
    else:
        virustotal_info_cache[file_hash] = True

    return info


def group_update_assembly_by_filename(input_filename, output_dir, *, windows_version, update_kb, update_info, manifest_name):
    with open(input_filename) as f:
        data = json.load(f)

    assembly_identity = data['assemblyIdentity']

    for file_item in data['files']:
        filename = file_item['attributes']['name'].split('\\')[-1].lower()

        hash_is_sha256 = 'sha256' in file_item
        if hash_is_sha256:
            file_hash = file_item['sha256']
        else:
            file_hash = file_item['sha1']

        virustotal_info = get_virustotal_info(file_hash)
        if virustotal_info and file_hash != virustotal_info['sha256']:
            assert file_hash == virustotal_info['sha1']
            file_hash = virustotal_info['sha256']
            hash_is_sha256 = True

        if not hash_is_sha256:
            raise Exception('No SHA256 hash')

        # Temporary workaround for what seems to be an incorrect SHA256 hash in
        # KB5017389 and newer Windows 11 22H2 update manifests for some of the
        # files. The files are language resource files (e.g.
        # resources.en-GB.pri) for some esoteric apps:
        # * holocamera_cw5n1h2txyewy
        # * MixedRealityLearning_cw5n1h2txyewy
        # * RoomAdjustment_cw5n1h2txyewy
        file_hash_md5 = file_item.get('fileInfo', {}).get('md5')
        if windows_version == '11-22H2' and (file_hash, file_hash_md5) in [
            ('f8636d2d93606b0069117cb05bc8d91ecb9a09e72e14695d56a693adf419f4e8', '70db27fdd0fd76305fb1dfcd401e8cde'),
            ('5ca0a43e4be5f7b60cd2170b05eb4627407729c65e7e0b62ed4ef3cdf895f5c5', '6ad932076c6a059db6e9743ae06c62cf'),
            ('b5a73db6c73c788dd62a1e5c0aa7bc2f50a260d52b04fcec4cd0192a25c6658f', 'af8a7f7b812a40bf8a1c151d3f09a98c'),
            ('d52440f126d95e94a86465e78849a72df11f0c22115e5b8cda10174d69167a44', 'afbb5df39d32d142a4cca08f89bbbe8e'),
            ('5a3b750a6dcc984084422d5c28ac99a2f878fdfe26c7261c9bff8de77658e8f8', '7ed0e64f81f63730983913be5b3cce17'),
            ('5292013c895e0f412c98766ba4ed7ba5ecb24bebf00aac5b56c71bcf44891945', '886ee85f216e28ac547fe71ff2823fc4'),
            ('b9297098632fbb1a513f96d6d2462926144d6528c4cc426d6caed5ed234438f0', '19aabb40b6431f411f97c85fbe77d7fe'),
            ('700760afebec6b3d638adac2f1cbb96cb60fbe9a2e2558eb20a63f9ebbd2c74f', '1f91bbe1b8ec8c42f00ffc73cbb72247'),
            ('994274f4494a852c0fe8c968d054fbaf0f6f7489ea586fc84102c6ebcafeeca3', 'a0d4e4256e8d54ab86ac6505f1272219'),
        ]:
            print(f'WARNING: Skipping file with (probably) an incorrect SHA256 hash: {file_hash}')
            print(f'         MD5 hash: {file_hash_md5}')
            print(f'         Manifest name: {manifest_name}')
            continue

        add_file_info_from_update(filename, output_dir,
            file_hash=file_hash,
            virustotal_file_info=virustotal_info,
            windows_version=windows_version,
            update_kb=update_kb,
            update_info=update_info,
            manifest_name=manifest_name,
            assembly_identity=assembly_identity,
            attributes=file_item['attributes'],
            delta_or_pe_file_info=file_item.get('fileInfo'))


def group_update_by_filename(windows_version, update_kb, update, parsed_dir, progress_state=None, time_to_stop=None):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = sorted(parsed_dir.glob('*.json'))  # for reproducible order
    count_total = len(paths)

    if progress_state:
        assert progress_state['update_kb'] == update_kb

        count = progress_state['files_processed']

        if progress_state['files_total'] is None:
            progress_state['files_total'] = count_total
        else:
            assert progress_state['files_total'] == count_total

        paths = paths[count:]
    else:
        count = 0

    for path in paths:
        if time_to_stop and datetime.now() >= time_to_stop:
            break

        if path.is_file():
            try:
                group_update_assembly_by_filename(path, output_dir,
                    windows_version=windows_version,
                    update_kb=update_kb,
                    update_info=update,
                    manifest_name=path.stem)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                print(f'ERROR: failed to process {path}')
                print(f'       {e}')
                if config.exit_on_first_error:
                    raise

        count += 1
        if count % 200 == 0 and config.verbose_progress:
            print(f'Processed {count} of {count_total}')

    if progress_state:
        progress_state['files_processed'] = count


def process_updates(progress_state=None, time_to_stop=None):
    updates_path = config.out_path.joinpath('updates.json')
    if updates_path.is_file():
        with open(updates_path) as f:
            updates = json.load(f)
    else:
        updates = {}

    for windows_version in updates:
        print(f'Processing Windows version {windows_version}:')

        for update_kb in updates[windows_version]:
            update = updates[windows_version][update_kb]

            parsed_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
            if parsed_dir.is_dir():
                group_update_by_filename(windows_version, update_kb, update, parsed_dir, progress_state, time_to_stop)
                print('  ' + update_kb)

    if progress_state and progress_state['files_total'] is None:
        progress_state['files_total'] = 0


def add_file_info_from_virustotal_data(filename, output_dir, *, file_hash, file_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rb') as f:
                data = orjson.loads(f.read())
        else:
            data = {}

    x = data[file_hash]

    updated_file_info = update_file_info(x.get('fileInfo'), None, file_info, None)
    assert updated_file_info
    x['fileInfo'] = updated_file_info

    if config.high_mem_usage_for_performance:
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))


def process_virustotal_data():
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    info_progress_virustotal_path = config.out_path.joinpath('info_progress_virustotal.json')
    if info_progress_virustotal_path.is_file():
        with open(info_progress_virustotal_path, 'r') as f:
            info_progress_virustotal = json.load(f)
    else:
        info_progress_virustotal = {}

    pending = info_progress_virustotal.get('pending', {})

    for name in pending:
        for file_hash in pending[name]:
            if file_hash in virustotal_info_cache:
                # Was already added with one of the updates.
                continue

            virustotal_info = get_virustotal_info(file_hash)
            if file_hash != virustotal_info['sha256']:
                assert file_hash == virustotal_info['sha1']
                file_hash = virustotal_info['sha256']

            add_file_info_from_virustotal_data(name, output_dir,
                file_hash=file_hash,
                file_info=virustotal_info)

    info_progress_virustotal['pending'] = {}

    with open(info_progress_virustotal_path, 'w') as f:
        json.dump(info_progress_virustotal, f, indent=0, sort_keys=True)

    virustotal_info_cache.clear()


def add_file_info_from_iso_data(filename, output_dir, *, file_hash, file_info, source_path, windows_version, windows_version_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {}

    x = data.setdefault(file_hash, {})

    # Many files distributed with Edge are for some reason signed twice.
    multiple_sign_times = (
        source_path.startswith('Program Files (x86)\\Microsoft\\Edge\\Application\\') or
        source_path.startswith('Program Files (x86)\\Microsoft\\EdgeCore\\') or
        source_path.startswith('Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\')
    )
    updated_file_info = update_file_info(x.get('fileInfo'), None, None, file_info, multiple_sign_times)
    assert updated_file_info
    x['fileInfo'] = updated_file_info

    x = x.setdefault('windowsVersions', {})
    x = x.setdefault(windows_version, {})
    x = x.setdefault('BASE', {})

    if 'windowsVersionInfo' not in x:
        x['windowsVersionInfo'] = windows_version_info
    else:
        assert x['windowsVersionInfo'] == windows_version_info

    x = x.setdefault('sourcePaths', [])

    if source_path not in x:
        bisect.insort(x, source_path)

    file_info_data[filename] = data


def group_iso_data_by_filename(iso_data_file):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(iso_data_file) as f:
        iso_data = json.load(f)

    windows_version = iso_data['windowsVersion']
    iso_hash = iso_data['windowsIsoSha256']
    windows_release_date = iso_data['windowsReleaseDate']

    windows_version_info = {
        'releaseDate': windows_release_date,
        'isoSha256': iso_hash,
    }

    for file_item in iso_data['files']:
        filename = file_item['path'].split('\\')[-1].lower()

        source_path = file_item.pop('path')

        add_file_info_from_iso_data(filename, output_dir,
            file_hash=file_item['sha256'],
            file_info=file_item,
            source_path=source_path,
            windows_version=windows_version,
            windows_version_info=windows_version_info)


def process_iso_files():
    from_iso_dir = config.out_path.joinpath('from_iso')

    for iso_data_file in from_iso_dir.glob('*.json'):
        if iso_data_file.is_file():
            print('  ' + iso_data_file.stem)
            group_iso_data_by_filename(iso_data_file)


def main(progress_state=None, time_to_stop=None):
    print('Processing data from updates')
    process_updates(progress_state, time_to_stop)

    print('Processing data from VirusTotal')
    process_virustotal_data()

    print('Processing data from ISO files')
    process_iso_files()

    write_all_file_info()


if __name__ == '__main__':
    main()
