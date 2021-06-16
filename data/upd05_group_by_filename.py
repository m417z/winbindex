from datetime import datetime
from pathlib import Path
import bisect
import orjson
import gzip
import json

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

def assert_fileinfo_close_enough(file_info_1, file_info_2, multiple_sign_times=False):
    def canonical_fileinfo(file_info):
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

    file_info_1 = canonical_fileinfo(file_info_1)
    file_info_2 = canonical_fileinfo(file_info_2)

    assert file_info_1.keys() == file_info_2.keys()

    for key in file_info_1.keys() - {'signingDate'}:
        assert file_info_1[key] == file_info_2[key]

    if 'signingDate' in file_info_1 and file_info_1['signingDate'] != '???' and file_info_2['signingDate'] != '???':
        datetime1 = datetime.fromisoformat(file_info_1['signingDate'])
        datetime2 = datetime.fromisoformat(file_info_2['signingDate'])
        difference = datetime1 - datetime2
        hours = abs(difference.total_seconds()) / 3600

        # VirusTotal returns the time in a local, unknown timestamp.
        # "the maximum difference could be over 30 hours", https://stackoverflow.com/a/8131056
        assert hours <= 32, f'{hours} {file_info_1["sha256"]}'

def add_file_info_from_update(filename, output_dir, *, file_hash, file_info, windows_version, update_kb, update_info, manifest_name, assembly_identity, attributes):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'r') as f:
                data = orjson.loads(f.read())
        else:
            data = {}

    x = data.setdefault(file_hash, {})

    if file_info:
        if 'fileInfo' not in x:
            x['fileInfo'] = file_info
        else:
            assert_fileinfo_close_enough(x['fileInfo'], file_info)

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
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))

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
    section_alignment = first_section['virtual_address']

    # Handle special cases.
    if not is_power_of_two(section_alignment):
        if section_alignment == 0x3000:
            assert attr['signature_info']['description'] == 'TCB Launcher', file_hash
            section_alignment = 0x1000
        elif section_alignment == 0x380:
            assert file_hash == 'ede86c8d8c6b9256b926701f4762bd6f71e487f366dfc7db8d74b8af57e79bbb', file_hash  # ftdibus.sys
            section_alignment = 0x80
        else:
            assert False, file_hash

    virtual_size = first_section['virtual_address']
    for section in attr['pe_info']['sections']:
        assert virtual_size == section['virtual_address'], file_hash
        virtual_size += align_by(section['virtual_size'], section_alignment)

    info = {
        'size': attr['size'],
        'md5': attr['md5'],
        'sha1': attr['sha1'],
        'sha256': attr['sha256'],
        'machineType': attr['pe_info']['machine_type'],
        'timestamp': attr['pe_info']['timestamp'],
        'virtualSize': virtual_size,
    }

    has_signature_overlay = False
    if 'overlay' in attr['pe_info']:
        overlay_size = attr['pe_info']['overlay']['size']
        if overlay_size < 0x20:
            # Small non-signature overlay.
            assert file_hash in [
                '11efef27aea856060bdeb6d2f0d62c68088eb891997d4e99de708a6b51743148',  # brlapi-0.6.dll
                '3eaa62334520b41355c5103dcd663744ba26caae3496bd9015bc399fbaf42fce',  # brltty.exe
                'b4cc93cf4d7c2906c1929c079cd98ef00c7a33832e132ac57adde71857082e36',  # libgcc_s_dw2-1.dll
            ], file_hash
        else:
            unsigned_with_overlay = [
                'cf54a8504f2dbdd7bea3acdcd065608d21f5c06924baf647955cc28b8637ae68',  # libiconv-2.dll
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

        add_file_info_from_update(filename, output_dir,
            file_hash=file_hash,
            file_info=virustotal_info,
            windows_version=windows_version,
            update_kb=update_kb,
            update_info=update_info,
            manifest_name=manifest_name,
            assembly_identity=assembly_identity,
            attributes=file_item['attributes'])

def group_update_by_filename(windows_version, update_kb, update, parsed_dir, progress_state=None, time_to_stop=None):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = parsed_dir.glob('*.json')

    if progress_state:
        assert progress_state['update_kb'] == update_kb

        count = progress_state['files_processed']
        paths = sorted(paths)  # for reproducible order

        if progress_state['files_total'] is None:
            progress_state['files_total'] = len(paths)
        else:
            assert progress_state['files_total'] == len(paths)

        paths = paths[count:]
    else:
        count = 0

    for path in paths:
        if not path.is_file():
            continue

        count += 1
        if count % 200 == 0 and config.verbose_progress:
            print(f' ...{count}', end='', flush=True)

        if time_to_stop and datetime.now() >= time_to_stop:
            break

        try:
            group_update_assembly_by_filename(str(path), output_dir,
                windows_version=windows_version,
                update_kb=update_kb,
                update_info=update,
                manifest_name=path.stem)
        except Exception as e:
            print(f'ERROR: failed to process {path}')
            print('    ' + str(e))
            if config.exit_on_first_error:
                raise

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
        print(f'Processing Windows version {windows_version}:', end='', flush=True)

        for update_kb in updates[windows_version]:
            update = updates[windows_version][update_kb]

            parsed_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
            if parsed_dir.is_dir():
                group_update_by_filename(windows_version, update_kb, update, parsed_dir, progress_state, time_to_stop)
                print(' ' + update_kb, end='', flush=True)

        print()

def add_file_info_from_virustotal_data(filename, output_dir, *, file_hash, file_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'r') as f:
                data = orjson.loads(f.read())
        else:
            data = {}

    x = data[file_hash]

    if file_info:
        if 'fileInfo' not in x:
            x['fileInfo'] = file_info
        else:
            assert_fileinfo_close_enough(x['fileInfo'], file_info)
            return

    if config.high_mem_usage_for_performance:
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))

def process_virustotal_data():
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    for name in info_sources:
        for file_hash in info_sources[name]:
            if info_sources[name][file_hash] != 'newvt':
                continue

            info_sources[name][file_hash] = 'vt'

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

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f)

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

    if file_info:
        if 'fileInfo' not in x:
            x['fileInfo'] = file_info
        else:
            # Many files distributed with Edge are for some reason signed twice.
            multiple_sign_times = source_path.startswith('Program Files (x86)\\Microsoft\\Edge\\Application\\')
            assert_fileinfo_close_enough(x['fileInfo'], file_info, multiple_sign_times)
            x['fileInfo'] = file_info  # this one is more accurate

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
            print(' ' + iso_data_file.stem, end='', flush=True)
            group_iso_data_by_filename(iso_data_file)

    print()

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
