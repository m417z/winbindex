from datetime import datetime
from pathlib import Path
import bisect
import ujson
import gzip

import config

file_info_data = {}

def write_all_file_info():
    index_filename = config.out_path.joinpath('index.json')
    filenames_filename = config.out_path.joinpath('filenames.json')
    output_dir = config.out_path.joinpath('by_filename_compressed')

    if index_filename.is_file():
        with open(index_filename, 'r') as f:
            index_data = ujson.load(f)

        all_filenames = set(index_data['filenames'])
        sha256_to_filename = index_data['sha256ToFilename']
    else:
        all_filenames = set()
        sha256_to_filename = {}

    for filename in file_info_data:
        data = file_info_data[filename]

        all_filenames.add(filename)

        if not filename.endswith('.mui'):
            for sha256 in data:
                is_pe_file = 'fileInfo' in data[sha256] and 'machineType' in data[sha256]['fileInfo']
                if is_pe_file:
                    if sha256 not in sha256_to_filename:
                        sha256_to_filename[sha256] = filename
                    elif sha256_to_filename[sha256] != filename:
                        old = sha256_to_filename[sha256]
                        new = filename
                        if ((old.endswith('.tmp') and not new.endswith('.tmp')) or
                            len(new) < len(old) or
                            (len(new) == len(old) and new < old)):
                            sha256_to_filename[sha256] = filename

        output_path = output_dir.joinpath(filename + '.json.gz')
        with gzip.open(output_path, 'wt', encoding='utf-8') as f:
            ujson.dump(data, f, indent=4, sort_keys=True)

    all_filenames = sorted(list(all_filenames))

    index_data = {
        'filenames': all_filenames,
        'sha256ToFilename': sha256_to_filename,
    }

    with open(index_filename, 'w') as f:
        ujson.dump(index_data, f, indent=4, sort_keys=True)

    with open(filenames_filename, 'w') as f:
        ujson.dump(all_filenames, f, indent=4, sort_keys=True)

def assert_fileinfo_close_enough(file_info_1, file_info_2):
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
        assert hours <= 32

def add_file_info_from_update(filename, output_dir, *, file_hash, file_info, windows_version, update_kb, update_info, manifest_name, assembly_identity, attributes):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rt', encoding='utf-8') as f:
                data = ujson.load(f)
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
        with gzip.open(output_path, 'wt', compresslevel=6, encoding='utf-8') as f:
            ujson.dump(data, f, indent=4, sort_keys=True)

virustotal_info_cache = {}

def get_virustotal_info(file_hash):
    # https://stackoverflow.com/a/57027610
    def is_power_of_two(n):
        return (n != 0) and (n & (n-1) == 0)

    def align_by(n, alignment):
        return ((n + alignment - 1) // alignment) * alignment

    if file_hash in virustotal_info_cache:
        return virustotal_info_cache[file_hash]

    filename = config.out_path.joinpath('virustotal', file_hash + '.json')
    if not filename.is_file():
        if config.high_mem_usage_for_performance:
            virustotal_info_cache[file_hash] = None
        return None

    with open(filename) as f:
        data = ujson.load(f)

    attr = data['data']['attributes']

    first_section = attr['pe_info']['sections'][0]
    section_alignment = first_section['virtual_address']

    # Handle special cases.
    if not is_power_of_two(section_alignment):
        if section_alignment == 0x3000:
            assert attr['signature_info']['description'] == 'TCB Launcher'
            section_alignment = 0x1000
        elif section_alignment == 0x380:
            assert file_hash == 'ede86c8d8c6b9256b926701f4762bd6f71e487f366dfc7db8d74b8af57e79bbb'  # ftdibus.sys
            section_alignment = 0x80
        else:
            assert False

    virtual_size = first_section['virtual_address']
    for section in attr['pe_info']['sections']:
        assert virtual_size == section['virtual_address']
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
            ]
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
    file_verified = False

    if 'signature_info' in attr:
        signature_info = attr['signature_info']
        if 'file version' in signature_info:
            info['version'] = signature_info['file version']
        if 'description' in signature_info:
            info['description'] = signature_info['description']
        if 'verified' in signature_info:
            info['signingStatus'] = signature_info['verified']
            info['signatureType'] = 'Overlay' if has_signature_overlay else 'Catalog file'
            file_verified = True
        if has_signature_overlay and 'signing date' in signature_info:
            spaces = signature_info['signing date'].count(' ')
            if spaces == 1:
                # Examples:
                # 9:51 09/05/2020
                # 13:18 21/02/2020
                date_format = '%H:%M %d/%m/%Y'
            else:
                assert spaces == 2
                # Examples:
                # 8:30 AM 2/7/2020
                # 5:47 PM 9/19/2019
                date_format = '%I:%M %p %m/%d/%Y'

            datetime_object = datetime.strptime(signature_info['signing date'], date_format)
            info['signingDate'] = [datetime_object.isoformat()]

    assert not has_signature_overlay or file_verified

    if config.high_mem_usage_for_performance:
        virustotal_info_cache[file_hash] = info

    return info

def group_update_assembly_by_filename(input_filename, output_dir, *, windows_version, update_kb, update_info, manifest_name):
    with open(input_filename) as f:
        data = ujson.load(f)

    assembly_identity = data['assemblyIdentity']

    for file_item in data['files']:
        filename = file_item['attributes']['name'].split('\\')[-1].lower()

        hashIsSha256 = 'sha256' in file_item
        if hashIsSha256:
            file_hash = file_item['sha256']
        else:
            file_hash = file_item['sha1']

        virustotal_info = get_virustotal_info(file_hash)
        if virustotal_info and file_hash != virustotal_info['sha256']:
            assert file_hash == virustotal_info['sha1']
            file_hash = virustotal_info['sha256']
            hashIsSha256 = True

        if not hashIsSha256:
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

def group_update_by_filename(windows_version, update_kb, update, parsed_dir):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for path in parsed_dir.glob('*.json'):
        if not path.is_file():
            continue

        if config.verbose_progress:
            count += 1
            if count % 200 == 0:
                print(f' ...{count}', end='', flush=True)
            if count == 1000:
            	exit('Aborted')

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

def add_file_info_from_iso_data(filename, output_dir, *, file_hash, file_info, source_path, windows_version, windows_version_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rt', encoding='utf-8') as f:
                data = ujson.load(f)
        else:
            data = {}

    x = data.setdefault(file_hash, {})

    if file_info:
        if 'fileInfo' not in x:
            x['fileInfo'] = file_info
        else:
            assert_fileinfo_close_enough(x['fileInfo'], file_info)
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

def group_iso_data_by_filename(windows_version, windows_release_date, iso_data_file):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(iso_data_file) as f:
        iso_data = ujson.load(f)

    assert windows_version == iso_data['windowsVersion']

    iso_hash = iso_data['windowsIsoSha256']

    windows_version_info = {
        'releaseDate': windows_release_date,
        'isoSha256': iso_hash,
    }

    excluded_paths = [
        r'Windows\WinSxS',
        r'Windows\System32\CatRoot',
        r'Windows\SysWOW64\CatRoot',
        r'Windows\servicing\Packages',
    ]
    excluded_paths = [x.lower() + '\\' for x in excluded_paths]

    for file_item in iso_data['files']:
        path_lowercase = file_item['path'].lower()
        if any(path_lowercase.startswith(excluded_path) for excluded_path in excluded_paths):
            continue

        filename = path_lowercase.split('\\')[-1]

        source_path = file_item.pop('path')

        add_file_info_from_iso_data(filename, output_dir,
            file_hash=file_item['sha256'],
            file_info=file_item,
            source_path=source_path,
            windows_version=windows_version,
            windows_version_info=windows_version_info)

def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = ujson.load(f)

    for windows_version in updates:
        if windows_version == '1909':
            continue  # same updates as 1903

        print(f'Processing Windows version {windows_version}:', end='', flush=True)

        for update in updates[windows_version]:
            update_kb = update['updateKb']

            parsed_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
            if parsed_dir.is_dir():
                group_update_by_filename(windows_version, update_kb, update, parsed_dir)
                print(' ' + update_kb, end='', flush=True)

        print()

    print('Processing data from ISO files')

    windows_versions_from_iso = {
        '2004': '2020-05-27',
        '1909': '2019-11-12',
        '1903': '2019-05-21',
        '1809': '2018-11-13',
        '1803': '2018-04-30',
        '1709': '2017-10-17',
        '1703': '2017-04-05',
        '1607': '2016-08-02',
        '1511': '2015-11-10',
        '1507': '2015-07-29',
    }

    for windows_version in windows_versions_from_iso:
        iso_data_file = config.out_path.joinpath('from_iso', windows_version + '.json')
        if iso_data_file.is_file():
            print(' ' + windows_version, end='', flush=True)
            group_iso_data_by_filename(windows_version, windows_versions_from_iso[windows_version], iso_data_file)

    print()

    write_all_file_info()

if __name__ == '__main__':
    main()
