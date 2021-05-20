from datetime import datetime
from struct import unpack
from pathlib import Path
import subprocess
import json
import sys
import re

import config

# To get data from an ISO file use the following commands:
#
# 7z.exe e C:\path\to\windows.iso sources\install.wim -oC:\path\to\output
# 7z.exe x C:\path\to\output\install.wim -r -oC:\path\to\output
# del C:\path\to\output\install.wim
#
# Then point this script at the resulting folder.
# Note: keep the path short, e.g. extract to:
# C:\w10
# In order to keep paths under MAX_PATH=260.
# Long paths are not supported by some of the tools (like sigcheck).

# Enable to use intermediate files created at the first run for further runs.
# Convenient for testing, but beware of files containing only partial data.
REUSE_OUTPUT_FILES = False

def sigcheck_folder(folder, output_file):
    if not REUSE_OUTPUT_FILES or not output_file.is_file():
        with open(output_file, 'w') as f:
            args = ['tools/sigcheck64_patched.exe', '-accepteula', '-nobanner', '-i', '-h', '-s', folder]
            subprocess.run(args, stdout=f, text=True, encoding='utf-16')

    with open(output_file, encoding='utf-16') as f:
        return f.read()

def prase_sigcheck(sigcheck_data, folder):
    folder_in_correct_case = sigcheck_data[:len(str(folder))]
    assert folder_in_correct_case.lower() == str(folder).lower(), f'{folder_in_correct_case}.lower() == {str(folder)}.lower()'

    sigcheck_data = sigcheck_data.split(f'\n{folder_in_correct_case}\\')
    assert sigcheck_data[0].startswith(folder_in_correct_case + '\\')
    sigcheck_data[0] = sigcheck_data[len(folder_in_correct_case + '\\'):]

    result = []
    for file_info in sigcheck_data[1:]:
        filename, rest_info = file_info.split('\n', 1)
        assert filename[-1] == ':'
        filename = filename[:-1]

        assert '?' not in filename, filename

        if '\\' not in filename:
            continue

        filename = Path(filename)
        assert filename.parts[0].isdigit()

        filename_absolute = folder.joinpath(filename)
        assert filename_absolute.is_file()

        item = {
            'FileNameRelative': str(filename.relative_to(filename.parts[0])),
            'FileName': str(filename_absolute),
        }
        signing_dates = []
        catalogs = []
        key_value = re.findall(r'^\t([\w ]+):\t(.*)$', rest_info, re.MULTILINE)
        for key, value in key_value:
            if key in [
                'Verified',
                'MD5',
                'SHA1',
                'SHA256',
            ]:
                assert key not in item
                assert value != 'n/a'
                item[key] = value
            elif key in [
                'Description',
                'File version',
                'MachineType',
            ]:
                assert key not in item
                if value != 'n/a':
                    item[key] = value
            elif key == 'Signing date':
                assert value != 'n/a'
                signing_dates.append(value)
            elif key == 'Catalog':
                assert value != 'n/a'
                catalogs.append(value)

        if len(signing_dates) == 1:
            assert signing_dates[0] == '0'
            assert len(catalogs) == 0
        elif item['Verified'] != 'Unsigned':
            assert len(signing_dates) >= 2 and signing_dates[0] == signing_dates[1], str(filename)
            signing_dates = signing_dates[1:]
            assert len(catalogs) == len(signing_dates)
            assert len(signing_dates) <= 4, key_value  # haven't seen more than that

            embedded_signing_dates = []
            for catalog, signing_date in zip(catalogs, signing_dates):
                if catalog.lower() == str(filename_absolute).lower():
                    embedded_signing_dates.append(int(signing_date))
                else:
                    assert catalog.lower().startswith('c:\\windows\\system32\\catroot\\')

            if len(embedded_signing_dates) > 0:
                item['Signing date'] = embedded_signing_dates
        else:
            assert item['Verified'] != 'An error occurred while reading or writing to a file.'
            assert len(signing_dates) == 0

        if 'MachineType' in item:
            if item['MachineType'] == '43620':
                item['MachineType'] = 'ARM64'
            else:
                assert item['MachineType'] in ['16-bit', '32-bit', '64-bit']

        result.append(item)

    return result

# https://gist.github.com/geudrik/03152ba1a148d9475e81
def get_pe_extra_data(filename):
    with open(filename, 'rb') as handle:
        # Get PE offset (@60, DWORD) from DOS header
        handle.seek(60, 0)
        offset = handle.read(4)
        offset = unpack('<I', offset)[0]

        handle.seek(offset + 4, 0)
        word = handle.read(2)
        machine = unpack('<H', word)[0]

        handle.seek(offset + 8, 0)
        dword = handle.read(4)
        timestamp = unpack('<I', dword)[0]

        handle.seek(offset + 0x50, 0)
        dword = handle.read(4)
        image_size = unpack('<I', dword)[0]

    return {
        'machine': machine,
        'timestamp': timestamp,
        'image_size': image_size,
    }

# https://gist.github.com/Mostafa-Hamdy-Elgiar/9714475f1b3bc224ea063af81566d873
def filetime_to_date(filetime):
    # http://support.microsoft.com/kb/167296
    # How To Convert a UNIX time_t to a Win32 FILETIME or SYSTEMTIME
    EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
    HUNDREDS_OF_NANOSECONDS = 10000000
    datetime_object = datetime.utcfromtimestamp((filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
    return datetime_object.isoformat()

# https://stackoverflow.com/a/1151705
class hashabledict(dict):
    def __hash__(self):
        return hash(tuple(sorted(self.items())))

def main(folder, windows_version, iso_sha256, release_date):
    sigcheck_file = folder.joinpath('sigcheck64.txt')
    pe_files_extra_data = folder.joinpath('pe_files_extra_data.txt')

    print('Running sigcheck...')

    sigcheck_data = prase_sigcheck(sigcheck_folder(folder, sigcheck_file), folder)

    print('Parsing PE files...')

    if not REUSE_OUTPUT_FILES or not pe_files_extra_data.is_file():
        pe_extra_data = {}
        for item in sigcheck_data:
            if 'MachineType' in item and item['MachineType'] in ['32-bit', '64-bit', 'ARM64']:
                filename = item['FileName']
                pe_extra_data[filename] = get_pe_extra_data(filename)
                machine = pe_extra_data[filename]['machine']
                if item['MachineType'] == '32-bit':
                    assert machine == 332
                elif item['MachineType'] == '64-bit':
                    assert machine == 34404
                else:
                    assert item['MachineType'] == 'ARM64'
                    assert machine == 43620

        with open(pe_files_extra_data, 'w') as f:
            json.dump(pe_extra_data, f, indent=4)
    else:
        with open(pe_files_extra_data) as f:
            pe_extra_data = json.load(f)

    print('Gathering results...')

    result_files = set()
    file_hashes = {}
    for item in sigcheck_data:
        filename = item['FileName']
        file_size = Path(filename).stat().st_size
        result_item = {
            'path': item['FileNameRelative'],
            'md5': item['MD5'].lower(),
            'sha1': item['SHA1'].lower(),
            'sha256': item['SHA256'].lower(),
            'size': file_size,
        }

        if 'MachineType' in item and item['MachineType'] in ['32-bit', '64-bit', 'ARM64']:
            file_pe_extra_data = pe_extra_data[filename]
            result_item.update({
                'machineType': file_pe_extra_data['machine'],
                'timestamp': file_pe_extra_data['timestamp'],
                'virtualSize': file_pe_extra_data['image_size'],
                'signingStatus': item['Verified'],
            })
            if item['Verified'] != 'Unsigned':
                if 'Signing date' in item:
                    # Needs to be a tuple to be hashable.
                    result_item['signingDate'] = tuple(filetime_to_date(d) for d in item['Signing date'])
                    result_item['signatureType'] = 'Overlay'
                else:
                    result_item['signatureType'] = 'Catalog file'
            if 'Description' in item:
                result_item['description'] = item['Description']
            if 'File version' in item:
                result_item['version'] = item['File version']

        result_files.add(hashabledict(result_item))

        name = filename.split('\\')[-1].lower()
        if (name.endswith('.exe') or
            name.endswith('.dll') or
            name.endswith('.sys')):
            file_hashes.setdefault(name, set()).add(item['SHA256'].lower())

    result = {
        'windowsVersion': windows_version,
        'windowsIsoSha256': iso_sha256.lower(),
        'windowsReleaseDate': release_date,
        'files': list(result_files),
    }

    print('Writing results...')

    output_dir = config.out_path.joinpath('from_iso')
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir.joinpath(windows_version + '.json'), 'w') as f:
        json.dump(result, f, indent=4)

    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    for name in file_hashes:
        for file_hash in file_hashes[name]:
            info_sources.setdefault(name, {})[file_hash] = 'file'

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f)

if __name__ == '__main__':
    if len(sys.argv) != 5:
        exit(f'Usage: {sys.argv[0]} folder windows_version iso_sha256 release_date_yyyy_mm_dd')

    folder, windows_version, iso_sha256, release_date = sys.argv[1:5]
    main(Path(folder), windows_version, iso_sha256, release_date)
