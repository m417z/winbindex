from pathlib import Path
import json
import sys
import re

from extract_data_from_pe_files import extract_data_from_pe_files
import config

# To get data from an ISO file use the following commands:
#
# cd C:\path\to\output
# 7z.exe e C:\path\to\windows.iso sources\install.wim
# 7z.exe x install.wim -r
# del install.wim
#
# Then point this script at the resulting folder.
# Note: Prefix the path with \\?\, for example:
# \\?\C:\w10
# In order to add support for long paths to sigcheck.


# https://stackoverflow.com/a/1151705
class hashabledict(dict):
    def __hash__(self):
        return hash(tuple(sorted(self.items())))


def main(folder: Path, windows_version: str, iso_sha256: str, release_date: str):
    assert (
        re.match(r'^(1[5-9]|20)0[0-9]$', windows_version) or
        re.match(r'^(11-)?2[0-9]H[12]$', windows_version)
    )
    assert re.match(r'^[A-Fa-f0-9]{64}$', iso_sha256)
    assert re.match(r'^\d{4}-\d{2}-\d{2}$', release_date)
    assert str(folder).startswith('\\\\?\\'), 'Prefix dir with \\\\?\\ for long paths'

    result_files = set()
    pe_file_hashes = {}

    excluded_paths = [
        R'Windows\WinSxS',
        R'Windows\System32\CatRoot',
        R'Windows\SysWOW64\CatRoot',
        R'Windows\servicing\Packages',
    ]
    excluded_paths = [x.lower() + '\\' for x in excluded_paths]

    def path_filter_callback(filename_relative: Path):
        if len(filename_relative.parts) == 1:
            return None

        digit = filename_relative.parts[0]
        assert digit.isdigit()
        filename_relative = filename_relative.relative_to(digit)

        filename_relative_lower = str(filename_relative).lower()
        if any(filename_relative_lower.startswith(excluded_path) for excluded_path in excluded_paths):
            return None

        return filename_relative

    def callback(filename: str, result_item):
        result_files.add(hashabledict(result_item))

        name = filename.split('\\')[-1].lower()
        if (re.search(r'\.(exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv)$', name)):
            pe_file_hashes.setdefault(name, set()).add(result_item['sha256'])

    extract_data_from_pe_files(folder, callback, path_filter_callback=path_filter_callback, verbose=True)

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

    for name in pe_file_hashes:
        for file_hash in pe_file_hashes[name]:
            info_sources.setdefault(name, {})[file_hash] = 'file'

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)


if __name__ == '__main__':
    if len(sys.argv) != 5:
        exit(f'Usage: {sys.argv[0]} folder windows_version iso_sha256 release_date_yyyy_mm_dd')

    folder, windows_version, iso_sha256, release_date = sys.argv[1:5]
    main(Path(folder), windows_version, iso_sha256, release_date)
