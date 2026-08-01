from pathlib import Path
import json
import stat
import sys
import os
import re

from extract_data_from_pe_files import extract_data_from_pe_files
from info_sources import InfoSource, InfoSources
import config

# To get data from an ISO file use the following commands:
#
# mkdir C:\w
# cd C:\w
# 7z.exe e C:\path\to\windows.iso sources\install.wim
# 7z.exe x install.wim -r
# del install.wim
#
# Then point this script at the resulting folder.
# Note: Prefix the path with \\?\:
# \\?\C:\w
# In order to add support for long paths to sigcheck.
#
# Finally, run upd05_group_by_filename.py to aggregate the results.


# https://stackoverflow.com/a/1151705
class hashabledict(dict):
    def __hash__(self):
        return hash(tuple(sorted(self.items())))


def remove_duplicate_files(folder: Path):
    # Get all numbered subfolders
    numbered_folders = sorted(
        [f for f in folder.iterdir() if f.is_dir() and f.name.isdigit()],
        key=lambda f: int(f.name)
    )

    if len(numbered_folders) < 2:
        return

    # Build a dict: relative_path -> list of full_paths
    files_by_relative_path: dict[str, list[Path]] = {}

    for numbered_folder in numbered_folders:
        for file_path in numbered_folder.rglob('*'):
            if file_path.is_file():
                relative_path = file_path.relative_to(numbered_folder)
                files_by_relative_path.setdefault(str(relative_path), []).append(file_path)

    # For each relative path with multiple files, compare content and remove duplicates
    removed_count = 0
    for relative_path, file_paths in files_by_relative_path.items():
        if len(file_paths) < 2:
            continue

        # Group files by size first
        size_groups: dict[int, list[Path]] = {}
        for file_path in file_paths:
            size = file_path.stat().st_size
            size_groups.setdefault(size, []).append(file_path)

        # Only compare content for files with identical size
        for size, same_size_paths in size_groups.items():
            if len(same_size_paths) < 2:
                continue

            # Group files by content
            content_groups: dict[bytes, list[Path]] = {}
            for file_path in same_size_paths:
                content = file_path.read_bytes()
                content_groups.setdefault(content, []).append(file_path)

            # For each group with identical content, keep one and remove the rest
            for content, paths in content_groups.items():
                if len(paths) > 1:
                    # Keep the first one (lowest numbered folder), remove the rest
                    for path_to_remove in paths[1:]:
                        # Remove read-only attribute if set
                        os.chmod(path_to_remove, stat.S_IWRITE)
                        path_to_remove.unlink()
                        removed_count += 1

    print(f'Removed {removed_count} duplicate files')


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

    remove_duplicate_files(folder)

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

    info_sources = InfoSources.load()
    info_sources.update_sources({name: {file_hash: InfoSource.FILE for file_hash in pe_file_hashes[name]}
                                 for name in pe_file_hashes})
    info_sources.save()


if __name__ == '__main__':
    if len(sys.argv) != 5:
        exit(f'Usage: {sys.argv[0]} folder windows_version iso_sha256 release_date_yyyy_mm_dd')

    folder, windows_version, iso_sha256, release_date = sys.argv[1:5]
    main(Path(folder), windows_version, iso_sha256, release_date)
