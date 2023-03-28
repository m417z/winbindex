from threading import Thread
from pathlib import Path
import subprocess
import datetime
import platform
import requests
import hashlib
import shutil
import json
import re

import config


class UpdateNotFound(Exception):
    pass


class UpdateNotSupported(Exception):
    pass


def search_for_updates(search_terms):
    url = 'https://www.catalog.update.microsoft.com/Search.aspx'
    while True:
        html = requests.get(url, {'q': search_terms}).text
        if 'The website has encountered a problem' not in html:
            break
        # Retry...

    if 'We did not find any results' in html:
        raise UpdateNotFound

    assert '(page 1 of 1)' in html  # we expect only one page of results

    p = r'<a [^>]*?onclick=\'goToDetails\("([a-f0-9\-]+)"\);\'[^>]*?>\s*(.*?)\s*</a>'
    matches = re.findall(p, html)

    p2 = r'<input id="([a-f0-9\-]+)" class="flatBlueButtonDownload\b[^"]*?" type="button" value=\'Download\' />'
    assert [uid for uid, title in matches] == re.findall(p2, html)

    return matches


def get_update_download_url(update_uid):
    input_json = [{
        'uidInfo': update_uid,
        'updateID': update_uid
    }]
    url = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
    html = requests.post(url, {'updateIDs': json.dumps(input_json)}).text

    p = r'\ndownloadInformation\[\d+\]\.files\[\d+\]\.url = \'([^\']+)\';'
    matches = re.findall(p, html)
    if len(matches) != 1:
        raise Exception(f'Expected one downloadInformation item, found {len(matches)}')

    return matches[0]


def get_update(windows_version, update_kb):
    search_query = update_kb

    if windows_version == '11-21H2':
        package_windows_version = fr'Windows 11'  # first Windows 11 version, no suffix
    elif '-' in windows_version:
        windows_version_split = windows_version.split('-')
        search_query += f' {windows_version_split[1]}'
        package_windows_version = fr'Windows {windows_version_split[0]} Version {windows_version_split[1]}'
    else:
        search_query += f' {windows_version}'
        package_windows_version = fr'Windows 10 Version {windows_version}'

    search_query += f' {config.updates_architecture}'

    found_updates = search_for_updates(search_query)

    filter_regex = r'\bserver\b|\bDynamic Cumulative Update\b| UUP$'

    found_updates = [update for update in found_updates if not re.search(filter_regex, update[1], re.IGNORECASE)]

    # Replace the pattern, and if after the replacement the item exists, filter it.
    # For example, if there's both Cumulative and Delta, pick Cumulative.
    filter_regex_pairs = [
        [r'^(\d{4}-\d{2} )?Delta ', r'\1Cumulative '],
        [r'\bWindows 10 Version 1909\b', r'Windows 10 Version 1903'],
    ]

    found_update_titles = [update[1] for update in found_updates]
    filtered_updates = []
    for update in found_updates:
        update_title = update[1]
        matched = False
        for search, replace in filter_regex_pairs:
            update_title_sub, num_subs = re.subn(search, replace, update_title)
            if num_subs > 0 and update_title_sub in found_update_titles:
                matched = True
                break

        if not matched:
            filtered_updates.append(update)

    found_updates = filtered_updates

    if len(found_updates) != 1:
        raise Exception(f'Expected one update item, found {len(found_updates)}')

    update_uid, update_title = found_updates[0]
    update_title_pattern = rf'(\d{{4}}-\d{{2}} )?(Cumulative|Delta) Update (Preview )?for {package_windows_version} for (?i:{config.updates_architecture})-based Systems \({update_kb}\)'
    assert re.fullmatch(update_title_pattern, update_title), update_title

    return update_uid, update_title


def download_update(windows_version, update_kb):
    update_uid, update_title = get_update(windows_version, update_kb)

    download_url = get_update_download_url(update_uid)
    if not download_url:
        raise Exception('Update not found in catalog')

    local_dir = config.out_path.joinpath('manifests', windows_version, update_kb)
    local_dir.mkdir(parents=True, exist_ok=True)

    local_filename = download_url.split('/')[-1]
    local_path = local_dir.joinpath(local_filename)

    #with requests.get(download_url, stream=True) as r:
    #    with open(local_path, 'wb') as f:
    #        shutil.copyfileobj(r.raw, f)

    args = ['aria2c', '-x4', '-o', local_path, '--allow-overwrite=true', download_url]
    subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    return download_url, local_dir, local_path


# https://stackoverflow.com/a/44873382
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def extract_update_files(local_dir: Path, local_path: Path):
    def cab_extract(pattern: str, from_file: Path, to_dir: Path):
        to_dir.mkdir()
        if platform.system() == 'Windows':
            args = ['expand', '-r', f'-f:{pattern}', from_file, to_dir]
        else:
            args = ['cabextract', '-F', pattern, '-d', to_dir, from_file]
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    # Extract all files from all cab files until no more cab files can be found.
    first_unhandled_extract_dir_num = 1
    next_extract_dir_num = 1

    extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
    next_extract_dir_num += 1
    cab_extract('*', local_path, extract_dir)
    local_path.unlink()

    while first_unhandled_extract_dir_num < next_extract_dir_num:
        next_unhandled_extract_dir_num = next_extract_dir_num

        for src_extract_dir_num in range(first_unhandled_extract_dir_num, next_extract_dir_num):
            src_extract_dir = local_dir.joinpath(f'_extract_{src_extract_dir_num}')
            for cab in src_extract_dir.glob('*.cab'):
                extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
                next_extract_dir_num += 1
                cab_extract('*', cab, extract_dir)
                cab.unlink()

        first_unhandled_extract_dir_num = next_unhandled_extract_dir_num

    # Move all extracted files from all folders to the target folder.
    for extract_dir in local_dir.glob('_extract_*'):
        def ignore_files(path, names):
            source_dir = Path(path)
            destination_dir = local_dir.joinpath(Path(path).relative_to(extract_dir))

            ignore = []
            for name in names:
                source_file = source_dir.joinpath(name)
                if source_file.is_file():
                    # Ignore files in root folder which have different non-identical copies with the same name.
                    # Also ignore cab archives in the root folder.
                    if source_dir == extract_dir:
                        if (name in ['update.cat', 'update.mum'] or
                            name.endswith('.cab') or
                            name.endswith('.dll')):
                           ignore.append(name)
                           continue

                    # Ignore files which already exist as long as they're identical.
                    destination_file = destination_dir.joinpath(name)
                    if destination_file.exists():
                        if not destination_file.is_file():
                            raise Exception(f'A destination item already exists and is not a file: {destination_file}')

                        if sha256sum(source_file) != sha256sum(destination_file):
                            raise Exception(f'A different file copy already exists: {destination_file}')

                        ignore.append(name)

            return ignore

        shutil.copytree(extract_dir, local_dir, copy_function=shutil.move, dirs_exist_ok=True, ignore=ignore_files)
        shutil.rmtree(extract_dir)

    # Extract delta files from the PSF file which can be found in Windows 11 updates.
    # References:
    # https://www.betaarchive.com/forum/viewtopic.php?t=43163
    # https://github.com/Secant1006/PSFExtractor
    if platform.system() == 'Windows':
        psf_files = list(local_dir.glob('*.psf'))
        assert len(psf_files) <= 1
        if len(psf_files) == 1:
            psf_file = psf_files[0]
            args = ['tools/PSFExtractor.exe', '-v2', psf_file, local_dir.joinpath('express.psf.cix.xml'), local_dir]
            subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)
            psf_file.unlink()

    # Unpack null differential files.
    if platform.system() == 'Windows':
        from delta_patch import unpack_null_differential_file

        for file in local_dir.glob('*/n/**/*'):
            if file.is_file():
                unpack_null_differential_file(file, file)

    # Use DeltaDownloader to extract meaningful data from delta files:
    # https://github.com/m417z/DeltaDownloader
    if platform.system() == 'Windows':
        # Avoid path limitations by using a UNC path.
        local_dir_unc = Rf'\\?\{local_dir.absolute()}'
        args = ['tools/DeltaDownloader/DeltaDownloader.exe', '/g', local_dir_unc]
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    # Starting with Windows 11, manifest files are compressed with the DCM v1 format.
    # Use SYSEXP to de-compress them: https://github.com/hfiref0x/SXSEXP
    if platform.system() == 'Windows':
        args = ['tools/sxsexp64.exe', local_dir, local_dir]
        subprocess.run(args, stdout=None if config.verbose_run else subprocess.DEVNULL)


def get_files_from_update(windows_version: str, update_kb: str):
    if update_kb in config.updates_unsupported:
        raise UpdateNotSupported

    print(f'[{update_kb}] Downloading update')

    download_url, local_dir, local_path = download_update(windows_version, update_kb)
    print(f'[{update_kb}] Downloaded {local_path.stat().st_size} bytes from {download_url}')

    def extract_update_files_start():
        print(f'[{update_kb}] Extracting update files')
        try:
            extract_update_files(local_dir, local_path)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            print(f'[{update_kb}] ERROR: Failed to process update')
            print(f'[{update_kb}]        {e}')
            if config.exit_on_first_error:
                raise
            return
        print(f'[{update_kb}] Extracted update files')

    if config.extract_in_a_new_thread:
        thread = Thread(target=extract_update_files_start)
        thread.start()
    else:
        extract_update_files_start()


def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = json.load(f)

    for windows_version in updates:
        print(f'Processing Windows version {windows_version}')

        for update_kb in updates[windows_version]:
            try:
                get_files_from_update(windows_version, update_kb)
            except (KeyboardInterrupt, SystemExit):
                raise
            except UpdateNotSupported:
                print(f'[{update_kb}] WARNING: Skipping unsupported update')
            except UpdateNotFound:
                # Only treat as an error if the update is recent. If the update is old,
                # only show a warning, since old updates are removed from the update catalog
                # with time.
                a_while_ago = (datetime.date.today() - datetime.timedelta(days=90)).isoformat()
                if updates[windows_version][update_kb]['releaseDate'] > a_while_ago:
                    print(f'[{update_kb}] ERROR: Update wasn\'t found')
                    if config.exit_on_first_error:
                        raise
                else:
                    print(f'[{update_kb}] WARNING: Update wasn\'t found, it was probably removed from the update catalog')
            except Exception as e:
                print(f'[{update_kb}] ERROR: Failed to process update')
                print(f'[{update_kb}]        {e}')
                if config.exit_on_first_error:
                    raise

        print()


if __name__ == '__main__':
    main()
