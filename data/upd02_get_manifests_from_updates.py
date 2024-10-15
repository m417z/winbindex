from threading import Thread
from pathlib import Path
import subprocess
import datetime
import requests
import hashlib
import shutil
import json
import re

from delta_patch import unpack_null_differential_file
import config


class UpdateNotFound(Exception):
    pass


class UpdateNotSupported(Exception):
    pass


def search_for_updates(search_terms: str):
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


def get_update_download_urls(update_uid: str):
    input_json = [{
        'uidInfo': update_uid,
        'updateID': update_uid
    }]
    url = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
    html = requests.post(url, {'updateIDs': json.dumps(input_json)}).text

    p = r'\ndownloadInformation\[\d+\]\.files\[\d+\]\.url = \'([^\']+)\';'
    return re.findall(p, html)


def get_update(windows_version: str, update_kb: str):
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


def download_update(windows_version: str, update_kb: str):
    download_url = config.updates_alternative_links.get((windows_version, update_kb))
    if not download_url:
        update_uid, update_title = get_update(windows_version, update_kb)

        download_urls = get_update_download_urls(update_uid)
        if not download_urls:
            raise Exception('Update not found in catalog')

        p = fr'/windows[^-]*-{re.escape(update_kb.lower())}-[^/]*$'
        download_urls = [x for x in download_urls if re.search(p, x)]

        if len(download_urls) != 1:
            raise Exception(f'Expected one update URL, found {len(download_urls)}')

        download_url = download_urls[0]

    local_dir = config.out_path.joinpath('manifests', windows_version, update_kb)
    local_dir.mkdir(parents=True, exist_ok=True)

    local_filename = download_url.split('/')[-1]
    local_path = local_dir.joinpath(local_filename)

    #with requests.get(download_url, stream=True) as r:
    #    with open(local_path, 'wb') as f:
    #        shutil.copyfileobj(r.raw, f)

    args = ['aria2c', '-x4', '-d', local_dir, '-o', local_filename, '--allow-overwrite=true', download_url]
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


def extract_update_files(local_dir: Path, local_path: Path, windows_version: str):
    def cab_extract(from_file: Path, to_dir: Path):
        to_dir.mkdir()
        # New cab files fail to be extracted with the older system expand tool,
        # and old cab files fail to be extracted with the newer expand tool.
        expand = 'tools/expand/expand.exe' if windows_version.startswith('11-') else 'expand.exe'
        args = [expand, '-r', f'-f:*', from_file, to_dir]
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    def run_7z_extract(from_file: Path, to_dir: Path):
        args = ['7z.exe', 'x', from_file, f'-o{to_dir}', '-y']
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    def psf_extract(from_file: Path, to_dir: Path):
        # Extract delta files from the PSF file which can be found in Windows 11
        # updates. References:
        # https://www.betaarchive.com/forum/viewtopic.php?t=43163
        # https://github.com/Secant1006/PSFExtractor
        description_file = from_file.parent.joinpath('express.psf.cix.xml')
        if not description_file.exists():
            cab_file = from_file.with_suffix('.cab')
            wim_file = from_file.with_suffix('.wim')
            if cab_file.exists():
                assert not wim_file.exists()
                cab_extract(cab_file, to_dir)
                cab_file.unlink()
            elif wim_file.exists():
                assert not cab_file.exists()
                run_7z_extract(wim_file, to_dir)
                wim_file.unlink()
            else:
                raise Exception(f'PSF description file not found: {from_file}')

            description_file = to_dir.joinpath('express.psf.cix.xml')

        args = ['tools/PSFExtractor.exe', '-v2', from_file, description_file, to_dir]
        subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    first_unhandled_extract_dir_num = 1
    next_extract_dir_num = 1

    # Extract main archive.
    extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
    print(f'Extracting {local_path} to {extract_dir}')
    next_extract_dir_num += 1
    with local_path.open('rb') as f:
        first_bytes = f.read(16)
    if first_bytes.startswith(b'MSCF'):
        cab_extract(local_path, extract_dir)
    elif first_bytes.startswith(b'MSWIM\0\0\0\xD0\0\0\0\0'):
        run_7z_extract(local_path, extract_dir)
    else:
        raise Exception(f'Unknown archive format: {first_bytes}')
    local_path.unlink()

    # Extract PSF file.
    psf_files = list(extract_dir.glob('*.psf'))
    if psf_files:
        # Only one PSF file per update was observed so far.
        assert len(psf_files) == 1, psf_files
        p = psf_files[0]

        extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
        print(f'Extracting {p} to {extract_dir}')
        next_extract_dir_num += 1
        psf_extract(p, extract_dir)
        p.unlink()

    # Extract all files from all cab files until no more cab files can be found.
    while first_unhandled_extract_dir_num < next_extract_dir_num:
        next_unhandled_extract_dir_num = next_extract_dir_num

        for src_extract_dir_num in range(first_unhandled_extract_dir_num, next_extract_dir_num):
            src_extract_dir = local_dir.joinpath(f'_extract_{src_extract_dir_num}')
            for p in src_extract_dir.glob('*.cab'):
                extract_dir = local_dir.joinpath(f'_extract_{next_extract_dir_num}')
                print(f'Extracting {p} to {extract_dir}')
                next_extract_dir_num += 1
                cab_extract(p, extract_dir)
                p.unlink()

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
                    if source_dir == extract_dir:
                        if name in ['update.cat', 'update.mum'] or name.endswith('.dll'):
                           ignore.append(name)
                           continue

                    # Ignore files which already exist as long as they're identical.
                    destination_file = destination_dir.joinpath(name)
                    if destination_file.exists():
                        if not destination_file.is_file():
                            raise Exception(f'A destination item already exists and is not a file: {destination_file}')

                        if sha256sum(source_file) != sha256sum(destination_file):
                            raise Exception(f'A different file copy already exists: {destination_file} (source: {source_file})')

                        ignore.append(name)

            return ignore

        shutil.copytree(extract_dir, local_dir, copy_function=shutil.move, dirs_exist_ok=True, ignore=ignore_files)
        shutil.rmtree(extract_dir)

    # Make sure there are no archive files left.
    for p in local_dir.glob('*'):
        if p.suffix in {'.msu', '.cab', '.psf', '.wim'}:
            raise Exception(f'Unexpected archive file left: {p}')

    # Unpack null differential files.
    for file in local_dir.glob('*/n/**/*'):
        if file.is_file():
            unpack_null_differential_file(file, file)

    # Use DeltaDownloader to extract meaningful data from delta files:
    # https://github.com/m417z/DeltaDownloader
    args = ['tools/DeltaDownloader/DeltaDownloader.exe', '/g', local_dir]
    subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)

    # Starting with Windows 11, manifest files are compressed with the DCM v1 format.
    # Use SXSEXP to de-compress them: https://github.com/hfiref0x/SXSEXP
    args = ['tools/sxsexp64.exe', local_dir, local_dir]
    subprocess.check_call(args, stdout=None if config.verbose_run else subprocess.DEVNULL)


def get_files_from_update(windows_version: str, update_kb: str):
    if update_kb in config.updates_unsupported:
        raise UpdateNotSupported

    print(f'[{update_kb}] Downloading update')

    download_url, local_dir, local_path = download_update(windows_version, update_kb)
    print(f'[{update_kb}] Downloaded {local_path.stat().st_size} bytes from {download_url}')

    def extract_update_files_start():
        print(f'[{update_kb}] Extracting update files')
        try:
            extract_update_files(local_dir, local_path, windows_version)
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
