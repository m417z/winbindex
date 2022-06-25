from threading import Thread
from pathlib import Path
import subprocess
import datetime
import platform
import requests
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


def download_update(windows_version, update_kb):
    # ARM only.
    if update_kb in ['KB5016138', 'KB5016139']:
        raise UpdateNotSupported

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

    # TODO: more archs?
    search_query += f' x64'

    found_updates = search_for_updates(search_query)

    filter_regex = r'\bserver\b|\bDynamic Cumulative Update\b'

    found_updates = [update for update in found_updates if not re.search(filter_regex, update[1], re.IGNORECASE)]

    if len(found_updates) != 1:
        raise Exception(f'Expected one update item, found {len(found_updates)}')

    update_uid, update_title = found_updates[0]
    assert re.fullmatch(rf'(\d{{4}}-\d{{2}} )?Cumulative Update (Preview )?for {package_windows_version} for x64-based Systems \({update_kb}\)', update_title), update_title

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
    subprocess.run(args, check=True, stdout=None if config.verbose_run else subprocess.DEVNULL)

    return download_url, local_dir, local_path


def extract_manifest_files(local_dir, local_path):
    def cab_extract(pattern, from_file, to_dir):
        if platform.system() == 'Windows':
            args = ['expand', '-r', f'-f:{pattern}', from_file, to_dir]
        else:
            args = ['cabextract', '-F', pattern, '-d', to_dir, from_file]
        subprocess.run(args, check=True, stdout=None if config.verbose_run else subprocess.DEVNULL)

    extract_dirs = []
    for i in range(4):
        extract_dir = local_dir.joinpath(f'extract{i + 1}')
        extract_dir.mkdir(parents=True, exist_ok=True)
        extract_dirs.append(extract_dir)

    cab_extract('*.cab', local_path, extract_dirs[0])

    for i in range(4):
        for cab in extract_dirs[i].glob('*.cab'):
            if cab.name.lower() in (x.lower() for x in [
                'DesktopDeployment.cab',
                'DesktopDeployment_x86.cab',
                'onepackage.AggregatedMetadata.cab',
                'WSUSSCAN.cab'
            ]):
                continue

            cab_extract('*.manifest', cab, local_dir)
            cab_extract('*.cab', cab, extract_dirs[i + 1])

    # Assert that we're done.
    assert not any(extract_dirs[3].glob('*.cab'))

    for extract_dir in extract_dirs:
        shutil.rmtree(extract_dir)

    local_path.unlink()

    # Starting with Windows 11, manifest files are compressed with the DCM v1 format.
    # Use SYSEXP to de-compress them: https://github.com/hfiref0x/SXSEXP
    if platform.system() == 'Windows':
        args = ['tools/sxsexp64.exe', local_dir, local_dir]
        subprocess.run(args, stdout=None if config.verbose_run else subprocess.DEVNULL)


def get_manifests_from_update(windows_version, update_kb):
    print(f'[{update_kb}] Downloading update')

    download_url, local_dir, local_path = download_update(windows_version, update_kb)
    print(f'[{update_kb}] Downloaded {local_path.stat().st_size} bytes from {download_url}')

    def extract_manifest_files_start():
        print(f'[{update_kb}] Extracting manifest files')
        try:
            extract_manifest_files(local_dir, local_path)
        except Exception as e:
            print(f'[{update_kb}] ERROR: Failed to process update')
            print(f'[{update_kb}]        ' + str(e))
            if config.exit_on_first_error:
                raise
            return
        print(f'[{update_kb}] Extracted manifest files')

    if config.extract_in_a_new_thread:
        thread = Thread(target=extract_manifest_files_start)
        thread.start()
    else:
        extract_manifest_files_start()


def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = json.load(f)

    for windows_version in updates:
        print(f'Processing Windows version {windows_version}')

        for update_kb in updates[windows_version]:
            try:
                get_manifests_from_update(windows_version, update_kb)
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
                print(f'[{update_kb}]        ' + str(e))
                if config.exit_on_first_error:
                    raise

        print()


if __name__ == '__main__':
    main()
