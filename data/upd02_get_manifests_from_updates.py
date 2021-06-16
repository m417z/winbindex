from threading import Thread
from pathlib import Path
import subprocess
import platform
import requests
import shutil
import json
import re

import config

def search_for_updates(search_terms):
    url = 'https://www.catalog.update.microsoft.com/Search.aspx'
    while True:
        html = requests.get(url, {'q': search_terms}).text
        if 'The website has encountered a problem' not in html:
            break
        # Retry...

    assert '(page 1 of 1)' in html  # we expect only one page of results

    p = r'<a [^>]*?onclick=\'goToDetails\("([a-f0-9\-]+)"\);\'>\s*(.*?)\s*</a>'
    matches = re.findall(p, html)

    p2 = r'<input id="([a-f0-9\-]+)" class="flatBlueButtonDownload" type="button" value=\'Download\' />'
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
    # TODO: more archs?
    found_updates = search_for_updates(f'{update_kb} {windows_version} x64')

    filter_regex = r'\bserver\b|\bDynamic Cumulative Update\b'

    found_updates = [update for update in found_updates if not re.search(filter_regex, update[1], re.IGNORECASE)]

    if len(found_updates) != 1:
        raise Exception(f'Expected one update item, found {len(found_updates)}')

    update_uid, update_title = found_updates[0]
    assert re.fullmatch(rf'(\d{{4}}-\d{{2}} )?Cumulative Update (Preview )?for Windows 10 Version {windows_version} for x64-based Systems \({update_kb}\)', update_title), update_title

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

    if platform.system() == 'Windows':
        aria2c_app = 'tools/aria2c.exe'
    else:
        aria2c_app = 'aria2c'

    args = [aria2c_app, '-x4', '-o', local_path, '--allow-overwrite=true', download_url]
    subprocess.run(args, check=True, stdout=None if config.verbose_run else subprocess.DEVNULL)

    return download_url, local_dir, local_path

def extract_manifest_files(local_dir, local_path):
    def cab_exctract(pattern, from_file, to_dir):
        if platform.system() == 'Windows':
            args = ['expand', f'-f:{pattern}', from_file, to_dir]
        else:
            args = ['cabextract', '-F', pattern, '-d', to_dir, from_file]
        subprocess.run(args, check=True, stdout=None if config.verbose_run else subprocess.DEVNULL)

    extract_dirs = []
    for i in range(1, 5):
        extract_dir = local_dir.joinpath(f'extract{i}')
        extract_dir.mkdir(parents=True, exist_ok=True)
        extract_dirs.append(extract_dir)

    cab_exctract('*.cab', local_path, extract_dirs[0])

    for cab in extract_dirs[0].glob('*.cab'):
        if cab.name.lower() == 'WSUSSCAN.cab'.lower():
            continue

        cab_exctract('*.cab', cab, extract_dirs[1])

    if not any(extract_dirs[1].glob('*.cab')):
        # No more cabs, just extract manifests.
        for cab in extract_dirs[0].glob('*.cab'):
            if cab.name.lower() == 'WSUSSCAN.cab'.lower():
                continue

            cab_exctract('*.manifest', cab, local_dir)
    else:
        for cab in extract_dirs[1].glob('*.cab'):
            cab_exctract('*.manifest', cab, local_dir)
            cab_exctract('*.cab', cab, extract_dirs[2])

        for cab in extract_dirs[2].glob('*.cab'):
            cab_exctract('*.manifest', cab, local_dir)
            cab_exctract('*.cab', cab, extract_dirs[3])

        # Assert that we're done.
        assert not any(extract_dirs[3].glob('*.cab'))

    for extract_dir in extract_dirs:
        shutil.rmtree(extract_dir)

    local_path.unlink()

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
            except Exception as e:
                print(f'[{update_kb}] ERROR: Failed to process update')
                print(f'[{update_kb}]        ' + str(e))
                if config.exit_on_first_error:
                    raise

        print()

if __name__ == '__main__':
    main()
