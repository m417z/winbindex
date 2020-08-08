from threading import Thread
from pathlib import Path
import subprocess
import platform
import requests
import shutil
import json
import re

import config

def get_update_download_url(search_terms):
    url = 'https://www.catalog.update.microsoft.com/Search.aspx'
    html = requests.get(url, {'q': search_terms}).text

    p = r'<input id="([a-f0-9\-]+)" class="flatLightBlueButton" type="button" value=\'Download\' />'
    matches = re.findall(p, html)
    if len(matches) == 0:
        return None

    if len(matches) != 1:
        raise Exception(f'Expected one download button, found {len(matches)}')

    uid = matches[0]
    input_json = [{
        'uidInfo': uid,
        'updateID': uid
    }]
    url = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
    html = requests.post(url, {'updateIDs': json.dumps(input_json)}).text

    p = r'\ndownloadInformation\[\d+\]\.files\[\d+\]\.url = \'([^\']+)\';'
    matches = re.findall(p, html)
    if len(matches) != 1:
        raise Exception(f'Expected one downloadInformation item, found {len(matches)}')

    return matches[0]

def download_update(windows_version, update_kb):
    search_terms = update_kb

    # TODO: more archs?
    if False:  # update_kb in ['KB4478877', 'KB4471324', 'KB4507469']:
        search_terms += ' x64 server'  # for buggy downloads, the update package should be the same anyway
    else:
        search_terms += ' x64 -server'

    if windows_version == '1903':
        search_terms += ' -1909'  # the updates are the same and appear twice

    download_url = get_update_download_url(search_terms + ' -delta')
    if not download_url:
        download_url = get_update_download_url(search_terms)

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

    extract1_dir = local_dir.joinpath('extract1')
    extract1_dir.mkdir(parents=True, exist_ok=True)

    cab_exctract('*.cab', local_path, extract1_dir)

    extract2_dir = local_dir.joinpath('extract2')
    extract2_dir.mkdir(parents=True, exist_ok=True)

    for cab in extract1_dir.glob('*.cab'):
        if cab.name.lower() == 'WSUSSCAN.cab'.lower():
            continue

        cab_exctract('*.cab', cab, extract2_dir)

    if any(extract2_dir.glob('*.cab')):
        for cab in extract2_dir.glob('*.cab'):
            cab_exctract('*.manifest', cab, local_dir)
    else:
        for cab in extract1_dir.glob('*.cab'):
            if cab.name.lower() == 'WSUSSCAN.cab'.lower():
                continue

            cab_exctract('*.manifest', cab, local_dir)

    shutil.rmtree(extract1_dir)
    shutil.rmtree(extract2_dir)
    local_path.unlink()

def get_manifests_from_update(windows_version, update_kb):
    print(f'[{update_kb}] Downloading update')

    download_url, local_dir, local_path = download_update(windows_version, update_kb)
    print(f'[{update_kb}] Downloaded {local_path.stat().st_size} bytes from {download_url}')

    def extract_manifset_files():
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
        thread = Thread(target=extract_manifset_files)
        thread.start()
    else:
        extract_manifset_files()

def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = json.load(f)

    for windows_version in updates:
        if windows_version == '1909':
            continue  # same updates as 1903

        print(f'Processing Windows version {windows_version}')

        for update in updates[windows_version]:
            update_kb = update['updateKb']

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
