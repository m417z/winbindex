from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import requests
import zipfile
import socket
import json
import time
import os

# Temporary
import shutil

from upd01_get_list_of_updates import main as upd01_get_list_of_updates
from upd02_get_manifests_from_updates import main as upd02_get_manifests_from_updates
from upd03_parse_manifests import main as upd03_parse_manifests
from upd04_get_virustotal_data import main as upd04_get_virustotal_data
from upd05_group_by_filename import main as upd05_group_by_filename
import config

def filter_updates(updates, update_kbs):
    filtered = {}
    for windows_version in updates:
        for update_info in updates[windows_version]:
            if update_info['updateKb'] in update_kbs:
                updates_array = filtered.setdefault(windows_version, [])
                updates_array.append(update_info)

    return filtered

def prepare_updates():
    last_time_updates_path = config.out_path.joinpath('updates_last.json')
    with open(last_time_updates_path, 'r') as f:
        last_time_updates = json.load(f)

    last_time_update_kbs = {item['updateKb'] for items in last_time_updates.values() for item in items}

    upd01_get_list_of_updates()

    temp_updates_path = config.out_path.joinpath('updates.json')
    with open(temp_updates_path, 'r') as f:
        uptodate_updates = json.load(f)

    uptodate_update_kbs = {item['updateKb'] for items in uptodate_updates.values() for item in items}

    if last_time_update_kbs == uptodate_update_kbs:
        temp_updates_path.unlink()
        print('No new updates')
        return None

    assert len(last_time_update_kbs - uptodate_update_kbs) == 0
    assert len(uptodate_update_kbs - last_time_update_kbs) > 0

    new_update_kbs = sorted(uptodate_update_kbs - last_time_update_kbs)
    print(f'New updates: {new_update_kbs}')

    # Update one at a time.
    update_kb = new_update_kbs[0]

    print(f'Updating {update_kb}')

    single_update = filter_updates(uptodate_updates, {update_kb})

    with open(temp_updates_path, 'w') as f:
        json.dump(single_update, f, indent=4)

    with open(last_time_updates_path, 'w') as f:
        last_time_updates = filter_updates(uptodate_updates, last_time_update_kbs | {update_kb})
        json.dump(last_time_updates, f, indent=4)

    return update_kb

def check_pymultitor(address='127.0.0.1', port=8080):
    s = socket.socket()
    try:
        s.connect((address, port))
        return True
    except socket.error:
        return False

def run_virustotal_updates(start_time):
    time_to_stop = start_time + timedelta(minutes=46)

    # Install pymultitor.
    commands = [
        ['pip', 'install', 'mitmproxy'],
        ['sudo', 'apt', 'install', '-y', 'tor'],
        ['pip', 'install', 'pymultitor'],
    ]

    for args in commands:
        subprocess.run(args, check=True)

    # Temporary
    shutil.copy('_pymultitor.py', '/home/travis/virtualenv/python3.8.0/lib/python3.8/site-packages/pymultitor.py')

    subprocess.Popen(['pymultitor', '--tor-timeout', '0', '--on-error-code', '429'])

    while not check_pymultitor():
        time.sleep(1)

    virustotal_path = config.out_path.joinpath('virustotal')
    files_count_before = sum(1 for x in virustotal_path.glob('*.json') if not x.name.startswith('_'))

    print('Running upd04_get_virustotal_data')
    upd04_get_virustotal_data(time_to_stop)

    files_count_after = sum(1 for x in virustotal_path.glob('*.json') if not x.name.startswith('_'))
    if files_count_before == files_count_after:
        print('No new files')
        return None

    # Empty updates file - don't handle updates, only VT.
    temp_updates_path = config.out_path.joinpath('updates.json')
    with open(temp_updates_path, 'w') as f:
        json.dump({}, f)

    print('Running upd05_group_by_filename')
    upd05_group_by_filename()

    temp_updates_path.unlink()

    return f'Updated info of {files_count_after - files_count_before} files from VirusTotal'

def run_deploy():
    start_time = datetime.now()

    tools_extracted = Path('tools.zip').is_file()
    if tools_extracted:
        with zipfile.ZipFile('tools.zip', 'r') as zip_ref:
            zip_ref.extractall('tools')

    progress_file = config.out_path.joinpath('_progress.json')
    if progress_file.is_file():
        with open(progress_file, 'r') as f:
            progress_state = json.load(f)

        progress_file.unlink()
    else:
        new_single_update = False  # prepare_updates()
        if not new_single_update:
            # No updates, try to fetch stuff from VT instead.
            return run_virustotal_updates(start_time)

        progress_state = {
            'update_kb': new_single_update,
            'files_processed': 0,
            'files_total': None
        }

    print('Running upd02_get_manifests_from_updates')
    upd02_get_manifests_from_updates()

    print('Running upd03_parse_manifests')
    upd03_parse_manifests()

    time_to_stop = start_time + timedelta(minutes=46)

    print('Running upd05_group_by_filename')
    upd05_group_by_filename(progress_state, time_to_stop)

    if progress_state['files_processed'] < progress_state['files_total']:
        with open(progress_file, 'w') as f:
            json.dump(progress_state, f, indent=4)

        return f'Updated with files from {progress_state["update_kb"]} ({progress_state["files_processed"]} of {progress_state["files_total"]})'

    assert progress_state['files_processed'] == progress_state['files_total']

    config.out_path.joinpath('updates.json').unlink()

    return f'Updated with files from {progress_state["update_kb"]}'

def can_deploy():
    # Unsupported in this flow.
    assert not config.extract_in_a_new_thread

    # Can deploy only if there's no pending PR yet.
    url = 'https://api.github.com/search/issues?q=is:pr+is:open+repo:m417z/winbindex+author:winbindex-deploy-bot'
    return requests.get(url).json()['total_count'] == 0

def commit_deploy(pr_title):
    branch_name = f'deploy-{time.time()}'

    exclude_from_commit = [
        'tools',
        'manifests',
        'parsed',
        'virustotal'
    ]

    # https://stackoverflow.com/a/51914162
    extra_commit_params = [f':!{path}/*' for path in exclude_from_commit]

    commands = [
        ['git', 'config', '--global', 'user.email', '69083578+winbindex-deploy-bot@users.noreply.github.com'],
        ['git', 'config', '--global', 'user.name', 'winbindex-deploy-bot'],
        ['git', 'checkout', '-b', branch_name],
        ['git', 'add', '-A', '--'] + extra_commit_params,
        ['git', 'commit', '-m', pr_title],
        ['git', 'remote', 'add', 'push-origin', f'https://{os.environ["GITHUB_TOKEN"]}@github.com/m417z/winbindex.git'],
        ['git', 'push', 'push-origin', branch_name],
    ]

    for args in commands:
        subprocess.run(args, check=True)

    data = {
        'title': pr_title,
        'head': branch_name,
        'base': 'gh-pages'
    }
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {os.environ["GITHUB_TOKEN"]}'
    }
    response = requests.post('https://api.github.com/repos/m417z/winbindex/pulls', data=json.dumps(data), headers=headers)
    #print(response.text)
    response.raise_for_status()

def main():
    if not can_deploy():
        print('can_deploy() returned False, exiting')
        return

    pr_title = run_deploy()
    if not pr_title:
        print('run_deploy() returned False, exiting')
        return

    commit_deploy(pr_title)
    print('Done')

if __name__ == '__main__':
    main()
