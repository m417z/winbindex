from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import requests
import zipfile
import shutil
import json
import time
import os

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
    with open(config.out_path.joinpath('updates.json')) as f:
        last_time_updates = json.load(f)

    last_time_update_kbs = {item['updateKb'] for items in last_time_updates.values() for item in items}

    upd01_get_list_of_updates()

    with open(config.out_path.joinpath('updates.json')) as f:
        uptodate_updates = json.load(f)

    uptodate_update_kbs = {item['updateKb'] for items in uptodate_updates.values() for item in items}

    if last_time_update_kbs == uptodate_update_kbs:
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

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(single_update, f, indent=4)

    return update_kb, filter_updates(uptodate_updates, last_time_update_kbs | {update_kb})

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
    else:
        result = prepare_updates()
        if not result:
            return False

        new_single_update, new_updates = result

        progress_state = {
            'update_kb': new_single_update,
            'new_updates': new_updates,
            'files_processed': 0,
            'files_total': None,
            'done': False
        }

    print('Running upd02_get_manifests_from_updates')
    upd02_get_manifests_from_updates()

    print('Running upd03_parse_manifests')
    upd03_parse_manifests()

    #print('Running upd04_get_virustotal_data')
    #upd04_get_virustotal_data()

    progress_state['time_to_stop'] = start_time + timedelta(minutes=46)

    print('Running upd05_group_by_filename')
    upd05_group_by_filename(progress_state)

    del progress_state['time_to_stop']

    shutil.rmtree(config.out_path.joinpath('manifests'))
    shutil.rmtree(config.out_path.joinpath('parsed'))
    if tools_extracted:
        shutil.rmtree(config.out_path.joinpath('tools'))

    if not progress_state['done']:
        with open(progress_file, 'w') as f:
            json.dump(progress_state, f, indent=4)

        return f'Updated with files from {new_single_update} ({progress_state["files_processed"]} of {progress_state["files_total"]})'

    progress_file.unlink()

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(progress_state['new_updates'], f, indent=4)

    return f'Updated with files from {new_single_update}'

def can_deploy():
    # Unsupported in this flow.
    assert not config.extract_in_a_new_thread

    # Can deploy only if there's no pending PR yet.
    url = 'https://api.github.com/search/issues?q=is:pr+is:open+repo:m417z/winbindex+author:winbindex-deploy-bot'
    return requests.get(url).json()['total_count'] == 0

def commit_deploy(pr_title):
    branch_name = f'deploy-{time.time()}'

    commands = [
        ['git', 'config', '--global', 'user.email', 'winbindex-deploy-bot@m417z.com'],
        ['git', 'config', '--global', 'user.name', 'winbindex-deploy-bot'],
        ['git', 'checkout', '-b', branch_name],
        ['git', 'add', '-A'],
        ['git', 'commit', '-m', pr_title],
        ['git', 'remote', 'add', 'push-origin', f'https://{os.environ["GITHUB_TOKEN"]}@github.com/m417z/winbindex.git'],
        ['git', 'push', 'push-origin', branch_name],
    ]

    for args in commands:
        subprocess.run(args, check=True)

    data = {
        'title': pr_title,
        'head': f'winbindex-deploy-bot:{branch_name}',
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
