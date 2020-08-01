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

    print(f'New updates: {uptodate_update_kbs - last_time_update_kbs}')

    # Update one at a time.
    update_kb = sorted(uptodate_update_kbs - last_time_update_kbs)[0]

    print(f'Updating {update_kb}')

    single_update = filter_updates(uptodate_updates, {update_kb})

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(single_update, f, indent=4)

    return single_update, filter_updates(uptodate_updates, last_time_update_kbs | {update_kb})

def run_deploy():
    with zipfile.ZipFile('tools.zip', 'r') as zip_ref:
        zip_ref.extractall('tools')

    result = prepare_updates()
    if not result:
        return False

    new_single_update, new_updates = result

    print('Running upd02_get_manifests_from_updates')
    upd02_get_manifests_from_updates()

    print('Running upd03_parse_manifests')
    upd03_parse_manifests()

    #print('Running upd04_get_virustotal_data')
    #upd04_get_virustotal_data()

    print('Running upd05_group_by_filename')
    upd05_group_by_filename()

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(new_updates, f, indent=4)

    shutil.rmtree(config.out_path.joinpath('tools'))
    shutil.rmtree(config.out_path.joinpath('manifests'))
    shutil.rmtree(config.out_path.joinpath('parsed'))

    return f'Updated with files from {new_single_update}'

def can_deploy():
    # Can deploy only if there's no pending PR yet.
    #url = 'https://api.github.com/search/issues?q=is:pr+repo:m417z/winbindex+author:winbindex-deploy-bot'
    url = 'https://api.github.com/search/issues?q=is:pr+repo:m417z/winbindex+author:m417z'
    return requests.get(url).json()['total_count'] == 0

def commit_deploy(pr_title):
    branch_name = f'deploy-{time.time()}'

    commands = [
        ['git', 'config', '--global', 'user.email', 'winbindex-deploy-bot@m417z.com'],
        ['git', 'config', '--global', 'user.name', 'winbindex-deploy-bot'],
        ['git', 'checkout', '-b', branch_name],
        ['git', 'add', '-A'],
        ['git', 'commit', '-m', pr_title],
        ['git', 'remote', 'add', 'push-origin', f'https://{os.environ["GITHUB_TOKEN_TEMP"]}@github.com/m417z/winbindex.git'],
        ['git', 'push', 'push-origin', branch_name],
    ]

    for args in commands:
        subprocess.run(args, check=True)

    data = {
        'title': pr_title,
        'head': branch_name,
        'base': 'master'
    }
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {os.environ["GITHUB_TOKEN_TEMP"]}'
    }
    response = requests.post('https://api.github.com/repos/m417z/winbindex/pulls', data=json.dumps(data), headers=headers)
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
