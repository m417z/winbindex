from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import requests
import inspect
import html
import json
import time
import re

from upd01_get_list_of_updates import main as upd01_get_list_of_updates
from upd02_get_manifests_from_updates import main as upd02_get_manifests_from_updates
from upd03_parse_manifests import main as upd03_parse_manifests
from upd04_get_virustotal_data import main as upd04_get_virustotal_data
from upd05_group_by_filename import main as upd05_group_by_filename
from symbol_server_link_enumerate import main as symbol_server_link_enumerate
import config

deploy_start_time = datetime.now()


def filter_updates(updates, update_kbs):
    filtered = {}
    for windows_version in updates:
        for update_kb in updates[windows_version]:
            if update_kb in update_kbs:
                updates_dict = filtered.setdefault(windows_version, {})
                updates_dict[update_kb] = updates[windows_version][update_kb]

    return filtered


def prepare_updates():
    last_time_updates_path = config.out_path.joinpath('updates_last.json')
    if last_time_updates_path.is_file():
        with open(last_time_updates_path, 'r') as f:
            last_time_updates = json.load(f)
    else:
        last_time_updates = {}

    last_time_update_kbs = {update_kb for updates in last_time_updates.values() for update_kb in updates}

    upd01_get_list_of_updates()

    temp_updates_path = config.out_path.joinpath('updates.json')
    with open(temp_updates_path, 'r') as f:
        uptodate_updates = json.load(f)

    uptodate_update_kbs = {update_kb for updates in uptodate_updates.values() for update_kb in updates}

    if config.updates_never_removed:
        assert uptodate_update_kbs >= last_time_update_kbs

    new_update_kbs = sorted(uptodate_update_kbs - last_time_update_kbs)
    if len(new_update_kbs) == 0:
        temp_updates_path.unlink()
        print('No new updates')
        return None

    print(f'New updates: {new_update_kbs}')

    # Update one at a time.
    update_kb = new_update_kbs[0]

    print(f'Updating {update_kb}')

    single_update = filter_updates(uptodate_updates, {update_kb})

    with open(temp_updates_path, 'w') as f:
        json.dump(single_update, f, indent=4)

    with open(last_time_updates_path, 'w') as f:
        last_time_updates = filter_updates(uptodate_updates, last_time_update_kbs | {update_kb})
        json.dump(last_time_updates, f, indent=4, sort_keys=True)

    return update_kb


def add_update_to_info_progress_symbol_server(update_kb):
    info_progress_symbol_server_path = config.out_path.joinpath('info_progress_symbol_server.json')
    if info_progress_symbol_server_path.is_file():
        with open(info_progress_symbol_server_path, 'r') as f:
            info_progress_symbol_server = json.load(f)
    else:
        info_progress_symbol_server = {}

    updates = info_progress_symbol_server.get('updates')
    if updates is not None:
        assert update_kb not in updates, update_kb
        updates.append(update_kb)

    info_progress_symbol_server['next'] = None

    with open(info_progress_symbol_server_path, 'w') as f:
        json.dump(info_progress_symbol_server, f, indent=0, sort_keys=True)


def run_symbol_server_updates():
    #time_to_stop = deploy_start_time + timedelta(minutes=46)  # For Travis
    time_to_stop = min(datetime.now() + timedelta(minutes=46), deploy_start_time + timedelta(hours=6, minutes=-10))  # For GitHub Actions
    if datetime.now() >= time_to_stop:
        return None

    print('Running symbol_server_link_enumerate')
    num_files = symbol_server_link_enumerate(time_to_stop)
    if num_files is None:
        return None

    return f'Updated info of {num_files} files from Microsoft Symbol Server'


def add_update_to_info_progress_virustotal(update_kb):
    info_progress_virustotal_path = config.out_path.joinpath('info_progress_virustotal.json')
    if info_progress_virustotal_path.is_file():
        with open(info_progress_virustotal_path, 'r') as f:
            info_progress_virustotal = json.load(f)
    else:
        info_progress_virustotal = {}

    updates = info_progress_virustotal.get('updates')
    if updates is None:
        updates = [update_kb]
    else:
        assert updates != []
        assert update_kb not in updates, update_kb
        updates.append(update_kb)

    info_progress_virustotal['updates'] = updates
    info_progress_virustotal['next_updates'] = None

    with open(info_progress_virustotal_path, 'w') as f:
        json.dump(info_progress_virustotal, f, indent=0, sort_keys=True)


def is_handling_update_in_info_progress_virustotal():
    info_progress_virustotal_path = config.out_path.joinpath('info_progress_virustotal.json')
    if info_progress_virustotal_path.is_file():
        with open(info_progress_virustotal_path, 'r') as f:
            info_progress_virustotal = json.load(f)
    else:
        info_progress_virustotal = {}

    updates = info_progress_virustotal.get('updates')
    if updates is None:
        return False
    else:
        assert updates != []
        return True


def check_pymultitor(proxy='http://127.0.0.1:8080'):
    try:
        url = 'http://0.0.0.0/'
        requests.get(url, proxies={'http': proxy}, timeout=30)
        return True
    except requests.exceptions.RequestException:
        return False


def run_virustotal_updates():
    #time_to_stop = deploy_start_time + timedelta(minutes=46)  # For Travis
    time_to_stop = min(datetime.now() + timedelta(minutes=46), deploy_start_time + timedelta(hours=6, minutes=-10))  # For GitHub Actions
    if datetime.now() >= time_to_stop:
        return None

    if not check_pymultitor():
        subprocess.Popen(['pymultitor', '--on-error-code', '403,429', '--tor-timeout', '0'])

        while not check_pymultitor():
            time.sleep(1)

    virustotal_path = config.out_path.joinpath('virustotal')
    files_count_before = sum(1 for x in virustotal_path.glob('*.json') if not x.name.startswith('_'))

    print('Running upd04_get_virustotal_data')
    upd04_get_virustotal_data(time_to_stop)

    files_count_after = sum(1 for x in virustotal_path.glob('*.json') if not x.name.startswith('_'))

    # Empty updates file - don't handle updates, only VT.
    temp_updates_path = config.out_path.joinpath('updates.json')
    with open(temp_updates_path, 'w') as f:
        json.dump({}, f)

    print('Running upd05_group_by_filename')
    upd05_group_by_filename()

    temp_updates_path.unlink()

    return f'Updated info of {files_count_after - files_count_before} files from VirusTotal'


def run_deploy():
    #time_to_stop = deploy_start_time + timedelta(minutes=46)  # For Travis
    time_to_stop = deploy_start_time + timedelta(hours=6, minutes=-10)  # For GitHub Actions
    if datetime.now() >= time_to_stop:
        return None

    progress_file = config.out_path.joinpath('_progress.json')
    if progress_file.is_file():
        with open(progress_file, 'r') as f:
            progress_state = json.load(f)

        progress_file.unlink()
    else:
        new_single_update = prepare_updates()
        if not new_single_update:
            # No updates, try to fetch info instead.
            result = run_symbol_server_updates()
            if result:
                return result
            else:
                return run_virustotal_updates()

        progress_state = {
            'update_kb': new_single_update,
            'files_processed': 0,
            'files_total': None
        }

    print('Running upd02_get_manifests_from_updates')
    upd02_get_manifests_from_updates()

    print('Running upd03_parse_manifests')
    upd03_parse_manifests()

    print('Running upd05_group_by_filename')
    upd05_group_by_filename(progress_state, time_to_stop)

    if progress_state['files_processed'] < progress_state['files_total']:
        with open(progress_file, 'w') as f:
            json.dump(progress_state, f, indent=4)

        return f'Updated with files from {progress_state["update_kb"]} ({progress_state["files_processed"]} of {progress_state["files_total"]})'

    assert progress_state['files_processed'] == progress_state['files_total']

    config.out_path.joinpath('updates.json').unlink()

    add_update_to_info_progress_symbol_server(progress_state['update_kb'])
    add_update_to_info_progress_virustotal(progress_state['update_kb'])

    return f'Updated with files from {progress_state["update_kb"]}'


def can_deploy():
    # Unsupported in this flow.
    assert not config.extract_in_a_new_thread

    # Can deploy only if there's no pending PR yet.
    url = 'https://api.github.com/search/issues?q=is:pr+is:open+repo:m417z/winbindex+author:winbindex-deploy-bot'
    return requests.get(url).json()['total_count'] == 0


def build_html_index_of_hashes():
    def write_html(file, html_content, title='', full_version_link='..'):
        title_full = config.index_of_hashes_title
        if title:
            title_full = f'{title} - {title_full}'

        html = inspect.cleandoc(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="description" content="An index of Windows binaries, including download links for executables such as exe, dll and sys files">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <title>{title_full}</title>
                <link rel="shortcut icon" href="favicon.ico">
                <link rel="stylesheet" href="https://winbindex.m417z.com/modules/bootstrap/css/bootstrap.min.css">
                <style>
                    p {{
                        font-family: monospace;
                        overflow-wrap: break-word;
                    }}
                </style>
            </head>
            <body class="bg-light">
                <div class="container">
                    <header class="text-center my-5">
                        <h1>{title_full}</h1>
                        <div class="text-muted text-center text-small">
                            This is a simplified version with hashes only, for
                            the full version of Winbindex, including download
                            links, click <a href="{full_version_link}">here</a>
                        </div>
                    </header>
                    {{html_content}}
                </div>
                <!-- Global site tag (gtag.js) - Google Analytics -->
                <script async src="https://www.googletagmanager.com/gtag/js?id=UA-143074342-2"></script>
                <script>
                    window.dataLayer = window.dataLayer || [];
                    function gtag(){{dataLayer.push(arguments);}}
                    gtag('js', new Date());

                    gtag('config', 'UA-143074342-2');
                </script>
            </body>
            </html>
        """).replace('{html_content}', html_content) + '\n'

        file.write(html)

    def make_hash_links(prefix_without_link=None):
        html = '<p>\n'
        for index_num in range(0x100):
            if index_num == prefix_without_link:
                html += f'<b>{index_num:02x}</b>'
            else:
                html += f'<a href="{index_num:02x}.html">{index_num:02x}</a>'

            if index_num & 0x0F == 0x0F:
                html += '<br>\n'
            else:
                html += '\n'
        html += '</p>\n'

        return html

    with open(config.out_path.joinpath('info_sources.json'), 'r') as f:
        info_sources = json.load(f)

    output_dir = config.index_of_hashes_out_path
    output_dir.mkdir(parents=True, exist_ok=True)

    html_content_main = '<h3>Hashes</h3>\n'
    html_content_main += make_hash_links()

    html_content_main += '<h3>Files</h3>\n'
    html_content_main += '<div>\n'
    for name in sorted(info_sources):
        html_content_main += f'<div><a href="{html.escape(name)}.html">{html.escape(name)}</a><div>\n'
    html_content_main += '</div>\n'

    with open(output_dir.joinpath(f'index.html'), 'w') as f:
        write_html(f, html_content_main)

    for prefix in range(0x100):
        prefix_str = f'{prefix:02x}'

        html_content = make_hash_links(prefix_without_link=prefix)

        html_content += '<div>\n'
        for name in sorted(info_sources):
            html_code_hashes = ''
            for file_hash in sorted(info_sources[name]):
                if file_hash.startswith(prefix_str):
                    html_code_hashes += '<p>' + file_hash + '\n'

            if html_code_hashes:
                html_content += f'<h3><a href="{html.escape(name)}.html">{html.escape(name)}</a></h3>\n'
                html_content += html_code_hashes
                html_content += '</p>\n'
        html_content += '</div>\n'

        with open(output_dir.joinpath(f'{prefix_str}.html'), 'w') as f:
            write_html(f, html_content, title=prefix_str)

    for name in sorted(info_sources):
        html_content = '<h3>Hashes</h3>\n'
        html_content += make_hash_links()

        html_content += f'<h3>{html.escape(name)}</h3>\n'
        html_content += '<div>\n'
        for file_hash in sorted(info_sources[name]):
            html_content += '<p>' + file_hash + '\n'
        html_content += '</p>\n'
        html_content += '</div>\n'

        with open(output_dir.joinpath(f'{html.escape(name)}.html'), 'w') as f:
            write_html(f, html_content, title=name, full_version_link=f'../?file={html.escape(name)}')


def update_readme_stats():
    with open(config.out_path.joinpath('info_sources.json'), 'r') as f:
        info_sources = json.load(f)

    files_total = 0
    files_by_status = {
        'none': 0,
        'delta': 0,
        'delta+': 0,
        'pe': 0,
        'vt': 0,
        'file': 0,
    }

    for name in info_sources:
        file_hashes = info_sources[name]
        for file_hash in file_hashes:
            file_status = file_hashes[file_hash]
            files_total += 1
            files_by_status[file_status] += 1

    stats = f'Total amount of supported PE files: {files_total:,}\n'
    stats += f'\n'
    stats += f'* No information: {files_by_status["none"]:,}\n'
    stats += f'* Delta file information (multiple links): {files_by_status["delta"]:,}\n'
    stats += f'* Delta file information: {files_by_status["delta+"]:,}\n'
    stats += f'* PE file information: {files_by_status["pe"]:,}\n'
    stats += f'* Full information (VirusTotal): {files_by_status["vt"]:,}\n'
    stats += f'* Full information (file): {files_by_status["file"]:,}\n'
    stats += f'\n'

    if files_total > 0:
        stats += f'Some stats:\n'
        stats += f'\n'

        files_with_link = files_total - files_by_status['none']
        stats += f'* {100 * files_with_link / files_total:.1f}% of files with a link\n'

        files_with_link = files_total - files_by_status['none'] - files_by_status['delta']
        stats += f'* {100 * files_with_link / files_total:.1f}% of files with a single link\n'

        files_with_full_info = files_by_status['vt'] + files_by_status['file']
        stats += f'* {100 * files_with_full_info / files_total:.1f}% of files with full information\n'

    with open(config.out_path.joinpath('README.md'), 'r') as f:
        readme = f.read()

    readme = re.sub(r'(\n<!--FileStats-->\n)[\s\S]*?\n(<!--/FileStats-->\n)', rf'\1{stats}\2', readme)

    with open(config.out_path.joinpath('README.md'), 'w') as f:
        f.write(readme)


def init_deploy():
    subprocess.check_call(['git', 'config', '--global', 'user.email', config.deploy_git_email])
    subprocess.check_call(['git', 'config', '--global', 'user.name', config.deploy_git_name])


def commit_deploy(pr_title):
    # Make sure no accidental changes in the main repo.
    # https://stackoverflow.com/a/25149786
    status = subprocess.check_output(['git', 'status', '--porcelain'], text=True)
    if status:
        raise Exception(f'Non-empty status:\n{status}')

    git_cmd = ['git', '-C', config.out_path]

    subprocess.check_call(git_cmd + ['add', '-A'])

    # https://stackoverflow.com/a/2659808
    result = subprocess.run(git_cmd + ['diff-index', '--quiet', '--cached', 'HEAD'])
    if result.returncode == 0:
        print('No changes to commit')
        return

    amend_last_commit = False
    if config.deploy_amend_last_commit:
        commit_count = int(subprocess.check_output(git_cmd + ['rev-list', '--count', 'HEAD'], text=True).rstrip('\n'))
        if commit_count > 1:
            amend_last_commit = True

    if amend_last_commit:
        last_commit_body = subprocess.check_output(git_cmd + ['log', '--format=%B', '-n1'], text=True)
        current_time_iso = datetime.now().isoformat(timespec='seconds').replace('T', ' ')
        new_body = f'[{current_time_iso}] {pr_title}\n\n{last_commit_body}'
        subprocess.check_call(git_cmd + ['commit', '--amend', '-m', new_body])
        subprocess.check_call(git_cmd + ['push', '--force-with-lease'])

        # Free disk space by removing old objects.
        subprocess.check_call(git_cmd + ['reflog', 'expire', '--expire=all', '--all'])

        # Use `git prune` instead of `git gc --prune=now` to hopefully prevent
        # out-of-disk errors: https://stackoverflow.com/a/47890963
        subprocess.check_call(git_cmd + ['prune'])
    else:
        subprocess.check_call(git_cmd + ['commit', '-m', pr_title])
        subprocess.check_call(git_cmd + ['push'])


def clean_deploy_files():
    git_cmd = ['git', '-C', config.out_path]

    subprocess.check_call(git_cmd + ['clean', '-fdx'])


def main():
    if not can_deploy():
        print('can_deploy() returned False, exiting')
        return

    init_deploy()

    while True:
        pr_title = run_deploy()
        if not pr_title:
            print('run_deploy() returned None, exiting')
            return

        build_html_index_of_hashes()

        update_readme_stats()

        commit_deploy(pr_title)

        # Stop once we get non-update files from VirusTotal. Otherwise, continue
        # as long as there are other tasks.
        match = re.match(r'Updated info of (\d+) files from VirusTotal$', pr_title)
        if match and not is_handling_update_in_info_progress_virustotal():
            print('Done')
            return

        clean_deploy_files()


if __name__ == '__main__':
    main()
