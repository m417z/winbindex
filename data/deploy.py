from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import requests
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
    with open(config.out_path.joinpath('info_sources.json'), 'r') as f:
        info_sources = json.load(f)

    output_dir = config.index_of_hashes_out_path
    output_dir.mkdir(parents=True, exist_ok=True)

    for prefix in range(0x100):
        prefix_str = f'{prefix:02x}'

        html_code_start = (
            '<!DOCTYPE html>\n'
            '<html>\n'
            '<head>\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">\n'
            f'<title>{prefix_str} - Winbindex hashes</title>\n'
            '<style>\n'
            '/* stolen from thebestmotherfucking.website */\n'
            'body{font-family:Open Sans,Arial;color:#454545;font-size:16px;margin:2em auto;max-width:800px;padding:1em;line-height:1.4;text-align:justify}html.contrast body{color:#050505}html.contrast blockquote{color:#11151a}html.contrast blockquote:before{color:#262626}html.contrast a{color:#0051c9}html.contrast a:visited{color:#7d013e}html.contrast span.wr{color:#800}html.contrast span.mfw{color:#4d0000}@media screen and (prefers-color-scheme:light){html.inverted{background-color:#000}html.inverted body{color:#d9d9d9}html.inverted div#contrast,html.inverted div#invmode{color:#fff;background-color:#000}html.inverted blockquote{color:#d3c9be}html.inverted blockquote:before{color:#b8b8b8}html.inverted a{color:#00a2e7}html.inverted a:visited{color:#ca1a70}html.inverted span.wr{color:#d24637}html.inverted span.mfw{color:#b00000}html.inverted.contrast{background-color:#000}html.inverted.contrast body{color:#fff}html.inverted.contrast div#contrast,html.inverted.contrast div#invmode{color:#fff;background-color:#000}html.inverted.contrast blockquote{color:#f8f6f5}html.inverted.contrast blockquote:before{color:#e5e5e5}html.inverted.contrast a{color:#44c7ff}html.inverted.contrast a:visited{color:#e9579e}html.inverted.contrast span.wr{color:#db695d}html.inverted.contrast span.mfw{color:#ff0d0d}}@media (prefers-color-scheme:dark){html:not(.inverted){background-color:#000}html:not(.inverted) body{color:#d9d9d9}html:not(.inverted) div#contrast,html:not(.inverted) div#invmode{color:#fff;background-color:#000}html:not(.inverted) blockquote{color:#d3c9be}html:not(.inverted) blockquote:before{color:#b8b8b8}html:not(.inverted) a{color:#00a2e7}html:not(.inverted) a:visited{color:#ca1a70}html:not(.inverted) span.wr{color:#d24637}html:not(.inverted) span.mfw{color:#b00000}html:not(.inverted).contrast{background-color:#000}html:not(.inverted).contrast body{color:#fff}html:not(.inverted).contrast div#contrast,html:not(.inverted).contrast div#invmode{color:#fff;background-color:#000}html:not(.inverted).contrast blockquote{color:#f8f6f5}html:not(.inverted).contrast blockquote:before{color:#e5e5e5}html:not(.inverted).contrast a{color:#44c7ff}html:not(.inverted).contrast a:visited{color:#e9579e}html:not(.inverted).contrast span.wr{color:#db695d}html:not(.inverted).contrast span.mfw{color:#ff0d0d}html.inverted html{background-color:#fefefe}}a{color:#07a}a:visited{color:#941352}.noselect{-webkit-touch-callout:none;-webkit-user-select:none;-khtml-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none}span.citneed{vertical-align:top;font-size:.7em;padding-left:.3em}small{font-size:.4em}p.st{margin-top:-1em}div.fancyPositioning div.picture-left{float:left;width:40%;overflow:hidden;margin-right:1em}div.fancyPositioning div.picture-left img{width:100%}div.fancyPositioning div.picture-left figure{margin:10px}div.fancyPositioning div.picture-left figure figcaption{font-size:.7em}div.fancyPositioning div.tleft{float:left;width:55%}div.fancyPositioning div.tleft p:first-child{margin-top:0}div.fancyPositioning:after{display:block;content:"";clear:both}ul li img{height:1em}blockquote{color:#456;margin-left:0;margin-top:2em;margin-bottom:2em}blockquote span{float:left;margin-left:1rem;padding-top:1rem}blockquote author{display:block;clear:both;font-size:.6em;margin-left:2.4rem;font-style:oblique}blockquote author:before{content:"- ";margin-right:1em}blockquote:before{font-family:Times New Roman,Times,Arial;color:#666;content:open-quote;font-size:2.2em;font-weight:600;float:left;margin-top:0;margin-right:.2rem;width:1.2rem}blockquote:after{content:"";display:block;clear:both}@media screen and (max-width:500px){body{text-align:left}div.fancyPositioning div.picture-left,div.fancyPositioning div.tleft{float:none;width:inherit}blockquote span{width:80%}blockquote author{padding-top:1em;width:80%;margin-left:15%}blockquote author:before{content:"";margin-right:inherit}}span.visited{color:#941352}span.visited-maroon{color:#85144b}span.wr{color:#c0392b;font-weight:600;text-decoration:underline}div#contrast{color:#000;top:10px}div#contrast,div#invmode{cursor:pointer;position:fixed;right:10px;font-size:.8em;text-decoration:underline;-webkit-touch-callout:none;-webkit-user-select:none;-khtml-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none}div#invmode{color:#fff;background-color:#000;top:34px;padding:2px 5px}@media screen and (max-width:1080px){div#contrast,div#invmode{position:absolute}}span.sb{color:#00e}span.sb,span.sv{cursor:not-allowed}span.sv{color:#551a8b}span.foufoufou{color:#444;font-weight:700}span.foufoufou:before{content:"";display:inline-block;width:1em;height:1em;margin-left:.2em;margin-right:.2em;background-color:#444}span.foufivfoufivfoufiv{color:#454545;font-weight:700}span.foufivfoufivfoufiv:before{content:"";display:inline-block;width:1em;height:1em;margin-left:.2em;margin-right:.2em;background-color:#454545}span.mfw{color:#730000}a.kopimi,a.kopimi img.kopimi{display:block;margin-left:auto;margin-right:auto}a.kopimi img.kopimi{height:2em}p.fakepre{font-family:monospace;font-size:.9em}\n'
            '/* More styles */\n'
            'p{font-family:monospace}\n'
            '</style>\n'
            '</head>\n'
            '<body>\n'
            f'<h1>{prefix_str} - Winbindex hashes</h1>\n'
        )

        html_code_end = (
            '<!-- Global site tag (gtag.js) - Google Analytics -->\n'
            '<script async src="https://www.googletagmanager.com/gtag/js?id=UA-143074342-2"></script>\n'
            '<script>\n'
            '    window.dataLayer = window.dataLayer || [];\n'
            '    function gtag(){dataLayer.push(arguments);}\n'
            '    gtag(\'js\', new Date());\n'
            '\n'
            '    gtag(\'config\', \'UA-143074342-2\');\n'
            '</script>\n'
            '</body>\n'
            '</html>\n'
        )

        html_code_index = '<p>\n'
        for index_num in range(0x100):
            if index_num != prefix:
                html_code_index += f'<a href="{index_num:02x}.html">{index_num:02x}</a>'
            else:
                html_code_index += f'<b>{index_num:02x}</b>'

            if index_num & 0x0F == 0x0F:
                html_code_index += '<br>\n'
            else:
                html_code_index += '\n'
        html_code_index += '</p>\n'

        html_code_main = '<div>\n'
        for name in sorted(info_sources):
            html_code_hashes = ''
            for file_hash in sorted(info_sources[name]):
                if file_hash.startswith(prefix_str):
                    html_code_hashes += '<p>' + file_hash + '\n'

            if html_code_hashes:
                html_code_main += f'<h3><a href="..?file={html.escape(name)}">{html.escape(name)}</a></h3>\n'
                html_code_main += html_code_hashes
                html_code_main += '</p>\n'
        html_code_main += '</div>\n'

        html_code = html_code_start + html_code_index + html_code_main + html_code_end
        with open(output_dir.joinpath(f'{prefix_str}.html'), 'w') as f:
            f.write(html_code)


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
