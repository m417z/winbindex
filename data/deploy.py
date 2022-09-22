from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import requests
import shutil
import html
import json
import time
import os
import re

from upd01_get_list_of_updates import main as upd01_get_list_of_updates
from upd02_get_manifests_from_updates import main as upd02_get_manifests_from_updates
from upd03_parse_manifests import main as upd03_parse_manifests
from upd04_get_virustotal_data import main as upd04_get_virustotal_data
from upd05_group_by_filename import main as upd05_group_by_filename
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
        json.dump(last_time_updates, f, indent=4, sort_keys=True)

    return update_kb


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
            # No updates, try to fetch stuff from VT instead.
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

    return f'Updated with files from {progress_state["update_kb"]}'


def can_deploy():
    # Unsupported in this flow.
    assert not config.extract_in_a_new_thread

    # Can deploy only if there's no pending PR yet.
    url = 'https://api.github.com/search/issues?q=is:pr+is:open+repo:m417z/winbindex+author:winbindex-deploy-bot'
    return requests.get(url).json()['total_count'] == 0


def build_html_index_of_hashes():
    with open('info_sources.json', 'r') as f:
        info_sources = json.load(f)

    output_dir = Path('..').joinpath('hashes')
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
        with output_dir.joinpath(f'{prefix_str}.html').open('w') as f:
            f.write(html_code)


def update_readme_stats():
    with open('info_sources.json', 'r') as f:
        info_sources = json.load(f)

    files_total = 0
    files_by_status = {
        'none': 0,
        'novt': 0,
        'vt': 0,
        'file': 0,
    }

    for name in info_sources:
        file_hashes = info_sources[name]
        for file_hash in file_hashes:
            file_status = file_hashes[file_hash]
            files_total += 1
            files_by_status[file_status] += 1

    files_with_link = files_by_status['file'] + files_by_status['vt']
    files_without_link = files_by_status['novt'] + files_by_status['none']

    stats = f'Total amount of supported PE files: {files_total:,}  \n'
    stats += f'Files with full information: {files_with_link:,} ({files_by_status["file"]:,} from the actual files, {files_by_status["vt"]:,} from VirusTotal)  \n'
    stats += f'Files with partial information: {files_without_link:,} ({files_by_status["novt"]:,} weren\'t uploaded to VirusTotal, {files_by_status["none"]:,} weren\'t checked yet)  \n'

    if files_with_link + files_without_link > 0:
        stats += f'% of files with full information: {100 * files_with_link / (files_with_link + files_without_link):.1f}  \n'

    with open('README.md', 'r') as f:
        readme = f.read()

    readme = re.sub(r'(\n<!--FileStats-->\n)[\s\S]*?\n(<!--/FileStats-->\n)', rf'\1{stats}\2', readme)

    with open('README.md', 'w') as f:
        f.write(readme)


def init_deploy():
    args = ['git', 'remote', 'add', 'push-origin', f'https://{os.environ["GITHUB_TOKEN"]}@github.com/{os.environ["GITHUB_REPOSITORY"]}.git']
    subprocess.run(args, check=True)


def commit_deploy(pr_title):
    git_email = '69083578+winbindex-deploy-bot@users.noreply.github.com'
    git_name = 'winbindex-deploy-bot'

    exclude_from_commit = [
        'tools',
        'manifests',
        'parsed',
        'virustotal'
    ]

    # https://stackoverflow.com/a/51914162
    extra_commit_params = [f':!{path}/*' for path in exclude_from_commit]

    commit_directly = True  # pr_title.endswith('files from VirusTotal')
    if commit_directly:
        branch_name = 'gh-pages'
        checkout_params = [branch_name]
    else:
        branch_name = f'deploy-{time.time()}'
        checkout_params = ['-b', branch_name]

    commands = [
        ['git', 'config', '--global', 'user.email', git_email],
        ['git', 'config', '--global', 'user.name', git_name],
        ['git', 'checkout'] + checkout_params,
        ['git', 'add', '-A', '--'] + extra_commit_params,
        ['git', 'commit', '-m', pr_title],
        ['git', 'push', 'push-origin', branch_name],
    ]

    for args in commands:
        subprocess.run(args, check=True)

    if not commit_directly:
        data = {
            'title': pr_title,
            'head': branch_name,
            'base': 'gh-pages'
        }
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {os.environ["GITHUB_TOKEN"]}'
        }
        response = requests.post('https://api.github.com/repos/{os.environ["GITHUB_REPOSITORY"]}/pulls', data=json.dumps(data), headers=headers)
        #print(response.text)
        response.raise_for_status()


def clean_deploy_files():
    # Remove files that take a lot of space and are no longer needed.
    p = config.out_path.joinpath('manifests')
    if p.exists():
        shutil.rmtree(p)

    p = config.out_path.joinpath('parsed')
    if p.exists():
        shutil.rmtree(p)


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

        # Stop once we got less than 100 files from VirusTotal.
        # Otherwise, continue as long as there are new updates.
        match = re.match(r'Updated info of (\d+) files from VirusTotal$', pr_title)
        if match and int(match.group(1)) < 100:
            print('Done')
            return

        clean_deploy_files()


if __name__ == '__main__':
    main()
