import calendar
import requests
import json
import re

import config

def get_updates_from_microsoft_support():
    url = 'https://support.microsoft.com/en-us/help/4000823'
    html = requests.get(url).text

    p = (
        r'<div class="supLeftNavCategoryTitle">\s*<a [^>]*>(.*?)</a>\s*</div>\s*'
        r'<ul class="supLeftNavArticles">([\s\S]*?)</ul>'
    )
    updates_section_match = re.findall(p, html)
    assert len(updates_section_match) > 0

    # Key: URL to skip, value: URL containing the same update.
    windows_update_urls_to_skip = {
        '1511': {
            '/help/4001884': '/help/4001883',  # KB3198586
        },
        '1607': {
            '/help/4001886': '/help/4001885',  # KB3200970
        },
    }

    all_updates = {}
    for windows_version_title, updates_section in updates_section_match:
        if windows_version_title == 'Windows&#xA0;10&#xA0;(initial version released July 2015) update history':
            windows_version = '1507'
        else:
            match = re.match(r'Windows 10, version (\w+)(?:(?:, Windows Server| and Windows Server).*)? update history$', windows_version_title, re.IGNORECASE)
            windows_version = match[1]

        updates_section = re.sub(r'<a [^>]*>Windows.*? update history</a>', '', updates_section, flags=re.IGNORECASE)

        # Specific title fixes.
        if windows_version == '1709':
            updates_section = updates_section.replace('KB4509104 Update for Windows 10 Mobile  (', 'KB4509104 Update for Windows 10 Mobile (')

        if windows_version == '1607':
            updates_section = updates_section.replace(' - KB4346877', '&#x2014;KB4346877')
            updates_section = updates_section.replace('KB4025334  (', 'KB4025334 (')
            updates_section = updates_section.replace('KB 3216755', 'KB3216755')

        p = r'<a class="supLeftNavLink" data-bi-slot="\d+" href="/en-us(/help/\d+)">((\w+) (\d+), (\d+) ?(?:&#x2014;|-) ?KB(\d{7})(?: Update for Windows 10 Mobile)? \(OS Builds? .+?\).*?)</a>'
        items = re.findall(p, updates_section)
        assert len(items) == len(re.findall('<a ', updates_section))

        windows_version_updates = []
        windows_version_update_urls = []
        for item in items:
            url, heading, month, date, year, kb_number = item

            if url in windows_update_urls_to_skip.get(windows_version, {}):
                continue

            windows_version_update_urls.append(url)

            month_num = list(calendar.month_name).index(month.capitalize())
            full_date = f'{year}-{month_num:02}-{int(date):02}'
            update_kb = 'KB' + kb_number

            update_to_append = {
                'updateKb': update_kb,
                'updateUrl': 'https://support.microsoft.com' + url,
                'releaseDate': full_date,
                'heading': heading
            }

            if update_to_append in windows_version_updates:
                assert windows_version in ['1709', '1703']
                continue

            windows_version_updates.append(update_to_append)

        assert all(x in windows_version_update_urls for x in windows_update_urls_to_skip.get(windows_version, {}).values())

        all_updates[windows_version] = windows_version_updates

    return all_updates

def get_updates_from_winreleaseinfoprod():
    url = 'https://winreleaseinfoprod.blob.core.windows.net/winreleaseinfoprod/en-US.html'
    html = requests.get(url).text

    p = (
        r'<button\b[^>]*\bonclick\s*=\s*"javascript:toggleHistoryTable\(\d+\);"'
        r'[\s\S]*?'
        r'<strong>Version (\w+)(?: \(RTM\))? \(OS build \d+\)</strong>'
        r'[\s\S]*?'
        r'(<table[\s\S]*?</table>)'
    )
    updates_table_match = re.findall(p, html)
    assert len(updates_table_match) > 0

    all_updates = {}
    for windows_version, updates_table in updates_table_match:
        p = (
            r'<tr>\s*'
            r'<td>(.*?)</td>\s*'
            r'<td>(.*?)</td>\s*'
            r'<td>(.*?)</td>\s*'
            r'<td>(.*?)</td>\s*'
            r'</tr>'
        )
        update_row_match = re.findall(p, updates_table)

        windows_version_updates = []
        for os_build, availability_date, servicing_option, kb_article in update_row_match:
            if kb_article == '':
                continue

            match = re.match(r'<a href="([^"]*)"[^>]*>KB (\d+)</a>$', kb_article)
            update_kb = 'KB' + match[2]
            update_url = match[1]

            windows_version_updates.append({
                'updateKb': update_kb,
                'updateUrl': update_url,
                'releaseDate': availability_date,
                'releaseVersion': os_build
            })

        all_updates[windows_version] = windows_version_updates

    return all_updates

def windows_version_updates_sanity_check(updates):
    update_kbs = {}
    update_urls = {}
    skipped_kbs = set()

    for windows_version in updates:
        older_windows_version = config.windows_with_overlapping_updates.get(windows_version)
        older_windows_version_kbs = [x['updateKb'] for x in updates.get(older_windows_version, [])]

        for update in updates[windows_version]:
            update_kb = update['updateKb']
            if update_kb in older_windows_version_kbs:
                skipped_kbs.add(update_kb)
                continue

            update_url = update['updateUrl']

            update_kbs[update_kb] = update_kbs.get(update_kb, 0) + 1
            update_urls[update_url] = update_urls.get(update_url, 0) + 1

    # Assert no two entries with the same URL.
    assert not any(x != 1 for x in update_urls.values()), [x for x in update_urls.items() if x[1] != 1]

    # Assert no two entries with the same KB.
    assert not any(x != 1 for x in update_kbs.values()), [x for x in update_kbs.items() if x[1] != 1]

    # Make sure we don't skip extra items.
    assert all(skipped_kb in update_kbs for skipped_kb in skipped_kbs), [x for x in skipped_kbs if x not in update_kbs]

def merge_updates(updates_a, updates_b):
    for windows_version in updates_b:
        updates_a_kbs = [x['updateKb'] for x in updates_a[windows_version]]
        for update in updates_b[windows_version]:
            update_kb = update['updateKb']
            if update_kb in updates_a_kbs:
                continue

            updates_a[windows_version].append(update)

def main():
    updates_from_microsoft_support = get_updates_from_microsoft_support()
    windows_version_updates_sanity_check(updates_from_microsoft_support)

    with open(config.out_path.joinpath('updates_from_microsoft_support.json'), 'w') as f:
        json.dump(updates_from_microsoft_support, f, indent=4)

    updates_from_winreleaseinfoprod = get_updates_from_winreleaseinfoprod()
    windows_version_updates_sanity_check(updates_from_winreleaseinfoprod)

    with open(config.out_path.joinpath('updates_from_winreleaseinfoprod.json'), 'w') as f:
        json.dump(updates_from_winreleaseinfoprod, f, indent=4)

    assert updates_from_microsoft_support.keys() == updates_from_winreleaseinfoprod.keys()

    result = updates_from_microsoft_support
    merge_updates(result, updates_from_winreleaseinfoprod)
    windows_version_updates_sanity_check(result)

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(result, f, indent=4)

if __name__ == '__main__':
    main()
