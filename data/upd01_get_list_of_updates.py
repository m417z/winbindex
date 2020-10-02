import calendar
import requests
import json
import re

import config

windows_versions = {
    '2004': '4555932',
    '1909': '4529964',
    '1903': '4498140',
    '1809': '4464619',
    '1803': '4099479',
    '1709': '4043454',
    '1703': '4018124',
    '1607': '4000825',
    '1511': '4000824',
    '1507': '4000823',
}

def parse_windows_version_updates_new_format(html):
    p = r'<div class="supLeftNavCategory supLeftNavActiveCategory">[\s\S]*?<ul class="supLeftNavArticles">([\s\S]*?)</ul>\s*</div>'
    nav_active = re.findall(p, html)
    assert len(nav_active) == 1
    nav_active = nav_active[0]
    assert '<div' not in nav_active

    p = r'<a class="supLeftNavLink" data-bi-slot="\d+" href="(/en-us/help/\d+)">((\w+) (\d+), (\d+) ?&#x2014; ?KB(\d{7}) \(OS Build (\d+)\.(\d+)\))</a>'
    items = re.findall(p, nav_active)
    assert len(items) + 1 == len(re.findall('<a ', nav_active))

    result = []
    result_urls = set()
    for item in items:
        url, heading, month, date, year, kb_number, os1, os2 = item

        # Due to a bug in the 1511 update history at the time of writing this comment,
        # there are duplicate items. Insert each item only once.
        if url in result_urls:
            continue
        result_urls.add(url)

        month_num = list(calendar.month_name).index(month.capitalize())
        full_date = f'{year}-{month_num:02}-{int(date):02}'
        update_kb = 'KB' + kb_number
        release_version = f'OS Build {os1}.{os2}'
        result.append({
            'heading': heading,
            'updateKb': update_kb,
            'updateUrl': 'https://support.microsoft.com' + url,
            'releaseDate': full_date,
            'releaseVersion': release_version
        })

    return result

def get_windows_version_updates(page_id):
    url = 'https://support.microsoft.com/en-us/help/' + page_id
    html = requests.get(url).text

    p = (
        r'microsoft\.support\.prefetchedArticle = \(function\(\) \{\s*'
        r'return \{ \'en-us/' + page_id + r'\' : '
        r'(\{[\s\S]*\})'
        r'\}\s*'
        r'\}\)\(\);;'
    )
    match = re.search(p, html)
    if not match:
        return parse_windows_version_updates_new_format(html)

    data = json.loads(match.group(1))

    result = []
    updates = data['releaseNoteRelationship']['minorVersions']
    for update in updates:
        match = re.search(r'\b(KB) ?(\d+)\b', update['heading'])
        update_kb = match.group(1) + match.group(2)
        result.append({
            'heading': update['heading'],
            'updateKb': update_kb,
            'updateUrl': 'https://support.microsoft.com/en-us/help/' + update['id'],
            'releaseDate': update['releaseDate'],
            'releaseVersion': update['releaseVersion']
        })

    return result

def windows_version_updates_sanity_check(updates):
    update_kbs = {}
    update_urls = {}
    skipped_kbs = set()

    for windows_version in updates:
        if windows_version in config.windows_versions_to_skip:
            skipped_kbs.update(update['updateKb'] for update in updates[windows_version])
            continue

        for update in updates[windows_version]:
            update_kb = update['updateKb']
            update_url = update['updateUrl']
            if update_url in config.windows_update_urls_to_skip:
                skipped_kbs.add(update_kb)
                continue

            update_kbs[update_kb] = update_kbs.get(update_kb, 0) + 1
            update_urls[update_url] = update_urls.get(update_url, 0) + 1

    # Assert no two entries with the same URL.
    assert not any(x != 1 for x in update_urls.values())

    # Assert no two entries with the same KB.
    assert not any(x != 1 for x in update_kbs.values())

    # Make sure we don't skip extra items.
    assert all(skipped_kb in update_kbs for skipped_kb in skipped_kbs)

def main():
    result = {}
    for ver in windows_versions:
        result[ver] = get_windows_version_updates(windows_versions[ver])

    windows_version_updates_sanity_check(result)

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(result, f, indent=4)

if __name__ == '__main__':
    main()
