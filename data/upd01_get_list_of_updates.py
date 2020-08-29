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

    p = r'<a class="supLeftNavLink" data-bi-slot="\d+" href="(/en-us/topic/(\w+)-(\d+)-(\d+)-kb(\d+)-os-build-(\d+)-(\d+)-[^"]*)">(.*?)</a>'
    items = re.findall(p, nav_active)
    assert len(items) + 1 == len(re.findall('<a ', nav_active))

    result = []
    for item in items:
        url, month, date, year, kb_number, os1, os2, heading = item
        month_num = list(calendar.month_name).index(month.capitalize())
        full_date = f'{year}-{month_num:02}-{int(date):02}'
        update_kb = 'KB' + kb_number
        release_version = f'OS Build {os1}.{os2}'
        assert heading == f'{update_kb} ({release_version})'
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

def main():
    result = {}
    for ver in windows_versions:
        result[ver] = get_windows_version_updates(windows_versions[ver])

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(result, f, indent=4)

if __name__ == '__main__':
    main()
