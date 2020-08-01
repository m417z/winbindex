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
