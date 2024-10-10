import calendar
import requests
import json
import time
import re

import config


def consolidate_overlapping_updates(updates):
    seen_kbs = {}
    for windows_version in sorted(updates.keys()):
        for update_kb in list(updates[windows_version]):
            update = updates[windows_version][update_kb]

            if update_kb in seen_kbs:
                seen_windows_version, seen_update = seen_kbs[update_kb]

                assert (seen_windows_version, windows_version) in [
                    ('1903', '1909'),
                    ('2004', '20H2'),
                    ('2004', '21H1'),
                    ('2004', '21H2'),
                    ('20H2', '21H1'),
                    ('20H2', '21H2'),
                    ('20H2', '22H2'),
                    ('21H2', '22H2'),
                    ('11-22H2', '11-23H2'),
                ], (update_kb, seen_windows_version, windows_version)

                assert update['updateUrl'] == seen_update['updateUrl']
                if update_kb not in ['KB5003173']:  # KB5003173 was released later for 21H1
                    assert update['releaseDate'] == seen_update['releaseDate']
                p = r'^\d+\.'
                assert re.sub(p, '', update['releaseVersion']) == re.sub(p, '', seen_update['releaseVersion'])

                if 'otherWindowsVersions' not in seen_update:
                    seen_update['otherWindowsVersions'] = []

                assert windows_version not in seen_update['otherWindowsVersions']
                seen_update['otherWindowsVersions'].append(windows_version)

                del updates[windows_version][update_kb]
                continue

            seen_kbs[update_kb] = windows_version, update

    for windows_version in list(updates.keys()):
        if len(updates[windows_version]) == 0:
            del updates[windows_version]


def get_updates_from_microsoft_support_for_version(windows_major_version, url):
    while True:
        try:
            request = requests.get(url)
            request.raise_for_status()
            break
        except Exception as e:
            print(f'Failed to get {url}, retrying...')
            print(f'       {e}')
            time.sleep(10)

    html = request.text

    p = (
        r'<div [^>]*\bid="supLeftNav"[^>]*>'
        r'([\s\S]*?)'
        r'</div>\s*'
        r'<main [^>]*\bid="supArticleContent"[^>]*>'
    )
    updates_navigation_links = re.findall(p, html)
    assert len(updates_navigation_links) == 1
    updates_navigation_links = updates_navigation_links[0]

    p = (
        r'<div class="supLeftNavCategoryTitle">\s*<a [^>]*>(.*?)</a>\s*</div>\s*'
        r'<ul class="supLeftNavArticles">([\s\S]*?)</ul>'
    )
    updates_section_match = re.findall(p, updates_navigation_links)
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
        if windows_major_version == 10:
            if windows_version_title == 'Windows&#xA0;10&#xA0;(initial version released July 2015) update history':
                windows_version = '1507'
            else:
                match = re.match(r'Windows 10, version (\w+)(?:(?:, Windows Server| and Windows Server).*)? update history$', windows_version_title, re.IGNORECASE)
                windows_version = match[1]
        else:
            assert windows_major_version == 11
            if windows_version_title == 'Windows 11, version 21H2':
                windows_version = '11-21H2'
            else:
                match = re.match(r'Windows 11, version (\w+)$', windows_version_title, re.IGNORECASE)
                windows_version = '11-' + match[1]

        assert windows_version not in all_updates

        # Specific title fixes.
        if windows_version in ['21H2', '21H1', '20H2']:
            updates_section = updates_section.replace('KB5012599(OS Builds', 'KB5012599 (OS Builds')

        if windows_version == '1809':
            updates_section = updates_section.replace('(OS Build OS 17763.529)', '(OS Build 17763.529)')
            updates_section = updates_section.replace('KB5012647(OS Build', 'KB5012647 (OS Build')

        if windows_version == '1709':
            updates_section = updates_section.replace('KB4509104 Update for Windows 10 Mobile  (', 'KB4509104 Update for Windows 10 Mobile (')

        if windows_version == '1607':
            updates_section = updates_section.replace(' - KB4346877', '&#x2014;KB4346877')
            updates_section = updates_section.replace('KB4025334  (', 'KB4025334 (')
            updates_section = updates_section.replace('KB 3216755', 'KB3216755')

        updates_section = re.sub(r'<a [^>]*>Windows.*? update history</a>', '', updates_section, flags=re.IGNORECASE)
        updates_section = re.sub(r'<a [^>]*>End of service statement</a>', '', updates_section, flags=re.IGNORECASE)
        updates_section = re.sub(r'<a [^>]*>Windows 11, version \w+\s*</a>', '', updates_section, flags=re.IGNORECASE)

        p = r'<a class="supLeftNavLink" data-bi-slot="\d+" href="/en-us(/help/\d+)">((\w+) (\d+), (\d+) ?(?:&#x2014;|-) ?KB(\d{7})(?: Update for Windows 10 Mobile)? \(OS Builds? .+?\).*?)</a>'
        items = re.findall(p, updates_section)
        assert len(items) == len(re.findall('<a ', updates_section))

        windows_version_updates = {}
        windows_version_update_urls = []
        for item in items:
            url, heading, month, date, year, kb_number = item

            if url in windows_update_urls_to_skip.get(windows_version, {}):
                continue

            windows_version_update_urls.append(url)

            month_num = list(calendar.month_name).index(month.capitalize())
            full_date = f'{year}-{month_num:02}-{int(date):02}'
            update_kb = 'KB' + kb_number

            match = re.search(r'\(OS Builds? ([\d\.]+)', heading)
            os_build = match[1]

            update_to_append = {
                'updateUrl': 'https://support.microsoft.com' + url,
                'releaseDate': full_date,
                'releaseVersion': os_build,
                'heading': heading
            }

            if update_kb in windows_version_updates:
                assert windows_version in ['1709', '1703']
                assert windows_version_updates[update_kb] == update_to_append
                continue

            windows_version_updates[update_kb] = update_to_append

        assert all(x in windows_version_update_urls for x in windows_update_urls_to_skip.get(windows_version, {}).values())

        # A temporary fix for missing entries in the Microsoft website's sidebar.
        if windows_version == '1709' and 'KB4341235' not in windows_version_updates:
            windows_version_updates['KB4341235'] = {
                "heading": "July 10, 2018&#x2014;KB4341235 Update for Windows 10 Mobile (OS Build 15254.490)",
                "releaseDate": "2018-07-10",
                "releaseVersion": "15254.490",
                "updateUrl": "https://support.microsoft.com/help/4341235"
            }
        elif windows_version == '11-22H2' and 'KB5019311' not in windows_version_updates:
            windows_version_updates['KB5019311'] = {
                "heading": "September 27, 2022&#x2014;KB5019311 (OS Build 22621.525) Out-of-band",
                "releaseDate": "2022-09-27",
                "releaseVersion": "22621.525",
                "updateUrl": "https://support.microsoft.com/help/5019311"
            }

        all_updates[windows_version] = windows_version_updates

    return all_updates


def get_updates_from_microsoft_support():
    win10_updates = get_updates_from_microsoft_support_for_version(10, 'https://support.microsoft.com/en-us/help/4000823')
    win11_updates = get_updates_from_microsoft_support_for_version(11, 'https://support.microsoft.com/en-us/help/5006099')
    return {**win10_updates, **win11_updates}


def get_updates_from_release_health_for_version(windows_major_version, url):
    while True:
        try:
            request = requests.get(url)
            request.raise_for_status()
            break
        except Exception as e:
            print(f'Failed to get {url}, retrying...')
            print(f'       {e}')
            time.sleep(10)

    html = request.text

    p = (
        r'<strong>Version (\w+)(?: \(RTM\)| \(original release\))? \(OS build \d+\)</strong>'
        r'[\s\S]*?'
        r'(<table[\s\S]*?</table>)'
    )
    updates_table_match = re.findall(p, html)
    assert len(updates_table_match) > 0

    all_updates = {}
    for windows_version_title, updates_table in updates_table_match:
        if windows_major_version == 10:
            windows_version = windows_version_title
        else:
            windows_version = f'{windows_major_version}-{windows_version_title}'

        assert windows_version not in all_updates

        p = (
            r'<tr>\s*'
            r'<td>(.*?)</td>\s*'
            r'<td>(.*?)</td>\s*'
            r'<td>(.*?)</td>\s*'
            r'<td>(.*?)</td>\s*'
            r'</tr>'
        )
        update_row_match = re.findall(p, updates_table)

        windows_version_updates = {}
        for servicing_option, availability_date, os_build, kb_article in update_row_match:
            if kb_article == '':
                continue

            match = re.match(r'<a href="([^"]*)"[^>]*>KB(\d+)</a>$', kb_article)
            update_kb = 'KB' + match[2]
            update_url = match[1]

            # Adjust date to fix an inconsistency.
            if windows_version == '11-22H2' and update_kb == 'KB5031455':
                assert availability_date == '2023-10-26'
                availability_date = '2023-10-31'

            windows_version_updates[update_kb] = {
                'updateUrl': update_url,
                'releaseDate': availability_date,
                'releaseVersion': os_build
            }

        if len(windows_version_updates) > 0:
            all_updates[windows_version] = windows_version_updates

    return all_updates


def get_updates_from_release_health():
    win10_updates = get_updates_from_release_health_for_version(10, 'https://docs.microsoft.com/en-us/windows/release-health/release-information')
    win11_updates = get_updates_from_release_health_for_version(11, 'https://docs.microsoft.com/en-us/windows/release-health/windows11-release-information')
    return {**win10_updates, **win11_updates}


def windows_version_updates_sanity_check(updates):
    update_kbs = {}
    update_urls = {}

    for windows_version in updates:
        for update_kb in updates[windows_version]:
            update = updates[windows_version][update_kb]
            update_url = update['updateUrl']

            update_kbs[update_kb] = update_kbs.get(update_kb, 0) + 1
            update_urls[update_url] = update_urls.get(update_url, 0) + 1

    # Assert no two entries with the same URL.
    assert not any(x != 1 for x in update_urls.values()), [x for x in update_urls.items() if x[1] != 1]

    # Assert no two entries with the same KB.
    assert not any(x != 1 for x in update_kbs.values()), [x for x in update_kbs.items() if x[1] != 1]


def merge_updates(updates_a, updates_b):
    for windows_version in updates_b:
        for update_kb in updates_b[windows_version]:
            if update_kb not in updates_a[windows_version]:
                updates_a[windows_version][update_kb] = updates_b[windows_version][update_kb]


def main():
    updates_from_microsoft_support = get_updates_from_microsoft_support()
    consolidate_overlapping_updates(updates_from_microsoft_support)
    windows_version_updates_sanity_check(updates_from_microsoft_support)

    updates_from_release_health = get_updates_from_release_health()
    consolidate_overlapping_updates(updates_from_release_health)
    windows_version_updates_sanity_check(updates_from_release_health)

    assert updates_from_microsoft_support.keys() == updates_from_release_health.keys() | {
        # Temporarily (?) missing in Release Health.
        '11-24H2',
    }

    result = updates_from_microsoft_support
    merge_updates(result, updates_from_release_health)
    windows_version_updates_sanity_check(result)

    for windows_version, from_date in config.windows_versions_unsupported.items():
        if windows_version not in result:
            continue

        new_windows_version_result = {
            k: v
            for k, v in result[windows_version].items()
            if from_date is not None and v['releaseDate'] < from_date
        }

        if new_windows_version_result:
            result[windows_version] = new_windows_version_result
        else:
            del result[windows_version]

    with open(config.out_path.joinpath('updates.json'), 'w') as f:
        json.dump(result, f, indent=4, sort_keys=True)


if __name__ == '__main__':
    main()
