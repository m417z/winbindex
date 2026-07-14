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
                    ('11-24H2', '11-25H2'),
                ], (update_kb, seen_windows_version, windows_version)

                assert update['updateUrl'] == seen_update['updateUrl']
                if update_kb not in [
                    # Different release dates:
                    # - 2004, 20H2: 2021-05-11
                    # - 21H1: 2021-05-18
                    'KB5003173',
                ]:
                    assert update['releaseDate'] == seen_update['releaseDate']
                p = r'^\d+\.'
                assert re.sub(p, '', update['releaseVersion']) == re.sub(p, '', seen_update['releaseVersion']), (
                    update_kb, update['releaseVersion'], seen_update['releaseVersion']
                )

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


def get_updates_from_microsoft_support_for_version(windows_major_version, url, page_format):
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

    # The support pages exist in two layouts, selected by page_format: 'new' uses
    # 'learnRender*' class names for the left navigation and slug-based article URLs,
    # 'old' uses 'sup*' names and '/help/<id>' URLs.
    if page_format == 'new':
        navigation_p = (
            r'<div [^>]*\bid="learnRenderLeftNav"[^>]*>'
            r'([\s\S]*?)'
            r'<main [^>]*\bid="supMainContent"[^>]*>'
        )
        section_p = (
            r'<div class="learnRenderLeftNavCategoryTitle">\s*<a [^>]*>(.*?)</a>\s*</div>\s*'
            r'<ul class="learnRenderLeftNavArticles[^"]*">([\s\S]*?)</ul>'
        )
        item_anchor_p = r'<a href="([^"]*)" class="learnRenderLeftNavLink" data-bi-slot="\d+"[^>]*>'
        # Key: URL to skip, value: URL containing the same update.
        windows_update_urls_to_skip = {
            '1511': {
                '../../2016/11/november-14-2016-kb3198586-os-build-10586-682':
                    '../../2016/11/november-8-2016-kb3198586-os-build-10586-679',  # KB3198586
            },
            '1607': {
                '../../2016/11/november-9-2016-kb3200970-os-build-14393-448':
                    '../../2016/11/november-8-2016-kb3200970-os-build-14393-447',  # KB3200970
            },
        }
    elif page_format == 'old':
        navigation_p = (
            r'<div [^>]*\bid="supLeftNav"[^>]*>'
            r'([\s\S]*?)'
            r'</div>\s*'
            r'<main [^>]*\bid="supArticleContent"[^>]*>'
        )
        section_p = (
            r'<div class="supLeftNavCategoryTitle">\s*<a [^>]*>(.*?)</a>\s*</div>\s*'
            r'<ul class="supLeftNavArticles">([\s\S]*?)</ul>'
        )
        item_anchor_p = r'<a class="supLeftNavLink" data-bi-slot="\d+"[^>]* href="/en-us(/help/\d+)">'
        # Key: URL to skip, value: URL containing the same update.
        windows_update_urls_to_skip = {
            '1511': {
                '/help/4001884': '/help/4001883',  # KB3198586
            },
            '1607': {
                '/help/4001886': '/help/4001885',  # KB3200970
            },
        }
    else:
        raise ValueError(f'Unknown page format: {page_format!r}')

    updates_navigation_links = re.findall(navigation_p, html)
    assert len(updates_navigation_links) == 1
    updates_navigation_links = updates_navigation_links[0]

    updates_section_match = re.findall(section_p, updates_navigation_links)
    assert len(updates_section_match) > 0

    all_updates = {}
    for windows_version_title, updates_section in updates_section_match:
        if windows_major_version == 10:
            if windows_version_title == 'Windows&#xA0;10&#xA0;(initial version released July 2015) update history':
                windows_version = '1507'
            else:
                match = re.match(r'Windows 10, version (\w+)(?:(?:, Windows Server| and Windows Server).*)? update history$', windows_version_title, re.IGNORECASE)
                assert match
                windows_version = match[1]
        else:
            assert windows_major_version == 11
            if windows_version_title == 'Windows 11, version 21H2':
                windows_version = '11-21H2'
            else:
                match = re.match(r'Windows 11, version (\w+)$', windows_version_title.strip(), re.IGNORECASE)
                assert match
                windows_version = '11-' + match[1]

        assert windows_version not in all_updates

        # Specific title fixes.
        if windows_version == '11-24H2':
            updates_section = updates_section.replace('KB5055627(OS Build', 'KB5055627 (OS Build')

        if windows_version == '11-22H2':
            updates_section = updates_section.replace(
                '(OS Builds OS 22621.5472 and 22631.5472)',
                '(OS Builds 22621.5472 and 22631.5472)')
            # Likely a mistake, the page says build 22621.5189, and the release
            # health page says so too.
            # https://answers.microsoft.com/en-us/windows/forum/all/inconsistency-in-kb5055528-release-note-os-build/ea9d36a0-8a28-444f-819f-f50a4cd36c19
            updates_section = updates_section.replace(
                'KB5055528 (OS Builds 22621.5191 and 22631.5191)',
                'KB5055528 (OS Builds 22621.5189 and 22631.5189)')

        if windows_version == '21H2':
            # Likely a mistake, the page says build 19044.5737, and the release
            # health page says so too.
            updates_section = updates_section.replace(
                'KB5055518 (OS Builds 19044.5736 and 19045.5736)',
                'KB5055518 (OS Builds 19044.5737 and 19045.5737)')

        if windows_version == '1809':
            updates_section = updates_section.replace('(OS Build OS 17763.529)', '(OS Build 17763.529)')

        if windows_version == '1709':
            updates_section = updates_section.replace('KB4509104 Update for Windows 10 Mobile  (', 'KB4509104 Update for Windows 10 Mobile (')

        if windows_version == '1607':
            updates_section = updates_section.replace(' - KB4346877', '&#x2014;KB4346877')
            updates_section = updates_section.replace('KB4025334  (', 'KB4025334 (')
            updates_section = updates_section.replace('KB 3216755', 'KB3216755')

        updates_section = re.sub(r'<a [^>]*>Windows.*? update history</a>', '', updates_section, flags=re.IGNORECASE)
        updates_section = re.sub(r'<a [^>]*>End of (service|servicing) statement</a>', '', updates_section, flags=re.IGNORECASE)

        if windows_major_version == 10:
            updates_section = re.sub(r'<a [^>]*>Windows 10 Extended Security Updates \(ESU\) program</a>', '', updates_section, flags=re.IGNORECASE)
            updates_section = re.sub(r'<a [^>]*>Support for Windows Server \d+ will end in .*?</a>', '', updates_section, flags=re.IGNORECASE)
        elif windows_major_version == 11:
            updates_section = re.sub(r'<a [^>]*>Windows 11, version \w+\s*</a>', '', updates_section, flags=re.IGNORECASE)

        p = item_anchor_p + r'((\w+) (\d+), (\d+) ?(?:\u2014|&#x2014;|-) ?KB(\d{7})(?: Update for Windows 10 Mobile|:? ?Windows 10, version \w+)? \(OS Builds? .+?\).*?)</a>'
        items = re.findall(p, updates_section)
        assert len(items) == len(re.findall('<a ', updates_section)), windows_version

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
            assert match, heading
            os_build = match[1]

            update_to_append = {
                'updateUrl': 'https://support.microsoft.com/help/' + kb_number,
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

    # Starting with 2025-05-13, 22H2 updates are no longer listed in the 21H2
    # section, although they are still available for 21H2 as well. They are
    # still listed in both sections in the health release page, though. Add them
    # to have both sources match.
    for update_kb, update in all_updates.get('22H2', {}).items():
        if update['heading'].endswith('Preview') or update_kb in [
            'KB5063159',
            'KB5071959',
        ]:
            continue

        if update_kb not in all_updates['21H2']:
            release_date = update['releaseDate']
            assert release_date >= '2025-05-13', release_date
            all_updates['21H2'][update_kb] = update
            print(f'WARNING: Added {update_kb} to 21H2')

    return all_updates


def get_updates_from_microsoft_support():
    def merge_updates_asserting_equal(updates_a, updates_b):
        # Combine two scrapes of the same data. updates_a takes precedence; where an
        # update appears in both, the fields that don't depend on HTML formatting must
        # match. The 'heading' is not compared: the layouts render it differently (e.g.
        # a literal em dash versus the &#x2014; entity).
        for windows_version in updates_b:
            version_updates_a = updates_a.setdefault(windows_version, {})
            for update_kb, update_b in updates_b[windows_version].items():
                update_a = version_updates_a.get(update_kb)
                if update_a is None:
                    version_updates_a[update_kb] = update_b
                    continue

                assert update_a['updateUrl'] == update_b['updateUrl'], (windows_version, update_kb)
                assert update_a['releaseDate'] == update_b['releaseDate'], (windows_version, update_kb)
                p = r'^\d+\.'
                assert re.sub(p, '', update_a['releaseVersion']) == re.sub(p, '', update_b['releaseVersion']), (
                    windows_version, update_kb, update_a['releaseVersion'], update_b['releaseVersion'])

    # The Windows 10 update history index page uses the new layout, while older
    # per-update article pages still use the old layout. Their sidebars list
    # overlapping but not identical sets of updates (the old one still includes
    # Windows 10 Mobile and some older updates dropped from the new one, while the
    # new one has the latest updates), so combine both, letting the new layout win.
    win10_updates = get_updates_from_microsoft_support_for_version(10, 'https://support.microsoft.com/en-us/help/4000823', 'new')
    win10_updates_old_layout = get_updates_from_microsoft_support_for_version(10, 'https://support.microsoft.com/help/4052314', 'old')
    merge_updates_asserting_equal(win10_updates, win10_updates_old_layout)

    win11_updates = get_updates_from_microsoft_support_for_version(11, 'https://support.microsoft.com/en-us/help/5006099', 'new')
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

    target_subtitle = f'<h2 id="windows-{windows_major_version}-release-history">Windows {windows_major_version} release history</h2>'
    index = html.find(target_subtitle)
    assert index != -1
    release_history = html[index + len(target_subtitle):]

    # Remove the hotpatch calendar section for Windows 11.
    if windows_major_version == 11:
        p = r'<h2[^>]*>.*?</h2>*'
        match = re.search(p, release_history)
        assert match
        assert match.group(0) == '<h2 id="windows-11-hotpatch-calendar">Windows 11 hotpatch calendar</h2>'
        release_history = release_history[:match.start()]

    p = (
        r'<strong>Version (\w+)(?: \(RTM\)| \(original release\))? \(OS build \d+\)</strong>'
        r'[\s\S]*?'
        r'(<table[\s\S]*?</table>)'
    )
    updates_table_match = re.findall(p, release_history)
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
            r'<td>(.*?)</td>\s*'
            r'</tr>'
        )
        update_row_match = re.findall(p, updates_table)

        windows_version_updates = {}
        for servicing_option, update_type, availability_date, os_build, kb_article in update_row_match:
            if kb_article == '':
                continue

            match = re.match(r'<a href="([^"]*)"[^>]*>KB(\d+)</a>$', kb_article)
            assert match
            update_kb = 'KB' + match[2]
            update_url = match[1]

            # Skip bogus entry.
            if windows_version == '11-25H2' and update_kb == 'KB4321':
                continue

            # Adjust date to fix an inconsistency.
            if windows_version == '11-22H2' and update_kb == 'KB5031455':
                assert availability_date == '2023-10-26'
                availability_date = '2023-10-31'

            windows_version_updates[update_kb] = {
                'updateUrl': update_url,
                'releaseDate': availability_date,
                'releaseVersion': os_build
            }

        # A temporary fix for missing entries.
        if windows_version == '11-22H2' and 'KB5062663' not in windows_version_updates:
            windows_version_updates['KB5062663'] = {
                'updateUrl': 'https://support.microsoft.com/help/5062663',
                'releaseDate': '2025-07-22',
                'releaseVersion': '22621.5699'
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

    def get_items_with_url(url):
        result = []
        for windows_version in updates:
            for update_kb in updates[windows_version]:
                update = updates[windows_version][update_kb]
                if update['updateUrl'] == url:
                    result.append((windows_version, update_kb, update))
        return result

    # Assert no two entries with the same URL.
    assert not any(x != 1 for x in update_urls.values()), [
        (x, get_items_with_url(x[0])) for x in update_urls.items() if x[1] != 1]

    def get_items_with_kb(kb):
        result = []
        for windows_version in updates:
            for update_kb in updates[windows_version]:
                if update_kb == kb:
                    update = updates[windows_version][update_kb]
                    result.append((windows_version, update_kb, update))
        return result

    # Assert no two entries with the same KB.
    assert not any(x != 1 for x in update_kbs.values()), [
        (x, get_items_with_kb(x[0])) for x in update_kbs.items() if x[1] != 1]


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

    assert updates_from_microsoft_support.keys() == updates_from_release_health.keys()

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
