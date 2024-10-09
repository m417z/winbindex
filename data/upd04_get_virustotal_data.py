from isal import igzip as gzip
from datetime import datetime
from pathlib import Path
import requests
import base64
import bisect
import orjson
import random
import json
import time

import config


def get_file_hashes_of_updates(name, updates):
    output_dir = config.out_path.joinpath('by_filename_compressed')

    with gzip.open(output_dir.joinpath(f'{name}.json.gz'), 'r') as f:
        data = orjson.loads(f.read())

    file_hashes = set()

    for file_hash in data:
        file_updates = set()

        windows_versions = data[file_hash]['windowsVersions']
        for windows_version in windows_versions:
            file_updates |= windows_versions[windows_version].keys()

        if any(update in updates for update in file_updates):
            file_hashes.add(file_hash)

    return file_hashes


def create_virustotal_urllib_session():
    # https://stackoverflow.com/a/28002687
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    # The headers are necessary for getting info from VirusTotal.
    session.headers.update({
        'User-Agent': 'Mozilla/5.0',
        'Referer': 'https://www.virustotal.com/',
        'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8',  # That's a deliberate typo, seems like an anti-automation protection
        'X-Tool': 'vt-ui-main',
    })
    session.proxies.update({'https': 'http://127.0.0.1:8080'})  # for pymultitor

    return session


def lookup_virustotal_bulk_hashes_exist(file_hashes):
    url = 'https://www.virustotal.com/partners/sysinternals/file-reports?apikey=4e3202fdbe953d628f650229af5b3eb49cd46b2d3bfe5546ae3c5fa48b554e0c'
    body = [{'hash': hash} for hash in file_hashes]

    response = requests.post(url, json=body, headers={'User-Agent': 'VirusTotal'})
    response.raise_for_status()
    response = response.json()

    hashes_found = {}
    for result in response['data']:
        hashes_found[result['hash']] = result['found']

    return hashes_found


def identify_virustotal_result(file_hash, virustotal_json):
    try:
        type_tag = virustotal_json['data']['attributes']['type_tag']
        if type_tag == 'neexe':
            return 'win16'
    except KeyError:
        type_tag = None

    try:
        pe_info = virustotal_json['data']['attributes']['pe_info']

        # Make sure it has anything meaningful in it.
        _ = pe_info['sections'][0]
    except KeyError:
        pe_info = None

    missing_signature_info = (
        pe_info
        and 'RT_VERSION' in pe_info.get('resource_types', [])
        and 'signature_info' not in virustotal_json['data']['attributes']
    )

    # Temporary log.
    if missing_signature_info:
        print(f'WARNING: signature_info is missing for {file_hash}')

    # Warn about unexpected type_tag, and proceed anyway. Don't warn if both
    # type_tag and PE info are missing as that's to be expected.
    if type_tag is None:
        if pe_info:
            print(f'WARNING: type_tag is missing for {file_hash}')
    elif type_tag not in ['peexe', 'pedll']:
        print(f'WARNING: Unknown type_tag {type_tag} for {file_hash}')

    if not pe_info or missing_signature_info:
        # VirusTotal often doesn't have PE information for large files.
        # https://twitter.com/sixtyvividtails/status/1697355272568643970
        if virustotal_json['data']['attributes']['size'] > 250000000:
            return 'too_large_no_pe_info'

        # No PE info, need to rescan it on VirusTotal.
        return 'no_pe_info'

    return 'ok'


def get_virustotal_data_for_file(session: requests.Session, file_hash, output_dir):
    if output_dir.joinpath(file_hash + '.json').is_file():
        return 'exists'

    # if output_dir.joinpath('_404_' + file_hash + '.json').is_file():
    #     return 'not_found'

    url = 'https://www.virustotal.com/ui/files/' + file_hash
    headers = {
        # Sorry...
        'X-VT-Anti-Abuse-Header': base64.b64encode(f'{random.randint(10000000000, 20000000000)}-ZG9udCBiZSBldmls-{round(time.time(), 3)}'.encode()).decode(),
    }

    try:
        r = session.get(url, verify=False, headers=headers, timeout=30)
    except Exception as e:
        print(f'ERROR: failed to get {url}')
        print(f'       {e}')
        return 'retry'

    if r.status_code in [403, 429]:
        return 'retry'

    virustotal_data = r.text

    prefix = ''
    if r.status_code != 200:
        prefix = f'_{r.status_code}_'
        result = 'not_found' if r.status_code == 404 else str(r.status_code)
    else:
        try:
            virustotal_json = json.loads(virustotal_data)
        except json.JSONDecodeError:
            virustotal_json = None

        if virustotal_json:
            result = identify_virustotal_result(file_hash, virustotal_json)
        else:
            result = 'not_json'

        if result != 'ok':
            prefix = f'_{result}_'

    output_filename = output_dir.joinpath(prefix + file_hash + '.json')

    with open(output_filename, 'w') as f:
        f.write(virustotal_data)

    if result == 'no_pe_info':
        try:
            r = session.post(url + '/analyse', verify=False, headers=headers, timeout=30)
            print(f'Submitted {file_hash} for analysis, response: {r.status_code}')
        except Exception as e:
            print(f'ERROR: failed to submit {file_hash} for analysis')
            print(f'       {e}')

    return result


def get_virustotal_data_for_files(names_and_hashes, session: requests.Session, output_dir, time_to_stop):
    result = {
        'found': set(),
        'not_found': set(),
        'failed': set(),
        'next': None,
    }

    # https://stackoverflow.com/a/312464
    def chunks(lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    # Split to chunks, the bulk lookup fails for an input which is too large.
    chunk_size = 1000

    count = 0

    for names_and_hashes_chunk in chunks(names_and_hashes, chunk_size):
        while True:
            try:
                hashes_found = lookup_virustotal_bulk_hashes_exist([hash for name, hash in names_and_hashes_chunk])
                break
            except Exception as e:
                print(f'ERROR: failed to do bulk lookup, retrying in 10 seconds')
                print(f'       {e}')
                time.sleep(10)

        print(f'Found {sum(hashes_found.values())} hashes of {len(hashes_found)}')

        for name, hash in names_and_hashes_chunk:
            if hashes_found[hash]:
                while True:
                    if time_to_stop and datetime.now() >= time_to_stop:
                        result['next'] = (name, hash)
                        return result

                    try:
                        file_result = get_virustotal_data_for_file(session, hash, output_dir)
                    except Exception as e:
                        print(f'ERROR: failed to process {hash} ({name})')
                        print(f'       {e}')
                        if config.exit_on_first_error:
                            raise
                        file_result = 'exception'

                    if file_result != 'retry':
                        break

                    # print('Waiting to retry...')
                    # time.sleep(30)
                    print(f'Retrying {hash} ({name})')

                if file_result in ['ok', 'exists']:
                    result['found'].add((name, hash))
                elif file_result == 'not_found':
                    assert False, (name, hash)
                    # result['not_found'].add((name, hash))
                elif file_result == 'too_large_no_pe_info':
                    result['not_found'].add((name, hash))
                else:
                    print(f'WARNING: got result {file_result} for {hash} ({name})')
                    result['failed'].add((name, hash))
            else:
                result['not_found'].add((name, hash))

            count += 1
            if count % 10 == 0 and config.verbose_progress:
                print(f'Processed {count} of {len(names_and_hashes)} ({name})')

    return result


def main(time_to_stop=None):
    output_dir = config.out_path.joinpath('virustotal')
    output_dir.mkdir(parents=True, exist_ok=True)

    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    info_progress_virustotal_path = config.out_path.joinpath('info_progress_virustotal.json')
    if info_progress_virustotal_path.is_file():
        with open(info_progress_virustotal_path, 'r') as f:
            info_progress_virustotal = json.load(f)
    else:
        info_progress_virustotal = {}

    progress_updates = info_progress_virustotal.get('updates')
    progress_updates_next_key = 'next' if progress_updates is None else 'next_updates'
    progress_next = info_progress_virustotal.get(progress_updates_next_key)
    if progress_next is not None:
        progress_next = tuple(progress_next)

    # Get names and hashes of all PE files without full information.
    names_and_hashes = []
    for name in info_sources.keys():
        file_hashes = set(hash for hash in info_sources[name] if info_sources[name][hash] not in ['vt', 'file'])
        if not file_hashes:
            continue

        if progress_updates is not None:
            file_hashes &= get_file_hashes_of_updates(name, progress_updates)

        names_and_hashes += [(name, hash) for hash in file_hashes]

    names_and_hashes.sort()

    # Order list to start from the 'next' file where the script stopped last time.
    if progress_next is not None:
        progress_hash_index = bisect.bisect_left(names_and_hashes, progress_next)
        if progress_updates is not None:
            names_and_hashes = names_and_hashes[progress_hash_index:]
        else:
            names_and_hashes = names_and_hashes[progress_hash_index:] + names_and_hashes[:progress_hash_index]

    names_and_hashes_to_retry = [tuple(x) for x in info_progress_virustotal.get('retry', [])]
    names_and_hashes = names_and_hashes_to_retry + [h for h in names_and_hashes if h not in names_and_hashes_to_retry]

    if config.verbose_progress:
        print(f'{len(names_and_hashes_to_retry)} items to retry')
        print(f'{len(names_and_hashes)} items total')

    session = create_virustotal_urllib_session()

    result = get_virustotal_data_for_files(names_and_hashes, session, output_dir, time_to_stop)

    if result['next'] is None:
        # All items were processed.
        info_progress_virustotal[progress_updates_next_key] = None
        info_progress_virustotal['updates'] = None
    elif result['next'] not in names_and_hashes_to_retry:
        # Save 'next' file for next time.
        info_progress_virustotal[progress_updates_next_key] = result['next']

    # Set failed and unprocessed files to retry.
    info_progress_virustotal['retry'] = sorted((set(names_and_hashes_to_retry) - result['found'] - result['not_found']) | result['failed'])

    # Update status of files for which full information was found.
    for name, hash in result['found']:
        assert info_sources[name][hash] not in ['vt', 'file']
        info_sources[name][hash] = 'vt'
        pending_for_file = info_progress_virustotal.setdefault('pending', {}).setdefault(name, [])
        if hash not in pending_for_file:
            pending_for_file.append(hash)

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)

    with open(info_progress_virustotal_path, 'w') as f:
        json.dump(info_progress_virustotal, f, indent=0, sort_keys=True)


if __name__ == '__main__':
    main()
