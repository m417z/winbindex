from isal import igzip as gzip
from datetime import datetime
from pathlib import Path
import requests
import urllib3
import base64
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
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def get_virustotal_data_for_file(session, file_hash, output_dir):
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
    except (KeyboardInterrupt, SystemExit):
        raise
    except:
        return 'retry'

    if r.status_code == 429:
        return 'retry'

    virustotal_data = r.text

    prefix = ''
    if r.status_code != 200:
        prefix = f'_{r.status_code}_'
        result = 'not_found' if r.status_code == 404 else str(r.status_code)
    else:
        try:
            virustotal_json = json.loads(virustotal_data)
            try:
                _ = virustotal_json['data']['attributes']['pe_info']['sections'][0]
                result = 'ok'
            except:
                prefix = '_no_pe_info_'  # no PE info, need to rescan it on VirusTotal
                result = 'no_pe_info'
        except:
            prefix = '_not_json_'
            result = 'not_json'

    output_filename = output_dir.joinpath(prefix + file_hash + '.json')

    with open(output_filename, 'w') as f:
        f.write(virustotal_data)

    return result


def get_virustotal_data_for_files(hashes, session, output_dir, time_to_stop):
    result = {
        'found': set(),
        'not_found': set(),
        'failed': set(),
        'next': None,
    }

    count = 0
    for hash in hashes:
        while True:
            if time_to_stop and datetime.now() >= time_to_stop:
                result['next'] = hash
                return result

            try:
                file_result = get_virustotal_data_for_file(session, hash, output_dir)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                print(f'ERROR: failed to process {hash}')
                print(f'       {e}')
                if config.exit_on_first_error:
                    raise

            if file_result != 'retry':
                break

            # print('Waiting to retry...')
            # time.sleep(30)
            print(f'Retrying {hash}')

        if file_result in ['ok', 'exists']:
            result['found'].add(hash)
        elif file_result == 'not_found':
            result['not_found'].add(hash)
        else:
            print(f'WARNING: got result {file_result} for {hash}')
            result['failed'].add(hash)

        count += 1
        if count % 10 == 0 and config.verbose_progress:
            print(f'Processed {count} of {len(hashes)}')

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

    # Get hashes of all PE files without full information.
    hashes = []
    for name in sorted(info_sources.keys()):
        file_hashes = set(hash for hash in info_sources[name] if info_sources[name][hash] not in ['vt', 'file'])
        if not file_hashes:
            continue

        if progress_updates is not None:
            file_hashes &= get_file_hashes_of_updates(name, progress_updates)

        hashes += sorted(file_hashes)

    # Order list to start from the 'next' file where the script stopped last time.
    if progress_next is not None:
        progress_hash_index = hashes.index(progress_next)
        if progress_updates is not None:
            hashes = hashes[progress_hash_index:]
        else:
            hashes = hashes[progress_hash_index:] + hashes[:progress_hash_index]

    hashes_to_retry = info_progress_virustotal.get('retry', [])
    hashes = hashes_to_retry + [h for h in hashes if h not in hashes_to_retry]

    if config.verbose_progress:
        print(f'{len(hashes_to_retry)} hashes to retry')
        print(f'{len(hashes)} hashes total')

    session = create_virustotal_urllib_session()

    result = get_virustotal_data_for_files(hashes, session, output_dir, time_to_stop)

    if result['next'] is None:
        # All hashes were processed.
        info_progress_virustotal[progress_updates_next_key] = None
        info_progress_virustotal['updates'] = None
    elif result['next'] not in hashes_to_retry:
        # Save 'next' file for next time.
        info_progress_virustotal[progress_updates_next_key] = result['next']

    # Set failed and unprocessed files to retry.
    info_progress_virustotal['retry'] = sorted((set(hashes_to_retry) - result['found'] - result['not_found']) | result['failed'])

    # Update status of files for which full information was found.
    for name in info_sources:
        for hash in info_sources[name]:
            if hash in result['found']:
                info_sources[name][hash] = 'vt'
                pending_for_file = info_progress_virustotal.setdefault('pending', {}).setdefault(name, [])
                if hash not in pending_for_file:
                    pending_for_file.append(hash)

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0)

    with open(info_progress_virustotal_path, 'w') as f:
        json.dump(info_progress_virustotal, f, indent=0)


if __name__ == '__main__':
    main()
