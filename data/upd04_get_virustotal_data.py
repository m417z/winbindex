from datetime import datetime
from pathlib import Path
import requests
import urllib3
import base64
import random
import json
import time

import config

file_hashes = {
    'found': {},
    'not_found': {}
}

def update_file_hashes():
    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    for name in file_hashes['found']:
        for file_hash in file_hashes['found'][name]:
            assert info_sources[name][file_hash] in ['none', 'novt']
            info_sources[name][file_hash] = 'newvt'

    file_hashes['found'].clear()

    for name in file_hashes['not_found']:
        for file_hash in file_hashes['not_found'][name]:
            assert info_sources[name][file_hash] in ['none', 'novt']
            info_sources[name][file_hash] = 'novt'

    file_hashes['not_found'].clear()

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f)

def get_virustotal_data_for_file(session, file_hash, output_dir):
    if output_dir.joinpath(file_hash + '.json').is_file():
        return 'exists'

    if output_dir.joinpath('_404_' + file_hash + '.json').is_file():
        return 'not_found'

    url = 'https://www.virustotal.com/ui/files/' + file_hash
    headers = {
        # Sorry...
        'X-VT-Anti-Abuse-Header': base64.b64encode(f'{random.randint(10000000000, 20000000000)}-ZG9udCBiZSBldmls-{round(time.time(), 3)}'.encode()).decode(),
    }

    r = None
    try:
        r = session.get(url, verify=False, headers=headers, timeout=60*10)
    except:
        return 'retry'

    if r.status_code == 429:
        return 'retry'

    virustotal_data = r.text

    prefix = ''
    if r.status_code != 200:
        prefix = f'_{r.status_code}_'
        result = 'not_found' if r.status_code == 404 else str(r.status_code)
    elif '"pe_info": {' not in virustotal_data:
        prefix = '_no_pe_info_'  # no PE info, need to rescan it on VirusTotal
        result = 'no_pe_info'
    else:
        result = 'ok'

    output_filename = output_dir.joinpath(prefix + file_hash + '.json')

    with open(output_filename, 'w') as f:
        f.write(virustotal_data)

    return result

def get_virustotal_data(time_to_stop=None):
    with open(config.out_path.joinpath('info_sources.json')) as f:
        info_sources = json.load(f)

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

    output_dir = config.out_path.joinpath('virustotal')
    output_dir.mkdir(parents=True, exist_ok=True)

    # If at least one file wasn't even checked against VT, check all such files.
    # Otherwise, check again the file that were checked before, perhaps they're on VT now.
    if any(info_sources[name][file_hash] == 'none' for name in info_sources for file_hash in info_sources[name]):
        target_source = 'none'
    else:
        target_source = 'novt'

    count = 0
    total_count = sum(1 for name in info_sources for file_hash in info_sources[name] if info_sources[name][file_hash] == target_source)
    print(f'{total_count} items of type {target_source}')

    names = info_sources.keys()
    if time_to_stop:
        # Time is limited, shuffle keys to try different ones at different runs.
        names = list(names)
        random.shuffle(names)

    for name in names:
        for file_hash in info_sources[name]:
            info_source = info_sources[name][file_hash]
            if info_source != target_source:
                continue

            count += 1
            if count % 200 == 0 and config.verbose_progress:
                print(f'Processed {count} of {total_count}')

            while True:
                if time_to_stop and datetime.now() >= time_to_stop:
                    return

                try:
                    result = get_virustotal_data_for_file(session, file_hash, output_dir)
                except Exception as e:
                    print(f'ERROR: failed to process {file_hash}')
                    print('    ' + str(e))
                    if config.exit_on_first_error:
                        raise

                if result != 'retry':
                    break

                #print('Waiting to retry...')
                #time.sleep(30)
                print('Retrying')

            if result in ['ok', 'exists']:
                file_hashes['found'].setdefault(name, set()).add(file_hash)
            elif result == 'not_found':
                file_hashes['not_found'].setdefault(name, set()).add(file_hash)
            else:
                print(f'WARNING: got result {result} for {file_hash} ({name})')

def main(time_to_stop=None):
    get_virustotal_data(time_to_stop)
    update_file_hashes()

if __name__ == '__main__':
    main()
