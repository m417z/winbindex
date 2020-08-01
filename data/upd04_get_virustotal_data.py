from pathlib import Path
import requests
import json
import time

import config

def get_virustotal_data_for_file(session, input_filename, output_dir):
    with open(input_filename) as f:
        data = json.load(f)

    for file_item in data['files']:
        filename = file_item['attributes']['name']
        if (not filename.endswith('.exe') and
            not filename.endswith('.dll') and
            not filename.endswith('.sys')):
            continue

        if 'sha1' in file_item:
            file_hash = file_item['sha1']
        else:
            file_hash = file_item['sha256']

        if output_dir.joinpath(file_hash + '.json').is_file() or output_dir.joinpath('_404_' + file_hash + '.json').is_file():
            continue

        #time.sleep(1)
        while True:
            url = 'https://www.virustotal.com/ui/files/' + file_hash
            r = session.get(url, verify=False)

            if r.status_code == 429:
                time.sleep(60)
                continue

            virustotal_data = r.text

            prefix = ''
            if r.status_code != 200:
                prefix = f'_{r.status_code}_'
            elif '"pe_info": {' not in virustotal_data:
                prefix = '_no_pe_info_'  # no PE info, need to rescan it on VirusTotal

            break

        output_filename = output_dir.joinpath(prefix + file_hash + '.json')

        with open(output_filename, 'w') as f:
            f.write(virustotal_data)

def get_virustotal_data_for_update(parsed_dir, output_dir):
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'})
    session.proxies.update({'https': 'http://127.0.0.1:8080'})

    output_dir.mkdir(parents=True, exist_ok=True)

    for path in parsed_dir.glob('*.json'):
        if not path.is_file():
            continue

        try:
            get_virustotal_data_for_file(session, str(path), output_dir)
        except Exception as e:
            print(f'ERROR: failed to process {path}')
            print('    ' + str(e))

def main():
    with open(config.out_path.joinpath('updates.json')) as f:
        updates = json.load(f)

    for windows_version in updates:
        if windows_version == '1909':
            continue  # same updates as 1903

        print(f'Processing Windows version {windows_version}:', end='', flush=True)

        for update in updates[windows_version]:
            update_kb = update['updateKb']

            parsed_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
            if parsed_dir.is_dir():
                output_dir = config.out_path.joinpath('virustotal')
                get_virustotal_data_for_update(parsed_dir, output_dir)
                print(' ' + update_kb, end='', flush=True)

        print()

if __name__ == '__main__':
    main()
