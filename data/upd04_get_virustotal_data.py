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

from info_sources import InfoSource, InfoSources
import config

# Sources which already hold everything VirusTotal could add.
SOURCES_WITH_FULL_INFO = [InfoSource.VT, InfoSource.FILE]


def get_file_hashes_of_updates(name, updates):
    with gzip.open(config.compressed_filename_path(name), 'r') as f:
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


def lookup_virustotal_bulk_hashes_exist(session: requests.Session, file_hashes):
    url = 'https://www.virustotal.com/partners/sysinternals/file-reports?apikey=4e3202fdbe953d628f650229af5b3eb49cd46b2d3bfe5546ae3c5fa48b554e0c'
    body = [{'hash': hash} for hash in file_hashes]

    response = session.post(url, verify=False, json=body, headers={'User-Agent': 'VirusTotal'})
    response.raise_for_status()
    response = response.json()

    hashes_found = {}
    for result in response['data']:
        hashes_found[result['hash']] = result['found']

    return hashes_found


def identify_virustotal_result(file_hash: str, virustotal_json: dict) -> str:
    try:
        type_tag = virustotal_json['data']['attributes']['type_tag']
        if type_tag == 'neexe':
            return 'win16'

        if type_tag not in ['peexe', 'pedll']:
            print(f'WARNING: Unknown type_tag {type_tag} for {file_hash}')
    except KeyError:
        type_tag = None

    try:
        pe_info = virustotal_json['data']['attributes']['pe_info']

        # Make sure it has anything meaningful in it.
        _ = pe_info['sections'][0]
    except KeyError:
        pe_info = None

    missing_version_info = (
        pe_info
        and 'RT_VERSION' in pe_info.get('resource_types', {})
        and not (
            virustotal_json['data']['attributes'].get('signature_info', {}).keys()
            & {
                'copyright',
                'description',
                'file version',
                'internal name',
                'original name',
                'product',
            }
        )
    )

    if not type_tag or not pe_info or missing_version_info:
        # VirusTotal often doesn't have PE information for large files.
        # https://x.com/sixtyvividtails/status/1697355272568643970
        if virustotal_json['data']['attributes']['size'] > 250000000:
            return 'too_large_no_pe_info'

        if file_hash.lower() in [
            # Mysterious files with no PE info.
            # https://x.com/m417z/status/1983105172218749222
            # ekaioopl.dll
            '1c857a17a6aacfa38a1c95cc6e6f45fee7c7c46f14e0b1a409e0af532b455582',
            # ekaioopl.dll
            'fc443f74eecbd77c2b48e6f26db5dbcf8d68ff1a2cd474caa7f8d69f0ea08d91',
            # ekaiostr.dll
            '81999de8fa119fad5e1ddb06a19bb140319e8d408d06cb14b666232a386c8b3b',
            # ekaiostr.dll
            '96aa482f2d38e6a08502875b5130250f0775e0bbd2f2d7afd5b4e62e707789a1',
            # ekaioxps.dll
            '62ca4eda8830d9324c1ee1b553c01e70a7f2fa824038dfdbacace108db83b355',
            # ekaioxps.dll
            'c91e3c60231614e1e800567e2c12ed1e153ac589373c5b44139d166129d6d099',
            # microsoft.ceres.docparsing.formathandlers.common.configuration.dll
            '1950daee95a5548f70abb69695a97a96b2506ae6b8296033ea4c28ba0329abd9',
            # microsoft.ceres.docparsing.formathandlers.common.configuration.dll
            '4e8408f9b66ecf316e03887226086458471abbb4aa59815d911a785c02efa154',
            # microsoft.ceres.docparsing.formathandlers.common.configuration.dll
            '86e2eac22ac346a33f1e8a0907786d6cc9b2a6c492d98fac7e5a237d95acfe58',
            # microsoft.ceres.docparsing.formathandlers.common.jpeginterop.dll
            '0118e0fcd676509ed9a750bf47467282e1c57332f8ed4a928d833a9faf57e23c',
            # microsoft.ceres.docparsing.formathandlers.common.jpeginterop.dll
            '04f8591186445243c2e6a8f8161852de4f027381f077e8c78fadc09ee022f899',
            # microsoft.ceres.docparsing.formathandlers.common.jpeginterop.dll
            '0bf23e9042cad8fdefbafeededf08cc8e8d9d3789fd561c040de2f66e1d8b9de',
            # microsoft.ceres.docparsing.formathandlers.common.linkdetector.dll
            '920a9eb0e61ee13af50e07abcc77bcc0202108b4b7ab84acecbd7add2ffd7b51',
            # vc_redist.arm64.exe
            '8a81a52b7ff6b194cb88e1bb48d597b6588d2b840552909359f286fb1699235c',
        ]:
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
        r = session.get(url, verify=False, headers=headers)
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
            r = session.post(url + '/analyse', verify=False, headers=headers)
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
        sleep_time = 1
        while True:
            try:
                hashes_found = lookup_virustotal_bulk_hashes_exist(session, [hash for name, hash in names_and_hashes_chunk])
                break
            except Exception as e:
                print(e)
                time.sleep(sleep_time)
                sleep_time = min(sleep_time * 2, 60 * 5)
                print('Retrying')

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

    info_sources = InfoSources.load()

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
    sources = [source for source in InfoSource if source not in SOURCES_WITH_FULL_INFO]
    names_and_hashes = []
    for name, file_hashes in info_sources.get_file_hashes_by_source(sources).items():
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
        if info_sources.get_source(name, hash) == InfoSource.VT:
            assert (name, hash) in names_and_hashes_to_retry
        else:
            assert info_sources.get_source(name, hash) != InfoSource.FILE
            info_sources.set_source(name, hash, InfoSource.VT)
        pending_for_file = info_progress_virustotal.setdefault('pending', {}).setdefault(name, [])
        if hash not in pending_for_file:
            pending_for_file.append(hash)

    info_sources.save()

    with open(info_progress_virustotal_path, 'w') as f:
        json.dump(info_progress_virustotal, f, indent=0, sort_keys=True)


if __name__ == '__main__':
    main()
