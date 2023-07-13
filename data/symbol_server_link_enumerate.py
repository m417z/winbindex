from isal import igzip as gzip
from datetime import datetime
import concurrent.futures
from pathlib import Path
import requests
import orjson
import json

import config


def write_to_gzip_file(file, data):
    with open(file, 'wb') as fd:
        with gzip.GzipFile(fileobj=fd, mode='w', compresslevel=config.compression_level, filename='', mtime=0) as gz:
            gz.write(data)


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


def make_symbol_server_url(file_name, timestamp, size):
    return f'https://msdl.microsoft.com/download/symbols/{file_name}/{timestamp:08X}{size:x}/{file_name}'


def create_symbol_server_urllib_session():
    return requests.Session()


# https://stackoverflow.com/a/46144596
def test_symbol_server_urls(session: requests.Session, urls):
    CONNECTIONS = 64
    TIMEOUT = 10

    def load_url(url, timeout):
        ans = session.head(url, timeout=timeout)
        return ans.status_code, url

    valid_urls = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTIONS) as executor:
        future_to_url = (executor.submit(load_url, url, TIMEOUT) for url in urls)
        for future in concurrent.futures.as_completed(future_to_url):
            status_code, url = future.result()
            if status_code == 302:
                valid_urls.append(url)
            elif status_code != 404:
                raise Exception(f'Unexpected status code {status_code} for {url}')

    return valid_urls


def get_symbol_server_links_for_file(session, hash, name, data):
    file_info = data[hash]['fileInfo']

    last_section_virtual_address = file_info['lastSectionVirtualAddress']
    last_section_pointer_to_raw_data = file_info['lastSectionPointerToRawData']
    timestamp = file_info['timestamp']
    file_size = file_info['size']
    assert 'virtualSize' not in file_info

    # Algorithm inspired by DeltaDownloader:
    # https://github.com/Wack0/DeltaDownloader/blob/ab71359fc5a1f2446b650b31450c74a701c40979/Program.cs#L68-L85

    PAGE_SIZE = 0x1000

    def get_mapped_size(size):
        PAGE_MASK = (PAGE_SIZE - 1)
        page = size & ~PAGE_MASK
        if (page == size):
            return page
        return page + PAGE_SIZE

    # We use the rift table (VirtualAddress,PointerToRawData pairs for each section) and the target file size to calculate the SizeOfImage.
    last_section_and_signature_size = file_size - last_section_pointer_to_raw_data
    last_section_and_signature_mapped_size = get_mapped_size(last_section_virtual_address + last_section_and_signature_size)

    size_of_image = last_section_and_signature_mapped_size
    lowest_size_of_image = last_section_virtual_address + PAGE_SIZE

    urls_and_virtual_sizes = {}
    size = size_of_image
    while size >= lowest_size_of_image:
        url = make_symbol_server_url(name, timestamp, size)
        urls_and_virtual_sizes[url] = size
        size -= PAGE_SIZE

    while True:
        try:
            valid_urls = test_symbol_server_urls(session, urls_and_virtual_sizes.keys())
            break
        except Exception as e:
            print(e)
            print(f'Retrying {hash}')

    if len(valid_urls) != 1:
        return None

    file_info['virtualSize'] = urls_and_virtual_sizes[valid_urls[0]]

    return data


def get_symbol_server_links_for_files(names_and_hashes, session, time_to_stop):
    result = {
        'found': set(),
        'not_found': set(),
        'next': None,
    }

    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_path = None
    data = None
    data_modified = False

    count = 0
    for name, hash in names_and_hashes:
        if time_to_stop and datetime.now() >= time_to_stop:
            result['next'] = (name, hash)
            break

        new_output_path = output_dir.joinpath(f'{name}.json.gz')
        if new_output_path != output_path:
            if output_path and data_modified:
                write_to_gzip_file(output_path, orjson.dumps(data))

            output_path = output_dir.joinpath(f'{name}.json.gz')
            with gzip.open(output_path, 'rb') as f:
                data = orjson.loads(f.read())
                data_modified = False

        new_data = get_symbol_server_links_for_file(session, hash, name, data)
        if new_data:
            data = new_data
            data_modified = True
            result['found'].add((name, hash))
        else:
            result['not_found'].add((name, hash))

        count += 1
        if count % 10 == 0 and config.verbose_progress:
            print(f'Processed {count} of {len(names_and_hashes)}')

    if output_path and data_modified:
        write_to_gzip_file(output_path, orjson.dumps(data))

    return result


def main(time_to_stop=None):
    info_sources_path = config.out_path.joinpath('info_sources.json')
    if info_sources_path.is_file():
        with open(info_sources_path, 'r') as f:
            info_sources = json.load(f)
    else:
        info_sources = {}

    info_progress_symbol_server_path = config.out_path.joinpath('info_progress_symbol_server.json')
    if info_progress_symbol_server_path.is_file():
        with open(info_progress_symbol_server_path, 'r') as f:
            info_progress_symbol_server = json.load(f)
    else:
        info_progress_symbol_server = {}

    progress_updates = info_progress_symbol_server.get('updates')
    progress_next = info_progress_symbol_server.get('next')
    if progress_next is not None:
        progress_next = tuple(progress_next)

    if progress_updates == []:
        return None  # no updates to process

    # Get names and hashes of all PE files with multiple links.
    names_and_hashes = []
    for name in info_sources.keys():
        file_hashes = set(hash for hash in info_sources[name] if info_sources[name][hash] == 'delta')
        if not file_hashes:
            continue

        if progress_updates is not None:
            file_hashes &= get_file_hashes_of_updates(name, progress_updates)

        names_and_hashes += [(name, hash) for hash in file_hashes]

    names_and_hashes.sort()

    # Order list to start from the 'next' file where the script stopped last time.
    if progress_next is not None:
        progress_hash_index = names_and_hashes.index(progress_next)
        names_and_hashes = names_and_hashes[progress_hash_index:]

    if config.verbose_progress:
        print(f'{len(names_and_hashes)} items to process')

    session = create_symbol_server_urllib_session()

    result = get_symbol_server_links_for_files(names_and_hashes, session, time_to_stop)

    if result['next'] is None:
        # All items were processed.
        info_progress_symbol_server['next'] = None
        info_progress_symbol_server['updates'] = []
    else:
        # Save 'next' file for next time.
        info_progress_symbol_server['next'] = result['next']

    # Update status of files for which full information was found.
    for name, hash in result['found']:
        assert info_sources[name][hash] == 'delta'
        info_sources[name][hash] = 'delta+'

    with open(info_sources_path, 'w') as f:
        json.dump(info_sources, f, indent=0, sort_keys=True)

    with open(info_progress_symbol_server_path, 'w') as f:
        json.dump(info_progress_symbol_server, f, indent=0, sort_keys=True)

    return len(result['found'])


if __name__ == '__main__':
    main()
