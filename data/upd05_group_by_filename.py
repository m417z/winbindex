from multiprocessing import Pool
from isal import igzip as gzip
from datetime import datetime
from itertools import repeat
from pathlib import Path
import bisect
import orjson
import json

import config

file_info_data = {}


def write_to_gzip_file(file, data):
    with open(file, 'wb') as fd:
        with gzip.GzipFile(fileobj=fd, mode='w', compresslevel=config.compression_level, filename='', mtime=0) as gz:
            gz.write(data)


def write_all_file_info():
    output_dir = config.out_path.joinpath('by_filename_compressed')

    for filename in file_info_data:
        data = file_info_data[filename]

        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))

    file_info_data.clear()

    all_filenames = sorted(path.with_suffix('').stem for path in output_dir.glob('*.json.gz'))

    with open(config.out_path.joinpath('filenames.json'), 'w') as f:
        json.dump(all_filenames, f, indent=0, sort_keys=True)


def get_file_info_type(file_info):
    if 'machineType' not in file_info:
        k = {'size'}
        if file_info.keys() in [
            k | {'md5'},
            k | {'sha256'},
        ]:
            return 'raw'

        if file_info.keys() == {
            'size',
            'md5',
            'sha1',
            'sha256',
        }:
            return 'raw_file'

        assert False, file_info

    k = {
        'size',
        'machineType',
        'timestamp',
        'lastSectionVirtualAddress',
        'lastSectionPointerToRawData',
    }
    if file_info.keys() in [
        k | {'md5'},
        k | {'sha256'},
    ]:
        return 'delta'

    k = {
        'size',
        'machineType',
        'timestamp',
        'lastSectionVirtualAddress',
        'lastSectionPointerToRawData',
        'virtualSize',
    }
    if file_info.keys() in [
        k | {'md5'},
        k | {'sha256'},
    ]:
        return 'delta+'

    assert 'lastSectionVirtualAddress' not in file_info
    assert 'lastSectionPointerToRawData' not in file_info

    # For old info.
    if file_info.keys() == {
        'size',
        'md5',
        'machineType',
        'timestamp',
        'virtualSize',
    }:
        return 'pe'

    assert file_info.keys() - {
        'version',
        'description',
        'signatureType',
        'signingDate',
    } == {
        'size',
        'md5',
        'sha1',
        'sha256',
        'machineType',
        'timestamp',
        'virtualSize',
        'signingStatus',
    }, file_info

    if file_info['signingStatus'] == 'Unknown':
        return 'file_unknown_sig'

    return 'vt_or_file'


def assert_file_info_close_enough(file_info_1, file_info_2):
    def canonical_file_info(file_info):
        file_info = file_info.copy()

        # VirusTotal strips whitespaces in descriptions.
        if 'description' in file_info:
            file_info['description'] = file_info['description'].strip()
            if file_info['description'].strip() == '':
                del file_info['description']

        # VirusTotal strips whitespaces in versions.
        if 'version' in file_info:
            file_info['version'] = file_info['version'].strip()
            if file_info['version'].strip() == '':
                del file_info['version']

        # Nullify Catalog file based data since it depends on the computer the scan ran on.
        if file_info.get('signatureType') == 'Catalog file':
            assert 'signingDate' not in file_info
            file_info['signingStatus'] = 'Unsigned'
            del file_info['signatureType']

        return file_info

    # Must be equal for all information sources.
    assert file_info_1['size'] == file_info_2['size']

    # Non-PE file.
    if 'machineType' not in file_info_1:
        non_pe_keys = {
            'md5',
            'sha1',
            'sha256',
            'size',
        }
        assert file_info_1.keys() <= non_pe_keys
        assert file_info_2.keys() <= non_pe_keys
        for key in file_info_1.keys() & file_info_2.keys():
            assert file_info_1[key] == file_info_2[key]
        return

    # Must be equal for all information sources.
    assert file_info_1['machineType'] == file_info_2['machineType']
    assert file_info_1['timestamp'] == file_info_2['timestamp']

    delta_or_pe_types = ['delta', 'delta+', 'pe']
    if get_file_info_type(file_info_1) in delta_or_pe_types or get_file_info_type(file_info_2) in delta_or_pe_types:
        for key in file_info_1.keys() & file_info_2.keys():
            assert file_info_1[key] == file_info_2[key]
        return

    file_info_1 = canonical_file_info(file_info_1)
    file_info_2 = canonical_file_info(file_info_2)

    # assert file_info_1.keys() - {'signingDate'} == file_info_2.keys() - {'signingDate'}, (file_info_1, file_info_2)

    # temp {
    if file_info_1.keys() - {'signingDate'} != file_info_2.keys() - {'signingDate'}:
        if file_info_1['sha256'] not in [
            # edgehtml.dll
            '0cb8e9df274c7edc3c4997fdd4110d6f73221f32d479af8648b54e90a294ebae',
            '51fce1826feddcfedface5ef71a9396b781083c7752b4ff77c3b549aad0917f6',

            # cortana.donotdisturb.dll
            '60527081581ab46e79a018c4c221deecb155da644149cb33e6b84708ddad4762',

            # mixedrealitycapture.pipeline.dll
            '8a17d8ddc645a1caf7db31549c6e3c32ff617f6f46f1ea7cc161756800256e4b',

            # eshims.dll
            'f0b577caf75fa0b1011bc160a8aaf146d9fbc026b2a7a52f71b011535d8a38d5',

            # msttsengine_onecore.dll
            'e3ae51ddc111cd1e3fdcb3466e8645861ca00f86a69ebb5de170119e5dbd2fb7',
            'bffbe22ee6a60b2937ec0000c211d01f05fb7d74cddb7b58fea1ba4c6288bd15',
            'bcc6329e67897cc5d3d1c7b81cc82025d6bcac62ec38062c9778d94884f76cd7',
            '97ab522b971e0a0501ae718407322e336cac561dd622ad414d3e8d8916f74db4',
            '8f357e5f52bac37e6c3d352aaf3fd8048cc8680d40b932d71482dda5b1b907c5',
            '7b25f42ce9a5331b3b54e4a3e6ac22f322ac43dbaca60b159d76bcd71c7941fa',
            '6a01403b56ce709edd311c8da55d41a9fea642ca917f71b48476885638bc2811',
            '5f0cc92cf7be3b99c630cd573430bd352ae9d6ffcd26bc5497caeb52bbf3e977',
            '58e687d926b2abad8f34e115ef59f747ffa85686be3ba88815b5ba640c01d402',
            '5463db6698bac760da2331e4182f3edf2d3ecec4d7d7fae6eb8ad21cfc6204c9',
            '42841fa76a617cf6844bc6633cb39ded4e44618c10dc8901986797d9d8ce5d84',
            '381889955b13ffa30cf1c9b76ca6761f7e3c97acc431b9b26a9aec3a6590bae1',
            '2f3c5932809f0c2b9bef6deab4175cb8a559e6466e33c45517ea03c6f2b53e7a',
            '20451391e40b588220b5141f0e8eeef3a78d6a6ac9ee0feba5b6ec373274f776',

            # msttsloc_onecore.dll
            '0275ad2274d2c14e80b09e4c388b9a1d2c93a403abc184b917a1ef8f51f493d6',
            '1a3f05cf6028c34dfcb766cdca7450983c74a8e4c970cbcf148bf334d270d878',
            '2680cb65257dcd26e85be7823de9572569c71dc9d62b268dc908fd162052ccfe',
            '42bc1acd8dbea042e4a618cd819ded0972487a8d61eb03a5efa3d58e77c7272c',
            '46e389dbfef2e8682e1e7632e14466b268b7bb37d11d13c8d7f429c42baefe89',
            '57154cfa259f7b372c1d392f434f8bd096859d49574ee69a04156956f6721e97',
            '5888c1ff3c3bf8bb0a1d7b4602c4abf0d047e1a61a61336551d013a45a50a989',
            '59f86bf6d94b1afb56696583298cb3f8288e58540b6a113786ed46dedd9747bb',
            '7bd26697358aaf3bd16a023cd65093b3eaf9e405db738f89a2b540a15f71b636',
            '813f48d24008dd807687480c271d83454b356c5f9fa4122f43aa2def2cc79971',
            '8c29ff4fb5c5ca3e56556bf3c9acf97c11289eb61fa626ffffdc4022f87c07ac',
            '971cc04dc9e4423fe24e0c3c750951c9975af111b527a528afe6a025e65df1ca',
            'a0b868086e475e3873da3c26956f88bef5d1b336f31a25990e3d1cbba49e50aa',
            'a0d49e6b4e2262aae0ea920a4fe9036de46023e0936d716b94c8fb8e46f62d86',
            'b909d09a16b2e1ae8bbef6b7a33b4db8847f3d4f487f00f7a00e047d58200042',
            'c5db92e1e5c3f0c980205d4ffe34da9a730d3da4c508f51da67827352975b2d0',
            'cf7869eaec115d053bcc4c26f706b0906f5f3ddf7fa313fb07e6158ee5a9c9c0',
            'e1ed8425c70f57b58c1d42618c3bf5af3431120bc118c274cc0ae2a08ca77984',
            'e7e5b66090eb9238946024db9596c3f2082db4e78055190de632e9dd366547be',
            'fa549bc04592a7dfbfaaaa7b29f454ab2d008733c54be029e74b17e5c3ef370d',

            # rdpnano.dll
            '0fca6227972e72fedb79b6404f2a914e03854563c73895e0ff08c00bb1ec360b',
            '47226fbae75dd10db902e7d9fea6ac35b8307345aa645e94b6b9dcddbde854fa',
            'b4b841299a1915acb86341ac2bd30116f4cbff61cf0a5953e440dd4e74546f46',

            # microsoft.identityserver.web.resources.dll
            'beec15a0ff06d14f749323b37e8e6cfd004fcf458ad6e2cdab29fed1b19dd8e2',

            # windows.media.dll
            '8a2d3656512aa0e18410f450d64be6a343c372324fc937664a6e522228e5695c',

            # msttsengine.dll
            '07738d6463336020e6f0ab08d3b289ffaa4cf63d92e82922b055ebfb130be659',
            '4075db17b433e3bc65afb2ae8750169568ae6cbb0f5120777a2fc261dcfacf2d',
            'a01432b9b3dfdb5f808f87c043deb551ee23fae93dbe609801e0263705435c10',

            # msttsloc.dll
            'e4530349fed4fd1ceab455f70e1a0698e467e21c070f38140410c95e5f08d77e',
            'fb9cb560f224f0284465b14b7c89dc4831ce2b3f837a37ea4e350c148d21ddf5',

            # rdpcorets.dll
            '8ab519e778998d195f29561384cb148825d57e83d8672e6adf140b40ba063de9',

            # mshtmled.dll
            '591ca99e103a802608ba0ab6c5cb3450192813fd8f69dd821d6cb5403d093d51',

            # appxdeploymentserver.dll
            '269392facd1ee472aa824ad3a70d377b81679f379a7f416c8606268a5efcca19',
        ]:
            assert file_info_1.keys() - {'signingDate'} == file_info_2.keys() - {'signingDate'}, (file_info_1, file_info_2)
        else:
            assert file_info_1.keys() - {'signingDate', 'version', 'description'} == file_info_2.keys() - {'signingDate', 'version', 'description'}, (file_info_1, file_info_2)
    # }

    for key in file_info_1.keys() - {'signingStatus', 'signingDate'}:
        assert file_info_1[key] == file_info_2[key], (file_info_1, file_info_2)

    if 'signingStatus' in file_info_1:
        if file_info_1['signingStatus'] == 'Unknown':
            assert file_info_2['signingStatus'] != 'Unsigned'
        elif file_info_2['signingStatus'] == 'Unknown':
            assert file_info_1['signingStatus'] != 'Unsigned'
        else:
            assert file_info_1['signingStatus'] == file_info_2['signingStatus']

    if 'signingDate' in file_info_1 and 'signingDate' in file_info_2:
        if file_info_1['signingDate'] != [] and file_info_2['signingDate'] != []:
            # Compare only first date.
            datetime1 = datetime.fromisoformat(file_info_1['signingDate'][0])
            datetime2 = datetime.fromisoformat(file_info_2['signingDate'][0])
            difference = datetime1 - datetime2
            hours = abs(difference.total_seconds()) / 3600

            # VirusTotal returns the time in a local, unknown timezone.
            # "the maximum difference could be over 30 hours", https://stackoverflow.com/a/8131056
            assert hours <= 32, f'{hours} {file_info_1["sha256"]}'
        else:
            assert file_info_1['signingDate'] == []
            assert file_info_2['signingDate'] == []
    else:
        # If the signature is invalid (but exists), VirusTotal doesn't return dates, but we do.
        if 'signingDate' not in file_info_1:
            assert file_info_1['signingStatus'] != 'Signed'

        if 'signingDate' not in file_info_2:
            assert file_info_2['signingStatus'] != 'Signed'


def update_file_info(existing_file_info, new_file_info, new_file_info_source):
    if existing_file_info is None:
        return new_file_info

    if new_file_info is None:
        return existing_file_info

    assert_file_info_close_enough(existing_file_info, new_file_info)

    if new_file_info_source == 'iso':
        new_file_info_type = 'file'
    elif new_file_info_source == 'vt':
        new_file_info_type = 'vt'
    elif new_file_info_source == 'update':
        new_file_info_type = get_file_info_type(new_file_info)
        if new_file_info_type == 'vt_or_file':
            new_file_info_type = 'file'
    else:
        assert False

    existing_file_info_type = get_file_info_type(existing_file_info)

    sources = [
        'raw',
        'raw_file',
        'delta',
        'delta+',
        'pe',
        # 'file_unknown_sig',
        'vt',
        'vt_or_file',
        'file',
    ]

    # Special merge: file_unknown_sig data is more reliable than VirusTotal's.
    # Only add signingStatus.
    unknown_sig_file_info = None
    other_file_info = None
    other_file_info_type = None
    if existing_file_info_type == 'file_unknown_sig' and new_file_info_type == 'file_unknown_sig':
        # Temporarily prefer new file info. TODO: remove.
        unknown_sig_file_info = new_file_info
        other_file_info = existing_file_info
        other_file_info_type = existing_file_info_type
    elif existing_file_info_type == 'file_unknown_sig':
        unknown_sig_file_info = existing_file_info
        other_file_info = new_file_info
        other_file_info_type = new_file_info_type
    elif new_file_info_type == 'file_unknown_sig':
        unknown_sig_file_info = new_file_info
        other_file_info = existing_file_info
        other_file_info_type = existing_file_info_type

    if unknown_sig_file_info and other_file_info and other_file_info_type:
        if 'signingStatus' not in other_file_info:
            return unknown_sig_file_info

        assert other_file_info['signingStatus'] != 'Unsigned'
        assert other_file_info['signatureType'] == unknown_sig_file_info['signatureType']

        # Unless the file is from VirusTotal, the dates should be identical.
        if (
            other_file_info_type not in ['vt', 'vt_or_file']
            and other_file_info.get('signingDate') != unknown_sig_file_info.get('signingDate')
        ):
            print(
                f'WARNING: Updating signing date of {other_file_info["sha256"]}:'
                f' {other_file_info["signingDate"]} ->'
                f' {unknown_sig_file_info["signingDate"]}'
            )

        return unknown_sig_file_info | {
            'signingStatus': other_file_info.get('signingStatus'),
        }

    if sources.index(new_file_info_type) > sources.index(existing_file_info_type):
        return new_file_info

    return existing_file_info


def add_file_info_from_update(data, *,
                              file_hash,
                              virustotal_file_info,
                              windows_version,
                              update_kb,
                              update_info,
                              manifest_name,
                              assembly_identity,
                              attributes,
                              delta_or_pe_file_info):
    x = data.setdefault(file_hash, {})

    updated_file_info = update_file_info(x.get('fileInfo'), delta_or_pe_file_info, 'update')
    updated_file_info = update_file_info(updated_file_info, virustotal_file_info, 'vt')
    if updated_file_info:
        x['fileInfo'] = updated_file_info

    x = x.setdefault('windowsVersions', {})
    x = x.setdefault(windows_version, {})
    x = x.setdefault(update_kb, {})

    if 'updateInfo' not in x:
        x['updateInfo'] = update_info
    else:
        assert x['updateInfo'] == update_info

    x = x.setdefault('assemblies', {})
    x = x.setdefault(manifest_name, {})

    if 'assemblyIdentity' not in x:
        x['assemblyIdentity'] = assembly_identity
    else:
        assert x['assemblyIdentity'] == assembly_identity

    x = x.setdefault('attributes', [])

    if attributes not in x:
        x.append(attributes)

    return data


virustotal_info_cache = {}


def get_virustotal_info(file_hash):
    # https://stackoverflow.com/a/57027610
    def is_power_of_two(n):
        return (n != 0) and (n & (n-1) == 0)

    def align_by(n, alignment):
        return ((n + alignment - 1) // alignment) * alignment

    if config.high_mem_usage_for_performance and file_hash in virustotal_info_cache:
        return virustotal_info_cache[file_hash]

    if len(file_hash) == 64:
        # SHA256, the default.
        source_dir = 'virustotal'
    elif len(file_hash) == 40:
        source_dir = 'virustotal_sha1'
    else:
        assert False, file_hash

    filename = config.out_path.joinpath(source_dir, file_hash + '.json')
    if not filename.is_file():
        if config.high_mem_usage_for_performance:
            virustotal_info_cache[file_hash] = None
        return None

    with open(filename) as f:
        data = json.load(f)

    attr = data['data']['attributes']

    first_section = attr['pe_info']['sections'][0]

    # Handle special cases.
    if attr.get('signature_info', {}).get('description') in config.tcb_launcher_descriptions:
        assert first_section['virtual_address'] in config.tcb_launcher_large_first_section_virtual_addresses, file_hash
        section_alignment = 0x1000
    elif unusual_section_alignment_info := config.file_hashes_unusual_section_alignment.get(file_hash):
        assert first_section['virtual_address'] == unusual_section_alignment_info['first_section_virtual_address']
        section_alignment = unusual_section_alignment_info['section_alignment']
    else:
        section_alignment = first_section['virtual_address']
        assert is_power_of_two(section_alignment), file_hash

    virtual_size = first_section['virtual_address']
    for section in attr['pe_info']['sections']:
        assert virtual_size == section['virtual_address'], file_hash
        virtual_size += align_by(section['virtual_size'], section_alignment)

    if 'timestamp' in attr['pe_info']:
        timestamp = attr['pe_info']['timestamp']
    else:
        assert file_hash in config.file_hashes_zero_timestamp, file_hash
        timestamp = 0

    info = {
        'size': attr['size'],
        'md5': attr['md5'],
        'sha1': attr['sha1'],
        'sha256': attr['sha256'],
        'machineType': attr['pe_info']['machine_type'],
        'timestamp': timestamp,
        'virtualSize': virtual_size,
    }

    has_signature_overlay = False
    if 'overlay' in attr['pe_info']:
        overlay_size = attr['pe_info']['overlay']['size']
        if overlay_size < 0x20:
            assert file_hash in config.file_hashes_small_non_signature_overlay, file_hash
        elif file_hash in config.file_hashes_unsigned_with_overlay:
            pass
        elif any(attr.get('signature_info', {}).get(x['k']) == x['v'] and overlay_size == x['overlay_size']
                 for x in config.file_details_unsigned_with_overlay):
            pass
        else:
            has_signature_overlay = True

    info['signingStatus'] = 'Unsigned'
    file_signed = False

    if 'signature_info' in attr:
        signature_info = attr['signature_info']

        if 'file version' in signature_info:
            info['version'] = signature_info['file version']

        if 'description' in signature_info:
            info['description'] = signature_info['description']

        signing_date_reliable = False
        if 'verified' in signature_info:
            info['signingStatus'] = signature_info['verified']
            info['signatureType'] = 'Overlay' if has_signature_overlay else 'Catalog file'
            file_signed = True

            # If the value is something else, the "signing date" is often the analysis date.
            if signature_info['verified'] == 'Signed':
                signing_date_reliable = True

        if has_signature_overlay and 'signing date' in signature_info and signing_date_reliable:
            spaces = signature_info['signing date'].count(' ')
            if spaces == 1:
                # Examples:
                # 9:51 09/05/2020
                # 13:18 21/02/2020
                date_format = '%H:%M %d/%m/%Y'
            else:
                assert spaces == 2, file_hash
                # Examples:
                # 8:30 AM 2/7/2020
                # 5:47 PM 9/19/2019
                date_format = '%I:%M %p %m/%d/%Y'

            datetime_object = datetime.strptime(signature_info['signing date'], date_format)
            info['signingDate'] = [datetime_object.isoformat()]

            # If this assertion fails, the "signing date" might be the analysis
            # date, in which case the signature type is "Catalog file", and
            # has_signature_overlay should be False.
            assert datetime_object.timestamp() < attr['first_submission_date'], file_hash

    assert not has_signature_overlay or file_signed, file_hash

    if config.high_mem_usage_for_performance:
        virustotal_info_cache[file_hash] = info
    else:
        virustotal_info_cache[file_hash] = True

    return info


def group_update_assembly_by_filename(filename, file_manifest_data, output_dir: Path, *,
                                      windows_version,
                                      update_kb,
                                      update_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rb') as f:
                data = orjson.loads(f.read())
        else:
            data = {}

    for item in file_manifest_data:
        file_hash_sha256 = item['file_hash_sha256']
        file_hash_sha1 = item['file_hash_sha1']
        file_hash_md5 = item['file_hash_md5']
        manifest_name = item['manifest_name']
        assembly_identity = item['assembly_identity']
        attributes = item['attributes']
        delta_or_pe_file_info = item['delta_or_pe_file_info']

        if file_hash_sha256 is not None:
            hash_is_sha256 = True
            file_hash = file_hash_sha256
        else:
            hash_is_sha256 = False
            file_hash = file_hash_sha1

        virustotal_info = get_virustotal_info(file_hash)
        if virustotal_info and file_hash != virustotal_info['sha256']:
            assert file_hash == virustotal_info['sha1']
            file_hash = virustotal_info['sha256']
            hash_is_sha256 = True

        if not hash_is_sha256:
            if config.allow_missing_sha256_hash:
                print(f'WARNING: No SHA256 hash for {filename} ({file_hash}) in {manifest_name}')
                continue
            raise Exception('No SHA256 hash')

        # Skip files with what seems to be a hash mismatch.
        if (file_hash, file_hash_md5) in config.file_hashes_mismatch:
            assert windows_version in config.file_hashes_mismatch[(file_hash, file_hash_md5)]
            print(f'WARNING: Skipping file with (probably) an incorrect SHA256 hash: {file_hash}')
            print(f'         MD5 hash: {file_hash_md5}')
            print(f'         Manifest name: {manifest_name}')
            continue

        data = add_file_info_from_update(data,
            file_hash=file_hash,
            virustotal_file_info=virustotal_info,
            windows_version=windows_version,
            update_kb=update_kb,
            update_info=update_info,
            manifest_name=manifest_name,
            assembly_identity=assembly_identity,
            attributes=attributes,
            delta_or_pe_file_info=delta_or_pe_file_info)

    if config.high_mem_usage_for_performance:
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))


def get_file_details_from_assembly(assembly_path: Path):
    with open(assembly_path) as f:
        data = json.load(f)

    result = {}

    manifest_name = assembly_path.stem
    assembly_identity = data['assemblyIdentity']

    for file_item in data['files']:
        filename = file_item['attributes']['name'].split('\\')[-1].lower()

        result.setdefault(filename, []).append({
            'file_hash_sha256': file_item.get('sha256'),
            'file_hash_sha1': file_item.get('sha1'),
            'file_hash_md5': file_item.get('fileInfo', {}).get('md5'),
            'manifest_name': manifest_name,
            'assembly_identity': assembly_identity,
            'attributes': file_item['attributes'],
            'delta_or_pe_file_info': file_item.get('fileInfo'),
        })

    return result


def group_update_assembly_by_filename_worker(filename,
                                             file_details,
                                             output_dir,
                                             windows_version,
                                             update_kb,
                                             update,
                                             time_to_stop):
    if time_to_stop and datetime.now() >= time_to_stop:
        return False

    group_update_assembly_by_filename(filename, file_details, output_dir,
                                        windows_version=windows_version,
                                        update_kb=update_kb,
                                        update_info=update)
    return True


def group_update_by_filename(windows_version, update_kb, update, parsed_dir: Path, progress_state=None, time_to_stop=None):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    if progress_state:
        assert progress_state['update_kb'] == update_kb
        files_processed = set(progress_state['files_processed'])
    else:
        files_processed = set()

    file_details_from_assembly = {}
    for path in parsed_dir.glob('*.json'):
        if path.is_dir():
            continue

        details = get_file_details_from_assembly(path)
        for filename, file_details in details.items():
            if filename in files_processed:
                continue

            file_details_from_assembly.setdefault(filename, []).extend(file_details)

    if progress_state:
        files_unprocessed_count = len(file_details_from_assembly)

        if progress_state['files_total'] is None:
            assert files_processed == set()
            progress_state['files_total'] = files_unprocessed_count
        else:
            assert progress_state['files_total'] == len(files_processed) + files_unprocessed_count

    processes = config.group_by_filename_processes
    if processes > 1:
        # Global state is not shared between processes.
        assert not config.high_mem_usage_for_performance
        assert file_info_data == {}

        with Pool(processes) as pool:
            results = pool.starmap(group_update_assembly_by_filename_worker, zip(
                file_details_from_assembly.keys(),
                file_details_from_assembly.values(),
                repeat(output_dir),
                repeat(windows_version),
                repeat(update_kb),
                repeat(update),
                repeat(time_to_stop),
            ))
            file_details_from_assembly_results = dict(zip(file_details_from_assembly.keys(), results))

            for filename, result in file_details_from_assembly_results.items():
                if result:
                    files_processed.add(filename)
    else:
        for filename, file_details in file_details_from_assembly.items():
            if time_to_stop and datetime.now() >= time_to_stop:
                break

            try:
                group_update_assembly_by_filename(filename, file_details, output_dir,
                                                  windows_version=windows_version,
                                                  update_kb=update_kb,
                                                  update_info=update)
                files_processed.add(filename)
            except Exception as e:
                print(f'ERROR: failed to process {path}')
                print(f'       {e}')
                if config.exit_on_first_error:
                    raise

    if progress_state:
        progress_state['files_processed'] = sorted(files_processed)


def process_updates(progress_state=None, time_to_stop=None):
    updates_path = config.out_path.joinpath('updates.json')
    if updates_path.is_file():
        with open(updates_path) as f:
            updates = json.load(f)
    else:
        updates = {}

    for windows_version in updates:
        print(f'Processing Windows version {windows_version}:')

        for update_kb in updates[windows_version]:
            update = updates[windows_version][update_kb]

            parsed_dir = config.out_path.joinpath('parsed', windows_version, update_kb)
            if parsed_dir.is_dir():
                group_update_by_filename(windows_version, update_kb, update, parsed_dir, progress_state, time_to_stop)
                print('  ' + update_kb)

    if progress_state and progress_state['files_total'] is None:
        progress_state['files_total'] = 0


def add_file_info_from_virustotal_data(filename, output_dir, *, file_hash, file_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rb') as f:
                data = orjson.loads(f.read())
        else:
            data = {}

    x = data[file_hash]

    updated_file_info = update_file_info(x.get('fileInfo'), file_info, 'vt')
    assert updated_file_info
    x['fileInfo'] = updated_file_info

    if config.high_mem_usage_for_performance:
        file_info_data[filename] = data
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        write_to_gzip_file(output_path, orjson.dumps(data))


def process_virustotal_data():
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    info_progress_virustotal_path = config.out_path.joinpath('info_progress_virustotal.json')
    if info_progress_virustotal_path.is_file():
        with open(info_progress_virustotal_path, 'r') as f:
            info_progress_virustotal = json.load(f)
    else:
        info_progress_virustotal = {}

    pending = info_progress_virustotal.get('pending', {})

    for name in pending:
        for file_hash in pending[name]:
            if file_hash in virustotal_info_cache:
                # Was already added with one of the updates.
                continue

            virustotal_info = get_virustotal_info(file_hash)
            assert virustotal_info is not None
            if file_hash != virustotal_info['sha256']:
                assert file_hash == virustotal_info['sha1']
                file_hash = virustotal_info['sha256']

            add_file_info_from_virustotal_data(name, output_dir,
                file_hash=file_hash,
                file_info=virustotal_info)

    info_progress_virustotal['pending'] = {}

    with open(info_progress_virustotal_path, 'w') as f:
        json.dump(info_progress_virustotal, f, indent=0, sort_keys=True)

    virustotal_info_cache.clear()


def add_file_info_from_iso_data(filename, output_dir, *, file_hash, file_info, source_path, windows_version, windows_version_info):
    if filename in file_info_data:
        data = file_info_data[filename]
    else:
        output_path = output_dir.joinpath(filename + '.json.gz')
        if output_path.is_file():
            with gzip.open(output_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {}

    x = data.setdefault(file_hash, {})

    updated_file_info = update_file_info(x.get('fileInfo'), file_info, 'iso')
    assert updated_file_info
    x['fileInfo'] = updated_file_info

    x = x.setdefault('windowsVersions', {})
    x = x.setdefault(windows_version, {})
    x = x.setdefault('BASE', {})

    if 'windowsVersionInfo' not in x:
        x['windowsVersionInfo'] = windows_version_info
    else:
        assert x['windowsVersionInfo'] == windows_version_info

    x = x.setdefault('sourcePaths', [])

    if source_path not in x:
        bisect.insort(x, source_path)

    file_info_data[filename] = data


def group_iso_data_by_filename(iso_data_file):
    output_dir = config.out_path.joinpath('by_filename_compressed')
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(iso_data_file) as f:
        iso_data = json.load(f)

    windows_version = iso_data['windowsVersion']
    iso_hash = iso_data['windowsIsoSha256']
    windows_release_date = iso_data['windowsReleaseDate']

    windows_version_info = {
        'releaseDate': windows_release_date,
        'isoSha256': iso_hash,
    }

    for file_item in iso_data['files']:
        filename = file_item['path'].split('\\')[-1].lower()

        source_path = file_item.pop('path')

        add_file_info_from_iso_data(filename, output_dir,
            file_hash=file_item['sha256'],
            file_info=file_item,
            source_path=source_path,
            windows_version=windows_version,
            windows_version_info=windows_version_info)


def process_iso_files():
    from_iso_dir = config.out_path.joinpath('from_iso')

    for iso_data_file in from_iso_dir.glob('*.json'):
        if iso_data_file.is_file():
            print('  ' + iso_data_file.stem)
            group_iso_data_by_filename(iso_data_file)


def main(progress_state=None, time_to_stop=None):
    print('Processing data from updates')
    process_updates(progress_state, time_to_stop)

    print('Processing data from VirusTotal')
    process_virustotal_data()

    print('Processing data from ISO files')
    process_iso_files()

    write_all_file_info()


if __name__ == '__main__':
    main()
