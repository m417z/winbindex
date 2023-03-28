from pathlib import Path

out_path = Path('.')
index_of_hashes_out_path = Path('..', 'hashes')

windows_versions_unsupported = set()

updates_unsupported = {
    # ARM only.
    'KB5016138',
    'KB5016139',
}

updates_architecture = 'x64'

verbose_run = False
verbose_progress = True
extract_in_a_new_thread = False
exit_on_first_error = True
high_mem_usage_for_performance = False
compression_level = 3

delta_machine_type_values_supported = {
    'CLI4_I386',
    'CLI4_AMD64',
    # 'CLI4_ARM',
    'CLI4_ARM64',
}

# Non-PE files (very rare).
file_hashes_non_pe = set()
