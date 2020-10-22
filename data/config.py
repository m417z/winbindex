from pathlib import Path

out_path = Path('.')
verbose_run = False
verbose_progress = True
extract_in_a_new_thread = False
exit_on_first_error = True
high_mem_usage_for_performance = False
compression_level = 9

# Key: version to skip, value: version containing the same updates.
windows_versions_to_skip = {
    '1909': '1903',
    '20H2': '2004',
}

windows_update_urls_to_skip = [
    'https://support.microsoft.com/en-us/help/4001884',  # Same update as https://support.microsoft.com/en-us/help/4001883
    'https://support.microsoft.com/en-us/help/4001886',  # Same update as https://support.microsoft.com/en-us/help/4001885
]
