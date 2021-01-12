from pathlib import Path

out_path = Path('.')
verbose_run = False
verbose_progress = True
extract_in_a_new_thread = False
exit_on_first_error = True
high_mem_usage_for_performance = False
compression_level = 9

# Key: a newer version with overlapping updates, value: an older version.
windows_with_overlapping_updates = {
    '1909': '1903',
    '20H2': '2004',
}

# Key: URL to skip, value: URL containing the same update.
windows_update_urls_to_skip = {
    'https://support.microsoft.com/en-us/help/4001884': 'https://support.microsoft.com/en-us/help/4001883',  # KB3198586
    'https://support.microsoft.com/en-us/topic/november-14-2016-kb3198586-os-build-10586-682-030d9a7a-9ecd-bf55-dad8-fe06f9e0f24c':
        'https://support.microsoft.com/en-us/topic/november-8-2016-kb3198586-os-build-10586-679-36734488-c893-d05f-7c19-43f1fcdc82b1',  # KB3198586 (alternative URL)
    'https://support.microsoft.com/en-us/help/4001886': 'https://support.microsoft.com/en-us/help/4001885',  # KB3200970
}
