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
