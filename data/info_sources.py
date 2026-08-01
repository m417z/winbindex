from enum import StrEnum
import json

import config

# The names are split into a file per bucket to keep the individual files small.
BUCKETS = [f'{bucket:02x}' for bucket in range(0x100)]


class InfoSource(StrEnum):
    """Where the information about a file comes from, declared from the least to the most informative."""

    NONE = 'none'
    DELTA = 'delta'
    DELTA_PLUS = 'delta+'
    PE = 'pe'
    VT = 'vt'
    FILE = 'file'

    @property
    def information_rank(self) -> int:
        """Position among all sources, the more information the source holds the higher."""
        return list(InfoSource).index(self)


def best_source(old: InfoSource | None, new: InfoSource) -> InfoSource:
    """Return the one of the two sources which holds more information."""
    if old is None or new.information_rank > old.information_rank:
        return new

    return old


class InfoSources:
    """The info source of every known file hash, stored in the info_sources folder."""

    def __init__(self, sources_by_name: dict[str, dict[str, InfoSource]]):
        self.sources_by_name = sources_by_name

    @staticmethod
    def path():
        return config.out_path.joinpath('info_sources')

    @classmethod
    def bucket_path(cls, bucket: str):
        return cls.path().joinpath(f'{bucket}.json')

    @classmethod
    def load(cls) -> 'InfoSources':
        """Load the stored data, defaulting to no known files if nothing was stored yet."""
        sources_by_name = {}

        for bucket in BUCKETS:
            path = cls.bucket_path(bucket)
            if not path.is_file():
                continue

            with open(path, 'r') as f:
                stored = json.load(f)

            for name in stored:
                sources_by_name[name] = {file_hash: InfoSource(source)
                                         for file_hash, source in stored[name].items()}

        return cls(sources_by_name)

    def save(self):
        self.path().mkdir(parents=True, exist_ok=True)

        sources_by_bucket = {bucket: {} for bucket in BUCKETS}

        for name in self.sources_by_name:
            sources_by_bucket[config.filename_bucket(name)][name] = self.sources_by_name[name]

        for bucket in BUCKETS:
            with open(self.bucket_path(bucket), 'w') as f:
                json.dump(sources_by_bucket[bucket], f, indent=0, sort_keys=True)

    def names(self):
        return self.sources_by_name.keys()

    def file_hashes(self, name: str):
        return self.sources_by_name[name].keys()

    def get_source(self, name: str, file_hash: str) -> InfoSource:
        return self.sources_by_name[name][file_hash]

    def set_source(self, name: str, file_hash: str, source: InfoSource):
        self.sources_by_name[name][file_hash] = source

    def update_sources(self, sources_by_name: dict[str, dict[str, InfoSource]]):
        """Merge in a name to file hash to source mapping, keeping the source with more information."""
        for name in sources_by_name:
            file_sources = self.sources_by_name.setdefault(name, {})
            for file_hash in sources_by_name[name]:
                new = sources_by_name[name][file_hash]
                file_sources[file_hash] = best_source(file_sources.get(file_hash), new)

    def get_file_hashes_by_source(self, sources) -> dict[str, set[str]]:
        """Map each name to the set of its file hashes with one of the given sources, omitting names with none."""
        result = {}

        for name in self.sources_by_name:
            file_sources = self.sources_by_name[name]
            file_hashes = set(file_hash for file_hash in file_sources if file_sources[file_hash] in sources)
            if file_hashes:
                result[name] = file_hashes

        return result

    def remove_file_hashes(self, names_and_hashes: set):
        """Remove the given (name, file hash) pairs, dropping names which are left without file hashes."""
        for name, file_hash in names_and_hashes:
            file_sources = self.sources_by_name.get(name)
            if file_sources is None:
                continue

            file_sources.pop(file_hash, None)
            if not file_sources:
                del self.sources_by_name[name]

    def count_by_source(self) -> dict[InfoSource, int]:
        """Count the file hashes of each source, including sources without file hashes."""
        counts = {source: 0 for source in InfoSource}

        for file_sources in self.sources_by_name.values():
            for source in file_sources.values():
                counts[source] += 1

        return counts
