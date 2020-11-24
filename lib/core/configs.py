from collections import namedtuple
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class AppConfig:
    senders: int
    queue_sleep: int
    statistics: bool
    input_file: str
    input_stdin: str
    single_targets: str
    output_file: str
    output_format: str
    write_mode: str
    filter_jarm: str
    filter_cipher_tls: str
    show_only_success: bool


@dataclass(frozen=True)
class TargetConfig:
    port: int
    conn_timeout: int
    read_timeout: int
    resolver_timeout: int
    list_payloads: List[bytes]


    def as_dict(self):
        return {
            'port': self.port,
            'conn_timeout': self.conn_timeout,
            'read_timeout': self.read_timeout,
            'resolver_timeout': self.resolver_timeout,
            'list_payloads': self.list_payloads,
        }


Target = namedtuple('Target', ['port', 'resolver_timeout', 'conn_timeout', 'read_timeout', 'list_payloads',
                               'ip', 'hostname'])
