from ipaddress import ip_network
from typing import Iterator, Generator

from lib.core import Target, TargetConfig
from lib.util import is_ip, is_network


def create_target(target_str: str, target_config: TargetConfig) -> Iterator[Target]:
    kwargs = target_config.as_dict()
    if ':' not in target_str:
        if any([is_ip(target_str), is_network(target_str)]):
            hosts = ip_network(target_str, strict=False)
            for host in hosts:
                target = Target(ip=str(host), hostname='', **kwargs)
                yield target
        else:
            # fqdn?
            target = Target(hostname=target_str, ip='', **kwargs)
            yield target
    elif target_str.count(':') == 1:  # target:port
        _target_str, _port_str = target_str.split(':')
        if _port_str.isdigit():
            port_int = int(_port_str)
            if any([is_ip(_target_str), is_network(_target_str)]):
                hosts = ip_network(_target_str, strict=False)
                kwargs.pop('port')
                for host in hosts:
                    target = Target(ip=str(host), hostname='', port=port_int, **kwargs)
                    yield target
            else:
                # fqdn?
                kwargs.pop('port')
                target = Target(ip='', hostname=_target_str, port=port_int, **kwargs)
                yield target


def create_targets(target: str, settings: TargetConfig) -> Generator[Target, None, None]:
    """
    Функция для обработки "подсетей" и создания "целей"
    """
    sub_targets = create_target(target, settings)
    if sub_targets:
        for target in sub_targets:
            yield target
