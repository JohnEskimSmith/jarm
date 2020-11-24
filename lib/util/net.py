from ipaddress import ip_network, ip_address
from aiodns import DNSResolver
from asyncio import wait_for
from typing import Union
__all__ = ['is_ip', 'is_network', 'hostname_resolver']


async def hostname_resolver(hostname: str, resolver_timeout: int) -> Union[str, None]:
    """
    Resolve fqdn, hostname -> ip address

    :param hostname:
    :param resolver_timeout:
    :return:
    """
    try:
        resolver = DNSResolver()
        _resolver = resolver.query(hostname, 'A')
        result = await wait_for(_resolver, timeout=resolver_timeout)
        if result:
            ip_address_hostname = result[0].host
            if ip_address_hostname != '127.0.0.1':
                return ip_address_hostname
    except BaseException as e:
        return None


def is_ip(ip_str: str) -> bool:
    """
    Checks if string is IP address
    """
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_network(net_str: str) -> bool:
    """
    Checks if string is network address
    """
    try:
        ip_network(net_str)
        return True
    except ValueError:
        return False
