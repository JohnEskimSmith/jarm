import argparse
from os import path
from sys import stderr
from typing import Tuple, List
from lib.core import AppConfig, TargetConfig

__all__ = ['parse_args', 'parse_settings']


def parse_args():
    """
    parsing arguments
    :return:
    """
    parser = argparse.ArgumentParser(description='JARM is an active Transport Layer Security (TLS) server fingerprinting tool. (Asyncio version)',
                                     formatter_class=argparse.MetavarTypeHelpFormatter)
    # input_stdin: str
    parser.add_argument('--stdin', dest='input_stdin', action='store_true', help='Read targets from stdin')
    parser.add_argument('-t', '--targets', nargs='+', type=str, default='', dest='single_targets',
                        help='Single targets: ipv4, fqdn, ipv4:port, fqdn:port. Example: facebook.com google.com:443 67.99.200.0/24:8443')
    parser.add_argument('-f', '--input-file', dest='input_file', type=str, help='path to file with targets.\n Targets: ipv4, fqdn, ipv4:port, fqdn:port')
    parser.add_argument('-o', '--output-file', dest='output_file', type=str, help='path to file with results')
    parser.add_argument('--json', dest='json', action='store_true', default=True, help='Output format of records, default json')
    parser.add_argument('--csv', dest='csv', action='store_true', help='Output format of records: csv')
    parser.add_argument('-s', '--senders', dest='senders', type=int, default=1024,
                        help='Number of send coroutines to use (default: 1024)')
    parser.add_argument('--queue-sleep', dest='queue_sleep', type=int, default=1,
                        help='Sleep duration if the queue is full, default 1 sec. Queue size == senders')
    parser.add_argument('-tconnect', '--timeout-connection', dest='conn_timeout', type=int, default=7,
                        help='Set connection timeout for open_connection(asyncio), seconds (default: 7)')
    parser.add_argument('-tread', '--timeout-read', dest='read_timeout', type=int, default=7,
                        help='Set connection timeout for reader from connection, seconds (default: 7)')
    parser.add_argument('-tresolver', '--resolver-timeout', dest='resolver_timeout', type=int, default=3,
                        help='Set DNS resolutions timeout, seconds (default: 3)')
    parser.add_argument('-p', '--port', type=int, help='Specify port (default: 443)', default=443)

    # region filters
    parser.add_argument('--filter-jarm', dest='jarm', type=str,
                        help='trying to find a jarm in a response')
    parser.add_argument('--filter-cipher-tls', dest='cipher_tls', type=str,
                        help='trying to find a cipher_tls(substring in jarm)')
    parser.add_argument('--show-only-success', dest='show_only_success', action='store_true',
                        help='Show(save) only success records')
    # endregion
    parser.add_argument('--show-statistics', dest='statistics', action='store_true')
    return parser.parse_args()


def parse_settings(args: argparse.Namespace) -> Tuple[TargetConfig, AppConfig]:
    if not args.input_stdin and not args.input_file and not args.single_targets:
        print("""errors, set input source:
         --stdin read targets from stdin;
         -t,--targets set targets, see -h;
         -f,--input-file read from file with targets, see -h""")
        exit(1)
    input_file = None
    if args.input_file:
        input_file = args.input_file
        if not path.isfile(input_file):
            abort(f'ERROR: file not found: {input_file}')

    if not args.output_file:
        output_file, write_mode = '/dev/stdout', 'wb'
    else:
        output_file, write_mode = args.output_file, 'a'

    payloads = return_structs_tls()
    # endregion

    if not args.csv:
        output_format = 'json'
    else:
        output_format = 'csv'

    filter_jarm = ''
    if args.jarm:
        filter_jarm = args.jarm

    filter_cipher_tls = ''
    if args.cipher_tls:
        filter_cipher_tls = args.cipher_tls

    target_settings = TargetConfig(**{
        'port': args.port,
        'conn_timeout': args.conn_timeout,
        'read_timeout': args.read_timeout,
        'resolver_timeout': args.resolver_timeout,
        'list_payloads': payloads,
    })

    app_settings = AppConfig(**{
        'output_format': output_format,
        'input_stdin': args.input_stdin,
        'senders': args.senders,
        'queue_sleep': args.queue_sleep,
        'statistics': args.statistics,
        'single_targets': args.single_targets,
        'input_file': input_file,
        'output_file': output_file,
        'write_mode': write_mode,
        'filter_jarm': filter_jarm,
        'filter_cipher_tls': filter_cipher_tls,
        'show_only_success': args.show_only_success
    })

    return target_settings, app_settings


def return_structs_tls() -> List[List[str]]:
    """
    function from jarm.py with changes
    :return:
    """

    #  Array format = [destination_host,destination_port,version,cipher_list,cipher_order,GREASE,RARE_APLN,1.3_SUPPORT,extension_orders]
    tls1_2_forward = ["TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN",
                      "1.2_SUPPORT", "REVERSE"]
    tls1_2_reverse = ["TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN",
                      "1.2_SUPPORT", "FORWARD"]
    tls1_2_top_half = ["TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN",
                       "NO_SUPPORT", "FORWARD"]
    tls1_2_bottom_half = ["TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN",
                          "NO_SUPPORT", "FORWARD"]
    tls1_2_middle_out = ["TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN",
                         "NO_SUPPORT", "REVERSE"]
    tls1_1_middle_out = ["TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN",
                         "NO_SUPPORT", "FORWARD"]
    tls1_3_forward = ["TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN",
                      "1.3_SUPPORT", "REVERSE"]
    tls1_3_reverse = ["TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN",
                      "1.3_SUPPORT", "FORWARD"]
    tls1_3_invalid = ["TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN",
                      "1.3_SUPPORT", "FORWARD"]
    tls1_3_middle_out = ["TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN",
                         "1.3_SUPPORT", "REVERSE"]
    # Possible versions: SSLv3, TLS_1, TLS_1.1, TLS_1.2, TLS_1.3
    # Possible cipher lists: ALL, NO1.3
    # GREASE: either NO_GREASE or GREASE
    # APLN: either APLN or RARE_APLN
    # Supported Verisons extension: 1.2_SUPPPORT, NO_SUPPORT, or 1.3_SUPPORT
    # Possible Extension order: FORWARD, REVERSE
    queue_tls = [tls1_2_forward, tls1_2_reverse, tls1_2_top_half, tls1_2_bottom_half, tls1_2_middle_out,
                  tls1_1_middle_out, tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out]
    return queue_tls


def abort(message: str, exc: Exception = None, exit_code: int = 1):
    print(message, file=stderr)
    if exc:
        print(exc, file=stderr)
    exit(exit_code)


