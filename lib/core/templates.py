from typing import List, Dict

__all__ = ['create_error_template', 'make_document_from_responses']

ONLY_ZERO_VALUES = "00000000000000000000000000000000000000000000000000000000000000"


def create_error_template(record: dict,
                          error_str: str) -> dict:
    """
    Creates skeleton of error result dictionary
    """

    result = {'ip': record['ip'],
              'port': record['port'],
              'data': {'jarm': {'status': 'unknown-error',
                                'error': ''}}}
    if 'error' in record:
        if record['error']:
            result['data']['jarm']['error'] = record['error']
    if 'raw_jarm' in record:
        if record['raw_jarm']:
            result['data']['jarm']['raw_jarm'] = record['raw_jarm']
    if error_str:
        result['data']['jarm']['error'] = error_str
    if 'hostname' in record:
        if record['hostname']:
            result['hostname'] = record['hostname']
    for k in list(result.keys()):
        if not result[k]:
            result.pop(k)
    return result


def create_result(key: str, ip: str, hostname: str, port: int, jarm: str):
    """

    :param key:
    :param ip:
    :param hostname:
    :param port:
    :param jarm:
    :return:
    """

    try:
        cipher_tls_version = jarm[:30]
    except:
        cipher_tls_version = ''
    try:
        sha256_of_tls_ext = jarm[30:]
    except:
        sha256_of_tls_ext = ''
    record = {'key': key,
              'ip': ip,
              'port': port,
              'hostname': hostname,
              'jarm': jarm,
              'cipher_tls': cipher_tls_version,
              'sha256_of_tls_ext': sha256_of_tls_ext}
    return record


def make_document_from_responses(raw_records: List[Dict],  output_format: str = 'json') -> dict:
    """

    :param raw_records:
    :param output_format:
    :return:
    """
    tmpresults = []
    results = None
    _tmp = []
    for record in raw_records:
        _row = (record['key'], record['ip'], record['hostname'], record['port'], record['jarm'])
        record: dict = create_result(*_row)
        if record['jarm'] not in _tmp:
            _tmp.append(record['jarm'])
            tmpresults.append(record)
    del _tmp

    if len(tmpresults) == 2:
        results = tmpresults
    if len(tmpresults) == 1:
        record = tmpresults[0]
        if record.get('hostname') and record.get('ip'):
            record['key'] = 'any'
        tmpresults[0] = record
        results = tmpresults
    if results:

        need_struct = {'ip': results[0]['ip'],
                       'port': results[0]['port'],
                       'hostname': results[0]['hostname'],
                       'data': {'jarm': {}}}
        keys = ['jarm', 'cipher_tls', 'sha256_of_tls_ext']
        for row in results:
            if row['jarm'] != ONLY_ZERO_VALUES:

                _tmp_dict = dict(zip(keys, [row[k] for k in keys]))
                need_struct['data']['jarm'][row['key']] =_tmp_dict

                need_struct['data']['jarm'][row['key']]['len'] = len(row['jarm'])
        for k in list(need_struct.keys()):
            if not need_struct[k]:
                need_struct.pop(k)
        check_keys = ['any', 'ipaddress', 'hostname']
        if any([k in need_struct['data']['jarm'] for k in check_keys]):
            need_struct['data']['jarm']['status'] = 'success'
            return need_struct
        error_str = 'seems ZERO in jarm'
        return create_error_template(raw_records[0], error_str)

    error_str = ''
    return create_error_template(raw_records[0], error_str)
