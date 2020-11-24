import abc
import asyncio
from abc import ABC
from asyncio import Queue
from typing import Optional, Callable, Any, Coroutine, List, Union
from aioconsole import ainput
from aiofiles import open as aiofiles_open
from ujson import dumps as ujson_dumps
from copy import deepcopy as copy_deepcopy

from lib.core import create_error_template, make_document_from_responses, Stats, AppConfig, \
    Target, TargetConfig, packet_building, read_packet, CONST_SIZE_READ_BYTES, jarm_hash
from lib.util import access_dot_path, write_to_file, write_to_stdout, hostname_resolver
from .factories import create_targets

__all__ = ['QueueWorker', 'TargetReader', 'TargetFileReader', 'TargetStdinReader', 'TaskProducer', 'Executor',
           'OutputPrinter', 'TargetWorker', 'create_io_reader', 'get_async_writer']

STOP_SIGNAL = b'check for end'


def create_filtred_output_record(record: dict,
                                 output_format: str,
                                 filter_jarm: str,
                                 filter_cipher_tls: str) -> List[str]:
    """

    :param record:
    :param output_format:
    :param filter_jarm:
    :param filter_cipher_tls:
    :return:
    """
    def local_sub_filter(_record: dict, filter_value: str, key: str) -> Union[dict, None]:
        if access_dot_path(_record, 'data.jarm.status') == 'success':  # only successful records have jarm values
            keys_to_jarm = [f'data.jarm.ipaddress.{key}',
                            f'data.jarm.hostname.{key}',
                            f'data.jarm.any.{key}']
            sub_keys = []
            for key in keys_to_jarm:
                sub_key = key.split('.')[-2]  # may be ipaddress, hostname, any
                sub_keys.append(sub_key)
                value = access_dot_path(_record, key)
                if value:
                    if value != filter_value:
                        _record['data']['jarm'].pop(sub_key)
            _records = [_record['data']['jarm'].get(k) for k in sub_keys]
            check_record = any(_records)
            if not check_record:
                return None
            else:
                return _record

    result_record = copy_deepcopy(record)
    if filter_jarm:
        result_record = local_sub_filter(result_record, filter_jarm, 'jarm')
    elif filter_cipher_tls:
        result_record = local_sub_filter(result_record, filter_cipher_tls, 'cipher_tls')
    results = []
    # i don't want to use a yield,
    # it will be may slow down when context switches in the program and will not save memory.
    if not result_record:
        return ['']
    else:
        if output_format == 'csv':
            ip: str = result_record.get('ip', '')
            hostname: str = result_record.get('hostname', '')
            port: str = str(result_record.get('port', ''))
            prefix_row = [ip, hostname, port]
            # format csv: ip,hostname,port,type_record,jarm,cipher_tls,sha256_of_tls_ext,len_jarm,
            if access_dot_path(result_record, 'data.jarm.status') == 'success':
                for key, value in result_record['data']['jarm'].items():
                    try:  # avoid checking the key 'status': data.jarm.status
                        _row = [key, value['jarm'], value['cipher_tls'], value['sha256_of_tls_ext'], str(value['len'])]
                        row = prefix_row + _row
                        row = ','.join(row)
                        results.append(row)
                    except:
                        pass
            else:
                empty_list = ['']*len(['type_record', 'jarm', 'cipher_tls', 'sha256_of_tls_ext', 'len_jarm'])
                row = ','.join(prefix_row+empty_list)
                return [row]
            return results

        else:
            return [ujson_dumps(result_record)]


class QueueWorker(metaclass=abc.ABCMeta):
    def __init__(self, stats: Optional[Stats] = None):
        self.stats = stats

    @abc.abstractmethod
    async def run(self):
        pass


class InputProducer:
    """
    Produces raw messages for workers
    """

    def __init__(self, stats: Stats, input_queue: Queue, target_conf: TargetConfig, send_limit: int, queue_sleep: int):
        self.stats = stats
        self.input_queue = input_queue
        self.target_conf = target_conf
        self.send_limit = send_limit
        self.queue_sleep = queue_sleep

    async def send(self, linein):
        targets = create_targets(linein, self.target_conf)  # generator
        if targets:
            for target in targets:
                check_queue = True
                while check_queue:
                    size_queue = self.input_queue.qsize()
                    if size_queue < self.send_limit:
                        if self.stats:
                            self.stats.count_input += 1
                        self.input_queue.put_nowait(target)
                        check_queue = False
                    else:
                        await asyncio.sleep(self.queue_sleep)

    async def send_stop(self):
        await self.input_queue.put(STOP_SIGNAL)


class TargetReader(QueueWorker, ABC):
    """
    Reads raw input messages from any source ans sends them to workers via producer
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer):
        super().__init__(stats)
        self.input_queue = input_queue
        self.producer = producer


class TargetFileReader(TargetReader):
    """
    Reads raw input messages from text file
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer, file_path: str):
        super().__init__(stats, input_queue, producer)
        self.file_path = file_path

    async def run(self):
        async with aiofiles_open(self.file_path, mode='rt') as f:
            async for line in f:
                linein = line.strip()
                if linein:
                    await self.producer.send(linein)

        await self.producer.send_stop()


class TargetSingleReader(TargetReader):
    """
    Reads --target input messages from args
    """

    def __init__(self, stats: Stats, input_queue: Queue, producer: InputProducer, single_targets: str):
        super().__init__(stats, input_queue, producer)
        self.single_targets = single_targets

    async def run(self):
        for single_target in self.single_targets:
            linein = single_target.strip()
            if linein:
                await self.producer.send(linein)
        await self.producer.send_stop()



class TargetStdinReader(TargetReader):
    """
    Reads raw input messages from STDIN
    """

    async def run(self):
        while True:
            try:
                linein = (await ainput()).strip()
                if linein:
                    await self.producer.send(linein)
            except EOFError:
                await self.producer.send_stop()
                break


class TaskProducer(QueueWorker):
    """
    Creates tasks for tasks queue
    """

    def __init__(self, stats: Stats, in_queue: Queue, tasks_queue: Queue, worker: 'TargetWorker'):
        super().__init__(stats)
        self.in_queue = in_queue
        self.tasks_queue = tasks_queue
        self.worker = worker

    async def run(self):
        while True:
            # wait for an item from the "start_application"
            target = await self.in_queue.get()
            if target == STOP_SIGNAL:
                await self.tasks_queue.put(STOP_SIGNAL)
                break
            if target:
                coro = self.worker.do(target)
                task = asyncio.create_task(coro)
                await self.tasks_queue.put(task)


class Executor(QueueWorker):
    """
    Gets tasks from tasks queue and launch execution for each of them
    """

    def __init__(self, stats: Stats, tasks_queue: Queue, out_queue: Queue):
        super().__init__(stats)
        self.tasks_queue = tasks_queue
        self.out_queue = out_queue

    async def run(self):
        while True:
            # wait for an item from the "start_application"
            task = await self.tasks_queue.get()
            if task == STOP_SIGNAL:
                await self.out_queue.put(STOP_SIGNAL)
                break
            if task:
                await task


class OutputPrinter(QueueWorker):
    """
    Takes results from results queue and put them to output
    """

    def __init__(self, output_file:str, stats: Stats, in_queue: Queue, io, async_writer) -> None:
        super().__init__(stats)
        self.in_queue = in_queue
        self.async_writer = async_writer
        self.io = io
        self.output_file = output_file

    async def run(self):
        while True:
            line = await self.in_queue.get()
            if line == STOP_SIGNAL:
                break
            if line:
                await self.async_writer(self.io, line)

        await asyncio.sleep(0.1)
        if self.stats:
            statistics = self.stats.dict()
            if self.output_file == '/dev/stdout':
                await self.io.write(ujson_dumps(statistics).encode('utf-8') + b'\n')
            else:
                async with aiofiles_open('/dev/stdout', mode='wb') as stats:
                    await stats.write(ujson_dumps(statistics).encode('utf-8') + b'\n')


async def send_one_payload(i: int,
                           payload,
                           target: str,
                           port: int,
                           timeout_connection:int,
                           timeout_read: int):
    """

    :param i: index of element from array utils_jarm.return_structs_tls
    :param payload:
    :param target: ipaddress
    :param port: network port
    :param timeout: timeout for open_connect
    :return:
    """

    future_connection = asyncio.open_connection(
        target, port)
    reader, writer = await asyncio.wait_for(future_connection, timeout=timeout_connection)
    payload_bytes = packet_building(payload)
    writer.write(payload_bytes)
    await asyncio.wait_for(writer.drain(), timeout_read)
    data = await asyncio.wait_for(reader.read(CONST_SIZE_READ_BYTES), timeout_read)
    try:
        future_connection.close()
    except Exception:
        await asyncio.sleep(0.05)
    try:
        writer.close()
    except Exception:
        pass
    return i, data


async def send_payloads(payloads: list, hostname_ip: str, target: Target):
    """

    :param payloads:
    :param hostname_ip:
    :param target:
    :return:
    """
    #  TODO: may be used like -->
    #   1.0 replace loop FOR by tasks = asyncio.gather([send_one_payload(i, payload) for i, payload in enumerate(payloads)])
    #   1.1 _jarm_list = await asyncio.gather(*tasks)
    #   1.2 and like jarm_list = [j[1] for j in sorted(_jarm_list, key=lambda x: x[0])]
    #   1.3 jarm = ','.join(jarm_list) (for example)
    #   need rethink
    jarm_list = []
    connection_call = 1
    connection_call_end = 5
    for i, payload in enumerate(payloads):
        try:
            _n, _data = await send_one_payload(i + 1, payload, hostname_ip, target.port,
                                         target.conn_timeout, target.read_timeout)
        except asyncio.TimeoutError:
            break
        except (ConnectionResetError, ConnectionRefusedError):
            connection_call += 1
            _data = None
            if connection_call > connection_call_end:
                break
        except Exception as e:
            _data = None
        try:
            data = read_packet(_data)
        except:
            pass
        else:
            jarm_list.append(data)
    if connection_call > connection_call_end:
        return None
    if jarm_list:
        jarm = ','.join(jarm_list)
        return jarm


class TargetWorker:
    """
    Runs payload against target
    """

    def __init__(self, stats: Stats, semaphore: asyncio.Semaphore, output_queue: asyncio.Queue, app_config: AppConfig):
        self.stats = stats
        self.semaphore = semaphore
        self.output_queue = output_queue
        self.success_only = app_config.show_only_success
        self.output_format = app_config.output_format
        self.filter_jarm = app_config.filter_jarm
        self.filter_cipher_tls = app_config.filter_cipher_tls

    # noinspection PyBroadException
    async def do(self, target: Target):
        """

        :param target:
        :return:
        """
        results = []
        result_document = None
        result = None
        hostname_ip = None
        async with self.semaphore:
            #  payloads_ip -list of lists [[ip, port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN"...]...]
            payloads_ip = []
            #  payloads_hostname - list of lists [[hostname, port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN"...]...]
            payloads_hostname = []
            if target.ip:  # if searching by ip, creating only payloads_ip
                for row in target.list_payloads:
                    _sub_line = [target.ip, target.port]+row
                    payloads_ip.append(_sub_line)
                hostname_ip = target.ip
            elif target.hostname:  # if searching by hostname(FQDN), creating  payloads_hostname and payloads_ip
                hostname_ip = await hostname_resolver(target.hostname, target.resolver_timeout)
                if hostname_ip:  # checks: was the hostname resolved in ip
                    for row in target.list_payloads:
                        _sub_line = [target.hostname, target.port] + row
                        payloads_hostname.append(_sub_line)
                    for row in target.list_payloads:
                        _sub_line = [hostname_ip, target.port] + row
                        payloads_ip.append(_sub_line)
            # and we have 2 List: payloads_ip, payloads_hostname
            if not payloads_hostname and not payloads_ip:  # not resolved FQDN to ip
                response = {'port': target.port,
                            'ip': "",
                            'hostname': target.hostname,
                            'jarm': '',
                            'status': 'error'}
                result_document = create_error_template(response, "hostname not resolves to IPv4")
            if payloads_ip:
                if hostname_ip:
                    jarm = await send_payloads(payloads_ip, hostname_ip, target)
                    if jarm:
                        result = jarm_hash(jarm)
                        response = {'key': 'ipaddress',
                                    'port': target.port,
                                    'ip': hostname_ip,
                                    'hostname': target.hostname,
                                    'jarm': result,
                                    'status': 'success'}
                        results.append(response)
                    else:
                        response = {'key': 'ipaddress',
                                    'port': target.port,
                                    'ip': hostname_ip,
                                    'hostname': target.hostname,
                                    'status': 'error'}
                        result_document = create_error_template(response, 'jarm not found')
            if payloads_hostname:
                jarm = await send_payloads(payloads_hostname, hostname_ip, target)
                if jarm:
                    result = jarm_hash(jarm)
                    response = {'key': 'hostname',
                                'port': target.port,
                                'ip': hostname_ip,
                                'hostname': target.hostname,
                                'jarm': result,
                                'status': 'success'}
                    results.append(response)
                else:
                    response = {'key': 'hostname',
                                'port': target.port,
                                'ip': hostname_ip,
                                'hostname': target.hostname,
                                'status': 'error'}
                    result_document = create_error_template(response, 'jarm not found')
            if results:
                result_document = make_document_from_responses(results)
            if result_document:
                success = access_dot_path(result_document, "data.jarm.status")
                if self.stats:
                    if success == "success":
                        self.stats.count_good += 1
                    else:
                        self.stats.count_error += 1
                lines_out =[]
                try:

                    if self.success_only:
                        if success == "success":
                            lines_out = create_filtred_output_record(result_document,
                                                                self.output_format,
                                                                self.filter_jarm,
                                                                self.filter_cipher_tls)
                    else:
                        lines_out = create_filtred_output_record(result_document,
                                                            self.output_format,
                                                            self.filter_jarm,
                                                            self.filter_cipher_tls)
                except Exception:
                    pass
                else:
                    for line in lines_out:
                        if line:
                            await self.output_queue.put(line)


def create_io_reader(stats: Stats, queue_input: Queue, target: TargetConfig, app_config: AppConfig) -> TargetReader:
    message_producer = InputProducer(stats, queue_input, target, app_config.senders - 1, app_config.queue_sleep)
    if app_config.input_stdin:
        return TargetStdinReader(stats, queue_input, message_producer)
    if app_config.single_targets:
        return TargetSingleReader(stats, queue_input, message_producer, app_config.single_targets)
    elif app_config.input_file:
        return TargetFileReader(stats, queue_input, message_producer, app_config.input_file)
    else:
        # TODO : rethink...
        print("""errors, set input source:
         --stdin read targets from stdin;
         -t,--targets set targets, see -h;
         -f,--input-file read from file with targets, see -h""")
        exit(1)


def get_async_writer(app_settings: AppConfig) -> Callable[[Any, str], Coroutine]:
    if app_settings.write_mode == 'a':
        return write_to_file
    return write_to_stdout
