__all__ = ['write_to_stdout', 'write_to_file']


async def write_to_stdout(io, record: str):
    """
    Write in 'wb' mode to io, input string in utf-8
    """
    return await io.write(record.encode('utf-8') + b'\n')


async def write_to_file(io, record: str):
    """
    Write in 'text' mode to io
    """
    return await io.write(record + '\n')
