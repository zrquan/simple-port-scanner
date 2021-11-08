import argparse
import asyncio
import socket
from ipaddress import ip_network, ip_address, AddressValueError
from typing import Iterator
import aiohttp
from rich.console import Console
from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientSSLError, ServerDisconnectedError
from lxml.html import fromstring

out = Console()
tasks = asyncio.Queue(1000)
todo = 0  # 待扫描的端口数


def task_done() -> None:
    global todo
    todo -= 1
    tasks.task_done()
    status.update(f"[magenta]Tasks queue: {todo}")


def parse_ports(port_arg: str) -> Iterator[int]:
    for port in port_arg.split(','):
        try:
            port = int(port)
            if not 0 < port < 65536:
                raise SystemExit(f'Invalid port number: {port}')
            yield port
        except ValueError:
            start, end = (int(port) for port in port.split('-'))
            yield from range(start, end + 1)


def parse_targets(ip_arg: str) -> Iterator[str]:
    for target in ip_arg.split(','):
        try:
            if '/' in target:
                yield from [str(_) for _ in ip_network(target, strict=False).hosts()]
            elif '-' in target:
                start, end = (ip_address(ip) for ip in target.split('-'))
                while start <= end:
                    yield str(start)
                    start += 1
            else:
                yield str(ip_address(target))
        except AddressValueError:
            raise SystemExit(f'Invalid IP address: {target}')


async def grab_banner(target: str, port: int, timeout: int) -> None:
    service = 'unknown'
    http_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        service = socket.getservbyport(port)
    except OSError:
        pass

    if port == 443:
        url, ssl = f'https://{target}:{port}', True
    else:
        url, ssl = f'http://{target}:{port}', False
    # try to grab http banner
    try:
        async with ClientSession() as session:
            async with session.get(url, ssl=ssl, timeout=http_timeout) as resp:
                content = await resp.text()
                out.print(
                    f'[green]{target}:{port}[/green] -- {service}')
                # print interesting headers
                for h in resp.headers.keys():
                    if h in ('X-Powered-By', 'Server', 'Location'):
                        out.print(f'[blue]{h}: {resp.headers[h]}')
                # print html title
                if len(content) > 0:
                    title = fromstring(content).findtext('.//title')
                    out.print(f'[blue]Title: {title}')
    except (ClientSSLError, ServerDisconnectedError) as aerr:
        out.print(
            f'[green]{target}:{port}[/green] -- {service} => [red]{aerr.__class__.__name__}')
    except Exception:
        out.print(f'[green]{target}:{port}[/green] -- {service}')

    task_done()


async def check_port(timeout: int, verbose: bool) -> None:
    target, port = await tasks.get()
    state = 'closed'
    try:
        await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout
        )
        state = 'opened'
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as why:
        reason = {
            'ConnectionRefusedError': 'refused',
            'TimeoutError': 'timeout',
            'OSError': 'error'
        }
        state = reason[why.__class__.__name__]

    if state == 'opened':
        asyncio.ensure_future(grab_banner(target, port, timeout))
    else:
        if verbose:
            out.print(f'[red]{target}:{port} => {state}')
        task_done()


async def start(ip_arg: str, port_arg: str, timeout: int, verbose: bool) -> None:
    global todo

    for target in parse_targets(ip_arg):
        for port in parse_ports(port_arg):
            await tasks.put((target, port))
            asyncio.ensure_future(check_port(timeout, verbose))
            todo += 1
            status.update(f"[magenta]Tasks queue: {todo}")

    await tasks.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Asynchronous port scanner')
    parser.add_argument('target', help='target ip(s)')
    parser.add_argument(
        '-p', '--port', help='target ports, separated by comma')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                        help='connection timeout, default is 5s')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show unopened ports')
    args = parser.parse_args()

    with out.status("Starting...") as status:
        loop = asyncio.get_event_loop()
        t = asyncio.ensure_future(
            start(args.target, args.port, args.timeout, args.verbose))
        loop.run_until_complete(t)
