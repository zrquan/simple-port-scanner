import argparse
import asyncio
import socket
from ipaddress import ip_network, ip_address, AddressValueError
from typing import Iterator

from rich.console import Console

from aiohttp import ClientSession
from lxml.html import fromstring


class Scanner():
    def __init__(self, args) -> None:
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.tasks = asyncio.Queue(1000)
        self.todo = 0  # 未完成扫描的端口数
        self.out = Console()

        with self.out.status(f"[magenta]Starting...") as status:
            self.status = status
            loop = asyncio.get_event_loop()
            t = asyncio.ensure_future(self.start(args.target, args.port))
            loop.run_until_complete(t)

    def _task_done(self):
        self.todo -= 1
        self.tasks.task_done()
        self.status.update(f"[magenta]Tasks queue: {self.todo}")

    async def grab_banner(self, target, port):
        service = 'unknown'
        try:
            service = socket.getservbyport(port)
        except OSError as why:
            if self.verbose:
                self.out.log(why)

        if 'http' in service:
            async with ClientSession() as session:
                async with session.get(f'http://{target}:{port}', ssl=False) as resp:
                    self.out.print(
                        f'[green]{target}:{port}[/green] -- [cyan]{service}')
                    if resp.headers["X-Powered-By"]:
                        self.out.print(
                            f'[blue]X-Powered-By: {resp.headers["X-Powered-By"]}')
                    if resp.headers["Server"]:
                        self.out.print(
                            f'[blue]Server: {resp.headers["Server"]}')
                    content = await resp.text()
                    if content is not None:
                        title = fromstring(content).findtext('.//title')
                        self.out.print(f'[blue]Title: {title}')
        else:
            self.out.print(
                f'[green]{target}:{port}[/green] -- [cyan]{service}')

        self._task_done()

    async def check_port(self):
        target, port = await self.tasks.get()
        state = 'closed'
        try:
            await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )
            state = 'open'
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as why:
            reason = {
                'ConnectionRefusedError': 'refused',
                'TimeoutError': 'timeout',
                'OSError': 'error'
            }
            state = reason[why.__class__.__name__]

        if state == 'open':
            asyncio.ensure_future(self.grab_banner(target, port))
        else:
            if self.verbose and state != 'timeout':
                self.out.print(f'[red]{target}:{port} => {state}')
            self._task_done()

    def _parse_ports(self, port_arg) -> Iterator[int]:
        for port in port_arg.split(','):
            try:
                port = int(port)
                if not 0 < port < 65536:
                    raise SystemExit(f'Invalid port number: {port}')
                yield port
            except ValueError:
                start, end = (int(port) for port in port.split('-'))
                yield from range(start, end + 1)

    def _parse_targets(self, ip_arg) -> Iterator[str]:
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

    async def start(self, ip_arg, port_arg):
        for target in self._parse_targets(ip_arg):
            for port in self._parse_ports(port_arg):
                await self.tasks.put((target, port))
                asyncio.ensure_future(self.check_port())
                self.todo += 1
                self.status.update(f"[magenta]Tasks queue: {self.todo}")

        await self.tasks.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Simple port scanner power by asyncio module.',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', help='target ip(s)')
    parser.add_argument(
        '-p', '--port', help='target ports, separated by comma')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                        help='connection timeout, default is 5s')
    parser.add_argument('-v', '--verbose', action='store_true')

    arguments = parser.parse_args()

    Scanner(arguments)
