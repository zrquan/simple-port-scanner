import argparse
import asyncio
import socket
from collections import defaultdict
from ipaddress import ip_network, ip_address, AddressValueError
from typing import Iterator

from rich.progress import Progress
from rich.tree import Tree
from rich import print


class Scanner():
    def __init__(self, args) -> None:
        self.targets = tuple(self._parse_targets(args.target))
        self.ports = tuple(self._parse_ports(args.port))
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.result = defaultdict(dict)

        asyncio.run(self.ready())

        if len(self.result) > 0:
            self.handler.report(self.result)

    async def _check_port(self, target: str, port: int):
        state = service = 'unknown'
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

        try:
            service = socket.getservbyport(port)
        except OSError:
            pass

        self.result[target].update({port: (state, service)})
        self.handler.log(target, port, state, self.verbose)

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

    async def ready(self):
        tasks = [self._check_port(target, port)
                 for target in self.targets
                 for port in self.ports]
        self.handler = ResultHandler(len(tasks))
        await asyncio.gather(*tasks, return_exceptions=True)
        self.handler.finish()


class ResultHandler():
    def __init__(self, port_num: int) -> None:
        prog = Progress()
        prog.start()
        self.task = prog.add_task('Scanning...', total=port_num)
        self.console = prog.console
        self.prog = prog

    def log(self, target: str, port: int, state: str, verbose: bool):
        if verbose:
            if state == 'open':
                self.console.print(
                    f'port [green]{port}[/green] open on [green]{target}[/green]')
        self.prog.update(self.task, advance=1)

    def report(self, result: dict):
        report = Tree('[bold red]Result')
        for target, port_info in result.items():
            target_report = report.add(target)
            for port, state in port_info.items():
                if state[0] == 'open':
                    target_report.add(
                        f'[blue]{port} - {state[0]} - {state[1]}')
        print(report)

    def finish(self):
        self.prog.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Simple port scanner power by asyncio module.',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', help='target ip(s)')
    parser.add_argument(
        '-p', '--port', help='target ports, separated by comma')
    parser.add_argument('-t', '--timeout', type=int, default=5)
    parser.add_argument('-v', '--verbose', action='store_true')

    arguments = parser.parse_args()

    Scanner(arguments)
