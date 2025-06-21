#!/usr/bin/python
import os
import base64
import argparse
import aiohttp
import aiohttp.web
import asyncio
import fcntl
import sys
import struct
import weakref
import logging
from typing import Union, Optional

from pathlib import Path

log = None


class TunInterface:

    fd: Optional[int]  # tunnel filedescriptor
    wsref: Optional[weakref.ref]  # weak reference to websocket
    timeout: float  # timeout for keepalives
    ethernet: bool  # tap instead of tun if True

    def __init__(self, devname: Union[str, bytes], timeout: float, ethernet: bool):
        if type(devname) == str:
            self.devname = devname.encode('ascii')
        self.fd = None  # file descriptor number
        self.wsref = None  # weak reference to last active websocket
        self.timeout = timeout
        self.ethernet = ethernet

        self._open()

    ###
    # /dev/tun stuff...
    ###

    def _open(self):
        # see manpage netifaces, and kernel networking/tuntap.txt
        TUNSETIFF = 1074025674  # _IOW('T', 202, int)
        IFNAMSIZ = 16  # length of name, then comes short ifr_flags
        IFF_TUN = 1  # mode of tunnel
        IFF_TAP = 2  # mode of tunnel
        IFF_NO_PI = 4096  # no packet info

        # open mux device
        self.fd = os.open('/dev/net/tun', os.O_RDWR)

        # ioctl to set interface name, we assume we run as a non-root
        # user and the device has been prepared for us already
        flags = IFF_TAP if self.ethernet else IFF_TUN

        ifr = struct.pack('16sH22s', self.devname, flags, b'x00'*22)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)

        # set nonblocking
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFD)
        fcntl.fcntl(self.fd, fcntl.F_SETFD, flags | os.O_NONBLOCK)

    async def packet_recv_task(self, send_binary: bool):
        q = asyncio.Queue()

        def _callback(q=q, fd=self.fd):
            data = os.read(fd, 2048) # must be more than mtu + overhead!
            q.put_nowait(data)

        loop = asyncio.get_event_loop()
        # no simple way to await os.read(), so we circumvent
        # this by the callback which puts stuff in the queue ;-)
        loop.add_reader(self.fd, _callback)

        ws_dead = False

        while True:
            packet = await q.get()

            if self.wsref is None:
                ws = None
            else:
                ws = self.wsref()

            if ws is None:
                if not ws_dead:
                    log.error(f'Websocket is now dead, not sending packets.')
                ws_dead = True
                continue

            if ws_dead:
                log.error(f'Websocket is alive again.')
                ws_dead = False

            try:
                if send_binary:
                    log.debug(f'>>> Send (binary) packet of {len(packet)} bytes.')
                    await ws.send_bytes(packet)
                else:
                    log.debug(f'>>> Send (base64) packet of {len(packet)} bytes.')
                    # b64encode(bytes) yields bytes, so decode to ascii ;-)
                    json_data = base64.b64encode(packet).decode('ascii')
                    await ws.send_json({'packet': json_data})
            except Exception as exc:
                log.error(f'Exception {repr(exc)} received trying to send packet.')

    ###
    # websocket stuff
    ###
    async def handle_messages(self, ws):
        # not using async for, because we want to timeout
        # for each individual message
        ws_iter = aiter(ws)
        while True:
            try:
                msg = await asyncio.wait_for(ws_iter.__anext__(), self.timeout)
            except TimeoutError:
                log.debug(f'Timeout, send ping...')
                await ws.send_json({'ping': 'Timeout.'})
                continue
            except StopAsyncIteration:
                log.info('Websocket has closed.')
                break

            if msg.type == aiohttp.WSMsgType.BINARY:
                packet = msg.data
                os.write(self.fd, packet)
                log.debug(f'<<< Received (binary) packet of {len(packet)} bytes.')
                continue

            data = msg.json()
            if 'hello' in data:
                log.info(f'Hello received: "{data["hello"]}".')
                # only enable websocket after a hello was received
                self.wsref = weakref.ref(ws)
            elif 'ping' in data and type(data['ping']) is str:
                log.debug(f'Ping received, send pong...')
                await ws.send_json({'pong': data['ping']})
            elif 'pong' in data and type(data['pong']) is str:
                log.debug(f'Pong received, ignoring...')
            elif 'packet' in data:
                packet = base64.b64decode(data['packet'])
                os.write(self.fd, packet)
                log.debug(f'<<< Received (base64) packet of {len(packet)} bytes.')
            else:
                log.error(f'Unknown packet {repr(msg)}, will drop the connection.')
                break

        self.wsref = None

    async def server_get_handler(self, req):
        log.info(f'Serving websocket...')
        try:
            ws = aiohttp.web.WebSocketResponse()
            await ws.prepare(req)
            await ws.send_json({'hello': 'I\'m a server.'})
            await self.handle_messages(ws)
        except Exception as exc:
            log.error(f'Exception {repr(exc)} received handling websocket.')
        return aiohttp.web.Response(body="bye", status=200)


    async def client_task(self, url, auth):
        log.info(f'Connecting to url {url}...')
        sess = aiohttp.ClientSession()
        async with sess.ws_connect(url, auth=auth) as ws:
            log.info('Sending hello...')
            await ws.send_json({'hello': 'I\'m a client.'})
            log.info('Handling messages...')
            await self.handle_messages(ws)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debugging output.')
    parser.add_argument('-s', '--server-port', type=int,
                        metavar='portnum', help='Run server on given port.')
    parser.add_argument('-S', '--server-address', type=str,
                        metavar='address', help='Run server on given address. [def:%(default)s]',
                        default='localhost')
    parser.add_argument('-c', '--client', type=str,
                        metavar='url', help='Connect to server on given URL.')
    parser.add_argument('-t', '--tun', type=str, default='tun0',
                        metavar='dev', help='Tunnel interface [default: tun0]')
    parser.add_argument('-a', '--auth', type=Path,
                        help='Filename with two lines, username and password.')
    parser.add_argument('-T', '--timeout', type=float, default=10, metavar='sec',
                        help='Timeout for keepalives [def:%(default)d s]')
    parser.add_argument('-b', '--binary', action='store_true',
                        help='Send packes as binary websocket message, default is base64-in-json.')
    parser.add_argument('-e', '--ethernet', action='store_true',
                        help='Emulate ethernet ("tap") instead of ip tunnel ("tun").')
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)
    log = logging.getLogger(__name__)

    if not ((args.server_port is not None) ^ (args.client is not None)):
        log.error('Error, either run -s/--server or -c/--client!')
        sys.exit(1)

    loop = asyncio.new_event_loop()

    try:
        tun = TunInterface(args.tun, args.timeout, args.ethernet)
    except Exception as exc:
        log.exception('Cannot create TunInterface object.')
        sys.exit(1)

    loop.create_task(tun.packet_recv_task(send_binary=args.binary))

    if args.server_port is not None:
        # Server
        app = aiohttp.web.Application()
        app.router.add_get('/vpn/', tun.server_get_handler)
        runner = aiohttp.web.AppRunner(app)
        loop.run_until_complete(runner.setup())
        site = aiohttp.web.TCPSite(runner, args.server_address, args.server_port)
        loop.run_until_complete(site.start())
        loop.run_forever()
    else:
        auth = None
        if args.auth:
            with args.auth.open() as f:
                login = f.readline().strip()
                password = f.readline().strip()
                auth = aiohttp.BasicAuth(login, password)

        loop.run_until_complete(tun.client_task(args.client, auth))
