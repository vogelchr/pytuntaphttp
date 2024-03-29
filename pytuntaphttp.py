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

from pathlib import Path

log = None


class TunInterface:
    def __init__(self, devname):
        if type(devname) == str:
            self.devname = devname.encode('ascii')
        self.fd = None  # file descriptor number
        self.wsref = None  # weak reference to last active websocket
        self._open()

    ###
    # /dev/tun stuff...
    ###

    def _open(self):
        # see manpage netifaces, and kernel networking/tuntap.txt
        TUNSETIFF = 1074025674  # _IOW('T', 202, int)
        IFNAMSIZ = 16  # length of name, then comes short ifr_flags
        IFF_TUN = 1  # mode of tunnel
        IFF_NO_PI = 4096  # no packet info

        # open mux device
        self.fd = os.open('/dev/net/tun', os.O_RDWR)

        # ioctl to set interface name, we assume we run as a non-root
        # user and the device has been prepared for us already
        flags = IFF_TUN | IFF_NO_PI
        ifr = struct.pack('16sH22s', self.devname, flags, b'x00'*22)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)

        # set nonblocking
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFD)
        fcntl.fcntl(self.fd, fcntl.F_SETFD, flags | os.O_NONBLOCK)

    async def packet_recv_task(self):
        q = asyncio.Queue()

        def _callback(q=q, fd=self.fd):
            data = os.read(fd, 1500)
            q.put_nowait(data)

        loop = asyncio.get_event_loop()
        # no simple way to await os.read(), so we circumvent
        # this by the callback which puts stuff in the queue ;-)
        loop.add_reader(self.fd, _callback)

        while True:
            packet = await q.get()

            if self.wsref is None:
                ws = None
            else:
                ws = self.wsref()

            if ws is None:
                log.error(
                    f'Websocket dead, cannot send packet of {len(packet)} bytes.')
                continue

            log.debug(f'>>> Send packet of {len(packet)} bytes.')
            # b64encode(bytes) yields bytes, so decode to ascii ;-)
            json_data = base64.b64encode(packet).decode('ascii')
            await ws.send_json({'packet': json_data})

    ###
    # websocket stuff
    ###
    async def handle_messages(self, ws):
        async for msg in ws:
            data = msg.json()
            if 'hello' in data:
                log.info(f'Hello received: "{data["hello"]}".')
                # only enable websocket after a hello was received
                self.wsref = weakref.ref(ws)

            if 'packet' in data:
                packet = base64.b64decode(data['packet'])
                os.write(self.fd, packet)
                log.debug(f'<<< Received packet of {len(packet)} bytes.')

    async def server_get_handler(self, req):
        log.info(f'Serving websocket...')
        log.info(repr(req))
        ws = aiohttp.web.WebSocketResponse()
        await ws.prepare(req)
        await ws.send_json({'hello': 'I\'m a server.'})
        await self.handle_messages(ws)

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
    parser.add_argument('-s', '--server', type=int,
                        metavar='portnum', help='Run server on given port.')
    parser.add_argument('-c', '--client', type=str,
                        metavar='url', help='Connect to server on given URL.')
    parser.add_argument('-t', '--tun', type=str, default='tun0',
                        metavar='dev', help='Tunnel interface [default: tun0]')
    parser.add_argument('-a', '--auth', type=Path,
                        help='Filename with two lines, username and password.')
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)
    log = logging.getLogger(__name__)

    if not ((args.server is not None) ^ (args.client is not None)):
        log.error('Error, either run -s/--server or -c/--client!')
        sys.exit(1)

    loop = asyncio.new_event_loop()

    try:
        tun = TunInterface(args.tun)
    except Exception as exc:
        log.exception('Cannot create TunInterface object.')
        sys.exit(1)

    loop.create_task(tun.packet_recv_task())

    if args.server is not None:
        # Server
        app = aiohttp.web.Application()
        app.router.add_get('/vpn/', tun.server_get_handler)
        runner = aiohttp.web.AppRunner(app)
        loop.run_until_complete(runner.setup())
        site = aiohttp.web.TCPSite(runner, 'localhost', args.server)
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
