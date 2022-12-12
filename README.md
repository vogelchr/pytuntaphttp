# pytuntaphttp - a "tun" server for python


# Server and Client

Create the tun device, with permissions for the given user (so that this
script doesn't have to run as root.)

```
ip tuntap add dev tun1234 mode tun user `id -u username` group `id -g username`
ip addr add 10.1.1.1/24 dev tun1234
ip link set tun1234 up
```

# Server

Run the server on the given port, the URL will be http://yourserver:port/tun
serving a websocket.

```
./pytuntaphttp.py -s 8080 -t tun1234
```

# Client

Connect the client to the given server (by URL). Of course the tun device on
the client must have a different address than the one on the server.

```
./pytuntaphttp.py -u http://yourserver:port/tun -t tun1234
```

# Protocol

json messages are exchanged over the websocket, the protocol is symmetric.

First one has to say hello:

```
{ 'hello': 'Any string.' }
```

Then one has to send packets:

```
{ 'packet': 'base64-encoded-payload' }
```

That's it.