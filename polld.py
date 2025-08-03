#!/usr/bin/env python3
import asyncio
import json
import os
import random
import time
import traceback
import zlib
import yaml
from copy import deepcopy

import aiohttp
from aioetcd3.help import range_prefix
#from influxdb import InfluxDBClient
from aioinflux import InfluxDBClient

from ffbstools.etcd import etcd_client

POLL_INTERVAL = 60
PRUNE_INTERVAL = 5*POLL_INTERVAL
CONFIG_PREFIX = '/config/'
#YANIC_ADDR = ('::1', 11001)
YANIC_ADDR = ('2001:bf7:381::3:1', 11001)
REQUEST = 'GET nodeinfo statistics neighbours wireguard'.encode('ascii')

# dict of mesh mac addresses of indirect nodes, with {ip: insertion time} as value
meshed_mac_ips = dict()
# map of last request timestamps
pings = dict()

timeout = aiohttp.ClientTimeout(total=30, connect=20)
session = aiohttp.ClientSession(timeout=timeout)

influxdb_queue = []

def influxdb_wireguard(address, info):
    node_id = None
    for v in info.values():
        if 'node_id' in v:
            node_id = v['node_id']
    if node_id is None:
        print('no node_id found in data from', address[0])
        return
    if 'wireguard' not in info:
        print('no wireguard report found in data from', address[0])
        return
    points = []
    for if_name, if_info in info['wireguard']['interfaces'].items():
        for peer_key, peer_info in if_info['peers'].items():
            points.append({
                "measurement": "wireguard",
                "tags": {
                    "nodeid": node_id,
                    "interface": if_name,
                    "peer": peer_key,
                },
                "fields": {
                    "handshake": peer_info.get('handshake'),
                    "rx": peer_info['transfer_rx'],
                    "tx": peer_info['transfer_tx'],
                },
            })
    influxdb_queue.extend(points)

def influxdb_delay(address, info, delay):
    node_id = None
    for v in info.values():
        if 'node_id' in v:
            node_id = v['node_id']
    if node_id is None:
        print('no node_id found in data from', address[0])
        return
    points = []
    points.append({
        "measurement": "respondd-delay",
        "tags": {
            "nodeid": node_id,
        },
        "fields": {
            "rtt": delay,
        },
    })
    influxdb_queue.extend(points)

class Node:
    _nodes = {}

    def __init__(self, address):
        self.address = address
        self._interfaces = None
        self._interfaces_ts = -3600
        self._neighbours = None
        self._neighbours_ts = -3600

    async def get_interfaces(self):
        age = time.monotonic() - self._interfaces_ts
        if age < 3600:
            return self._interfaces
        else:
            interfaces = self._interfaces or set()
            self._interfaces = None
            self._interfaces_ts = time.monotonic()

        try:
            async with session.get('http://[{}]/cgi-bin/dyn/neighbours-batadv'.format(self.address)) as resp:
                line = await resp.content.readline()
                resp.close()
        except asyncio.TimeoutError:
            print(f"http read for interfaces from {self.address} timed out")
            return None
        except aiohttp.client_exceptions.ClientConnectorError:
            return None

        #print('neighbours-batadv: ', line.decode())
        if not line.startswith(b'data: '):
            self._neighbours = None
            return None
        data = json.loads(line[6:])
        for neighbour in data.values():
            ifname = neighbour.get("ifname")
            if ifname:
                interfaces.add(ifname)

        self._interfaces = interfaces
        return self._interfaces

    async def get_neighbours(self):
        interfaces = await self.get_interfaces()
        age = time.monotonic() - self._neighbours_ts
        if age < 600:
            return self._neighbours
        elif not interfaces:
            return None
        else:
            neighbours = {}
            self._neighbours = None
            self._neighbours_ts = time.monotonic()

        for interface in interfaces:
            try:
                async with session.get('http://[{}]/cgi-bin/dyn/neighbours-nodeinfo?{}'.format(self.address, interface)) as resp:
                    async for line in resp.content:
                        if not line.startswith(b'data: '):
                            continue
                        print('neighbours-nodeinfo', self.address, line.decode())
                        data = json.loads(line[6:])
                        if data is None:
                            break
                        # is this the correct MAC?
                        mac = data.get("network", {}).get("mac", None)
                        addresses = data.get("network", {}).get("addresses", [])
                        if mac and addresses:
                            neighbours[mac] = addresses[0]
                    resp.close()
            except asyncio.TimeoutError:
                print(f"http read for neighbours on iface {interface} from {self.address} timed out")
                continue
            except aiohttp.client_exceptions.ClientConnectorError:
                continue

        self._neighbours = neighbours
        print('found neighbours', self.address, neighbours)
        return self._neighbours

    @classmethod
    def get(cls, address):
        node = cls._nodes.get(address)
        if node is None:
            node = cls(address)
            cls._nodes[address] = node
        return node


class ResponddProtocol:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        delay = time.monotonic() - pings.get(address[0], 0.0)
        if delay > POLL_INTERVAL/10:
            delay = None

        self.transport.sendto(data, YANIC_ADDR)

        info = json.loads(inflate(data))
        if trace:
            trace.write(json.dumps(info, indent=4)+'\n')

        influxdb_wireguard(address, info)

        if delay is not None:
            influxdb_delay(address, info, delay)

        print('received', address[0])
        #if address[0].endswith('::1'):
        #    if info['nodeinfo']:
        #        for mesh in info['nodeinfo']['network']['mesh'].values():
        #            for macs in mesh['interfaces'].values():
        #                add_direct_macs(macs)
        #    if info['neighbours']:
        #        for neighs in info['neighbours']['batadv'].values():
        #            for node in neighs['neighbours'].keys():
        #                add_meshed_ip(node, mac_to_ipv6(node, address[0]), 'respondd')
        #else:  # indirect response
        if info['nodeinfo']:
            for mesh in info['nodeinfo']['network']['mesh'].values():
                for macs in mesh['interfaces'].values():
                    for mac in macs:
                        add_meshed_ip(mac, address[0], 'respondd', acked=True)

        etcd_nodes.queue(info['nodeinfo'])

    def error_received(self, exc):
        print('error_received', exc)

class EtcdNodes:
    def __init__(self):
        self._prev = {}
        self._timestamp = {}
        self._queue = []

    def queue(self, nodeinfo):
        self._queue.append(deepcopy(nodeinfo))

    async def publish_one(self, nodeinfo):
        nodeid = nodeinfo['node_id']

        now = time.time()
        age = now - self._timestamp.get(nodeid, 0)
        if age < 300:
            return
        self._timestamp[nodeid] = now

        prev = self._prev.get(nodeid, {})
        if nodeinfo == prev and age < 3600:
            return
        self._prev[nodeid] = nodeinfo

        data = nodeinfo.copy()
        data['timestamp'] = time.time()
        key = "/node/{}".format(nodeid)
        await etcd_client.put(
            key,
            json.dumps(data, indent=2, sort_keys=True),
        )

    async def publish(self):
        while self._queue:
            await self.publish_one(self._queue.pop(0))

async def get_direct_ips():
    direct_ips = set()
    start = time.monotonic()
    raw = await etcd_client.range(key_range=range_prefix(CONFIG_PREFIX))
    print('etcd_client.range took {}'.format(time.monotonic()-start))
    for (k, v, meta) in raw:
        if k.decode('ascii').endswith('/address6'):
            direct_ips.add(v.decode('ascii'))
    return direct_ips

def get_meshed_ips(*, decrement=True, cutoff=0):
    meshed_ips = set()
    for ips in meshed_mac_ips.values():
        print('ips', ips)
        best = max(ips.values())
        if best < cutoff:
            continue
        selected = random.choice([ip for ip, tries in ips.items() if tries == best])
        if decrement:
            ips[selected] -= 1
        meshed_ips.add(selected)
    print('get_meshed_ips(cutoff={}):\n from {}\n to {}'.format(cutoff, meshed_mac_ips, meshed_ips))
    return meshed_ips

async def task_poll_step(transport):
    loop = asyncio.get_event_loop()
    start = loop.time()
    nodes = await get_direct_ips()
    nodes |= get_meshed_ips()
    nodes = sorted(nodes)
    print('nodes:', nodes)
    offset = POLL_INTERVAL / len(nodes)
    for i, node in enumerate(nodes):
        print('polling', node)
        await asyncio.sleep(start + i*offset - loop.time())
        pings[node] = time.monotonic()
        transport.sendto(REQUEST, (node, 1001))

async def task_poll(transport):
    loop = asyncio.get_event_loop()
    offset = loop.time()
    while not loop.is_closed():
        try:
            await task_poll_step(transport)
        except asyncio.CancelledError:
            break
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
        offset += POLL_INTERVAL
        await asyncio.sleep(offset - loop.time())

async def task_prune():
    loop = asyncio.get_event_loop()
    while not loop.is_closed():
        #await asyncio.sleep(PRUNE_INTERVAL)
        await asyncio.sleep(30)
        print('pruning')
        old = time.monotonic() - PRUNE_INTERVAL
        for ips in meshed_mac_ips.values():
            for ip, tries in list(ips.items()):
                # remove ips which do not respond
                if tries <= 0:
                    del ips[ip]
                # limit maximum for active ips
                elif tries > 15:
                    ips[ip] = 15
        # remove macs without ips
        for mac in [mac for mac, ips in meshed_mac_ips.items() if not ips]:
            del meshed_mac_ips[mac]
            print('pruned meshed mac {}'.format(mac))
        with open('/tmp/polld-dump.tmp', 'w') as dump:
            yaml.dump(meshed_mac_ips, dump)
        os.rename('/tmp/polld-dump.tmp', '/tmp/polld-dump')

async def task_poll_http():
    loop = asyncio.get_event_loop()
    while not loop.is_closed():
        await asyncio.sleep(10)
        print('poll_http: while')
        nodes = get_meshed_ips(decrement=False, cutoff=8)
        nodes = sorted(nodes)
        start = loop.time()
        for address in nodes:
            start = loop.time()
            node = Node.get(address)
            try:
                neighbours = await node.get_neighbours()
            except Exception:  # pylint: disable=broad-except
                traceback.print_exc()
                continue
            if not neighbours:
                print(f'poll_http: no neighbours for {address} ({loop.time()-start:.2f} seconds)')
                continue
            for mac, node_address in neighbours.items():
                add_meshed_ip(mac, node_address, 'http')
            print(f'poll_http: {len(neighbours)} neighbours for {address} ({loop.time()-start:.2f} seconds)')

async def task_publish_nodes():
    loop = asyncio.get_event_loop()

    while not loop.is_closed():
        await asyncio.sleep(15)
        print('publish_nodes: while')
        try:
            await etcd_nodes.publish()
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            continue

async def task_wd():
    loop = asyncio.get_event_loop()
    loops = 0
    while not loop.is_closed():
        start = time.monotonic()
        await asyncio.sleep(0.1)
        delay = time.monotonic() - start
        if delay > 0.2:
            print("unexpected delay of {} after {} good loops".format(delay, loops))
            loops = 0
        else:
            loops += 1

async def task_influxdb_writer():
    loop = asyncio.get_event_loop()
    while not loop.is_closed():
        await asyncio.sleep(1)
        pending = influxdb_queue[:]
        influxdb_queue.clear()
        if not pending:
            continue
        start = time.monotonic()
        try:
            print("writing {} points to influxdb".format(len(pending)))
            #await loop.run_in_executor(None, influx.write_points, pending)
            await influx.write(pending)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            continue
        delay = time.monotonic() - start
        print("wrote {} points to influxdb in {} seconds".format(len(pending), delay))

def add_meshed_ip(mac, ip, source, acked=False):
    ips = meshed_mac_ips.setdefault(mac, {})
    if ip not in ips:
        print("adding meshed ip {} for mac {} (using {})".format(ip, mac, source))
    ips[ip] = ips.get(ip, 5) + (2 if acked else 0)

def inflate(data):
    decompress = zlib.decompressobj(-zlib.MAX_WBITS)
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated.decode()

def mac_to_ipv6(mac, prefix):
    parts = mac.split(':')
    parts.insert(3, 'ff')
    parts.insert(4, 'fe')
    parts[0] = "%x" % (int(parts[0], 16) ^ 2)
    ipv6 = [prefix.split('::', 1)[0]]
    for i in range(0, len(parts), 2):
        ipv6.append(''.join(parts[i:i+2]))
    return ':'.join(ipv6)

trace = None
#trace = open('/tmp/polld-trace', 'w')
#influx = InfluxDBClient(database='ffbs')
influx = InfluxDBClient(unix_socket='/run/influxdb/influxdb.sock', db='ffbs')
etcd_nodes = EtcdNodes()

try:
    with open('/tmp/polld-dump', 'r') as dump:
        meshed_mac_ips = yaml.load(dump, Loader=yaml.SafeLoader)
    print(f'loaded /tmp/polld-dump with {len(meshed_mac_ips)} entries')
except Exception as e:
    print(f'could not load /tmp/polld-dump: {e}')

if not meshed_mac_ips:
    meshed_mac_ips = dict()

def main():
    loop = asyncio.get_event_loop()
    listen = loop.create_datagram_endpoint(ResponddProtocol, local_addr=('::', 0))
    transport, protocol = loop.run_until_complete(listen)
    loop.create_task(task_poll(transport))
    loop.create_task(task_prune())
    loop.create_task(task_poll_http())
    loop.create_task(task_publish_nodes())
    loop.create_task(task_wd())
    loop.create_task(task_influxdb_writer())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    loop.run_until_complete(session.close())
    transport.close()
    loop.close()

if __name__ == '__main__':
    main()
