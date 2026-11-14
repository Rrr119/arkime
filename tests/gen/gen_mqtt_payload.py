#!/usr/bin/env python3
"""Generate tests/pcap/mqtt_payload.pcap.

Focused regression pcap for the mqtt.payloadLen session field. It also
exercises CONNECT/PUBLISH/SUBSCRIBE extraction (client id, topic, QoS)
across MQTT 3.1, 3.1.1 and 5.0.

Sessions (raw IPv4, linktype 228):
  1. 192.168.77.10:41001 -> 10.0.77.100:1883  MQTT 3.1.1
     CONNECT, SUBSCRIBE (2 filters), PUBLISH QoS0/QoS1/QoS2 with known
     payload sizes, plus a zero-length PUBLISH.
  2. 192.168.77.20:41002 -> 10.0.77.100:1883  MQTT 3.1 (MQIsdp)
     CONNECT with will, PUBLISH QoS0.
  3. 192.168.77.30:41003 -> 10.0.77.100:1883  MQTT 5.0
     CONNECT, SUBSCRIBE, PUBLISH whose variable header carries
     properties so payloadLen must exclude them.

Run from the tests directory:  python3 gen/gen_mqtt_payload.py
"""

import struct
import sys


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def mqtt_str(text):
    raw = text.encode()
    return struct.pack('>H', len(raw)) + raw


def mqtt_connect(version, client_id, username=None, will_topic=None, will_message=None):
    if version == 3:
        proto_name = b'MQIsdp'
    else:
        proto_name = b'MQTT'

    flags = 0x02  # clean session
    if username:
        flags |= 0x80
    if will_topic is not None:
        flags |= 0x04  # will QoS 0, no retain

    variable = mqtt_str(proto_name.decode())
    variable += bytes([version, flags])
    variable += struct.pack('>H', 60)  # keep alive

    if version == 5:
        variable += b'\x00'  # empty CONNECT properties

    variable += mqtt_str(client_id)

    if will_topic is not None:
        if version == 5:
            variable += b'\x00'  # empty will properties
        variable += mqtt_str(will_topic)
        variable += struct.pack('>H', len(will_message)) + will_message

    if username:
        variable += mqtt_str(username)

    return bytes([0x10]) + varint(len(variable)) + variable


def mqtt_publish(topic, payload, qos=0, packet_id=None, properties=None):
    first_byte = 0x30 | (qos << 1)
    variable = mqtt_str(topic)
    if qos > 0:
        variable += struct.pack('>H', packet_id)
    if properties is not None:
        # MQTT 5.0: property length (zero when empty) followed by properties
        variable += varint(len(properties)) + properties
    body = variable + payload
    return bytes([first_byte]) + varint(len(body)) + body


def mqtt_subscribe(packet_id, filters):
    payload = struct.pack('>H', packet_id)
    for topic, qos in filters:
        payload += mqtt_str(topic) + bytes([qos])
    return bytes([0x82]) + varint(len(payload)) + payload


def csum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_tcp(src, dst, sport, dport, seq, ack, flags, payload=b''):
    iplen = 20 + 20 + len(payload)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, iplen, 1, 0, 64, 6, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0)
    pseudo = ip[12:20] + struct.pack('>BBH', 0, 6, 20 + len(payload))
    tcp = tcp[:16] + struct.pack('>H', csum(pseudo + tcp)) + tcp[18:]
    return ip + tcp + payload  # linktype 228 = raw IPv4


def session(client_ip, client_port, ts_start, messages):
    server_ip, server_port = '10.0.77.100', 1883
    cseq, sseq = 0x7000, 0x8000
    packets = []

    def add(packet):
        packets.append(packet)

    add(ip_tcp(client_ip, server_ip, client_port, server_port, cseq, 0, 0x02))       # SYN
    add(ip_tcp(server_ip, client_ip, server_port, client_port, sseq, cseq + 1, 0x12))  # SYN-ACK
    cseq += 1
    sseq += 1
    add(ip_tcp(client_ip, server_ip, client_port, server_port, cseq, sseq, 0x10))     # ACK

    for message in messages:
        add(ip_tcp(client_ip, server_ip, client_port, server_port, cseq, sseq, 0x18, message))
        cseq += len(message)
        add(ip_tcp(server_ip, client_ip, server_port, client_port, sseq, cseq, 0x10))  # ACK

    out = b''
    ts = ts_start
    for packet in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        out += struct.pack('<IIII', sec, usec, len(packet), len(packet)) + packet
        ts += 0.05
    return out


def main():
    outpath = sys.argv[1] if len(sys.argv) > 1 else 'pcap/mqtt_payload.pcap'

    # Session 1: MQTT 3.1.1 with varied PUBLISH payload sizes and QoS levels
    messages_v311 = [
        mqtt_connect(4, 'payload-client-311', username='payload_user'),
        mqtt_subscribe(1, [('rooms/+/temp', 0), ('alerts/#', 1)]),
        mqtt_publish('rooms/kitchen/temp', b'21.5'),                 # payloadLen 4, QoS0
        mqtt_publish('rooms/kitchen/temp', b'22.1', 1, 10),          # payloadLen 4, QoS1
        mqtt_publish('alerts/fire', b'{"zone":"kitchen"}', 2, 11),  # payloadLen 18, QoS2
        mqtt_publish('events/heartbeat', b''),                       # payloadLen 0, QoS0
        mqtt_publish('firmware/chunk', b'A' * 200),                  # payloadLen 200, QoS0
    ]

    # Session 2: legacy MQTT 3.1 (MQIsdp) with a will
    messages_v31 = [
        mqtt_connect(3, 'legacy-payload-31', will_topic='will/legacy', will_message=b'offline'),
        mqtt_publish('legacy/reading', b'\x00\x01\x02\x03\xff'),     # payloadLen 5, QoS0
    ]

    # Session 3: MQTT 5.0; PUBLISH includes a property (user property,
    # id 0x26) that must not be counted as payload.
    v5_props = b'\x26' + mqtt_str('sensor') + mqtt_str('kitchen')
    messages_v50 = [
        mqtt_connect(5, 'payload-client-50', username='payload5_user'),
        mqtt_subscribe(2, [('v5/telemetry', 0)]),
        mqtt_publish('v5/telemetry', b'temp=19.8', 1, 20, v5_props),  # payloadLen 9, QoS1
        mqtt_publish('v5/status', b'ok', properties=b'\x11\x08'),     # payloadLen 2, QoS0
    ]

    # pcap global header: magic, version 2.4, linktype 228 (raw IPv4)
    out = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 228)

    out += session('192.168.77.10', 41001, 1700100000.0, messages_v311)
    out += session('192.168.77.20', 41002, 1700100010.0, messages_v31)
    out += session('192.168.77.30', 41003, 1700100020.0, messages_v50)

    with open(outpath, 'wb') as handle:
        handle.write(out)
    print('Created ' + outpath)


if __name__ == '__main__':
    main()
