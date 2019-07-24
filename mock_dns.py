#!/usr/bin/env python
# coding: utf-8

import configparser
import os
import re
import socketserver
import time

import dnslib
import gevent
from gevent import monkey

monkey.patch_all()
from gevent.queue import Queue
import pylru


def query(qname):
    with open('db.csv') as fdb:
        soa_line = fdb.readline().rstrip().split(',')
        soa = tuple(soa_line) if len(soa_line) == 2 else None
        dns = [tuple(line.rstrip('\r\n').split(',')) for line in fdb.readlines()]

    def get_answer(q, d, names):
        name = d.get(q)
        if name:
            names.append((q, name))
            get_answer(name, d, names)

    ret = []
    get_answer(qname, dict(dns), ret)
    print(ret)
    return ret, soa


def pack_dns(dns, answers, soa=None):
    content_type = lambda x: 'A' if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', x) else 'CNAME'
    if answers:
        for ans in answers:
            if content_type(ans[1]) == 'A':
                dns.add_answer(dnslib.RR(ans[0], dnslib.QTYPE.A, rdata=dnslib.A(ans[1])))
            elif content_type(ans[1]) == 'CNAME':
                dns.add_answer(dnslib.RR(ans[0], dnslib.QTYPE.CNAME, rdata=dnslib.CNAME(ans[1])))
    elif soa:
        soa_content = soa[1].split()
        dns.add_auth(dnslib.RR(soa[0], dnslib.QTYPE.SOA,
                               rdata=dnslib.SOA(soa_content[0], soa_content[1], (int(i) for i in soa_content[2:]))))

    return dns


def handler(data, addr, sock):
    try:
        dns = dnslib.DNSRecord.parse(data)
    except Exception as e:
        print('Not a DNS packet.\n', e)
    else:
        dns.header.set_qr(dnslib.QR.RESPONSE)
        # Get domain name
        qname = dns.q.qname
        # Get DNS answer from LRUCache
        response = DNSServer.dns_cache.get(qname)
        print('qname =', qname, 'response =', response)

        # if response:
        #     response[:2] = data[:2]
        #     sock.sendto(response, addr)
        # else:
        answers, soa = query(str(qname).rstrip('.'))
        answer_dns = pack_dns(dns, answers, soa)

        DNSServer.dns_cache[qname] = answer_dns.pack()
        # return after 15s sleep
        time.sleep(15)
        sock.sendto(answer_dns.pack(), addr)


def _init_cache_queue():
    while True:
        data, addr, sock = DNSServer.deq_cache.get()
        gevent.spawn(handler, data, addr, sock)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if not DNSServer.deq_cache.full():
            DNSServer.deq_cache.put((self.request[0], self.client_address, self.request[1]))


class DNSServer(object):
    @staticmethod
    def start():
        # Cache queue, put request to here
        DNSServer.deq_cache = Queue(maxsize=deq_size) if deq_size > 0 else Queue()
        # LRU Cache
        DNSServer.dns_cache = pylru.lrucache(lru_size)

        gevent.spawn(_init_cache_queue)

        print('Start DNS server at %s:%d\n' % (ip, port))
        dns_server = socketserver.UDPServer((ip, port), DNSHandler)
        dns_server.serve_forever()


def load_config(filename):
    with open(filename, 'r') as fc:
        cfg = configparser.ConfigParser()
        cfg.read_file(fc)

    return dict(cfg.items('DEFAULT'))


if __name__ == '__main__':
    # Read config file
    config_file = os.path.basename(__file__).split('.')[0] + '.ini'
    config_dict = load_config(config_file)

    ip, port = config_dict['ip'], int(config_dict['port'])
    deq_size, lru_size = int(config_dict['deq_size']), int(config_dict['lru_size'])
    db = config_dict['db']

    # Start DNS server
    DNSServer.start()
