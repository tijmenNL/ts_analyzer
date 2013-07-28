#!/usr/bin/env python

from __future__ import print_function
from colorprint import *

#import tornado_pyuv
#tornado_pyuv.install()

from tornado.ioloop import IOLoop
from tornado_pyuv import UVLoop
IOLoop.configure(UVLoop)

import signal

import tornado.ioloop
import tornado.web

import os
import sys
import pyuv
import struct
import pprint
from sys import stdout
import syslog
import datetime
import ts_analyzer

import argparse

def handle_signal(sig, frame):
    tornado.ioloop.IOLoop.instance().add_callback(tornado.ioloop.IOLoop.instance().stop)

if sys.version_info >= (3, 0):
    LINESEP = os.linesep.encode()
else:
    LINESEP = os.linesep

def on_read(handle, ip_port, flags, data, error):
    global bits_second, start_time_packet
    if error is not None:
        print (error,color='red')
        return
    if start_time_packet == 'unset':
        start_time_packet=datetime.datetime.now()
    data = data.strip()
    mcast=handle.getsockname()
    if data:
        ip, port = ip_port
        diff = datetime.datetime.now()-start_time_packet
        if diff.total_seconds() >= '30':
            bits_second=1
            start_time_packet=datetime.datetime.now()
        else:
            bits_second=1+bits_second
        for i in range(0,len(data),188):
            offset =+ i
            #print(offset)
            sync = ord(data[offset:offset+1])
            header1 = ord(data[offset+1:offset+2])
            header2 = ord(data[offset+2:offset+3])
            header3 = ord(data[offset+3:offset+4])

            transport_error = bool(header1 & 0x80)
            payload_unit_start = bool(header1 & 0x40)
            transport_priority = bool(header1 & 0x20)
            pid = header2 | ((header1 & 0x1F) << 8)
            scrambling = ((header3 & 0xC0) >> 6)
            have_adaptation_field = bool(header3 & 0x20)
            adaptation_field = ((header3 & 0x30) >> 4)
            have_payload = bool(header3 & 0x10)
            cc = header3 & 0x0F
            length=len(data)

            # We have sync:
            if sync == 0x47:
                if mcast not in pids:
                    pids[mcast]={}
                if pid not in pids[mcast]:
                    pids[mcast][pid]={'packets':1,'cc':cc, 'error':0, 'ip':ip}
                    print ("==> Found new PID %s from %s (%s)" % (hex(pid),mcast,ip))
                else:
                    pids[mcast][pid]['packets']= pids[mcast][pid]['packets']+1
                    if adaptation_field != 2:
                        cc_com = (pids[mcast][pid]['cc']+1) % 16
                        pids[mcast][pid]['cc'] = cc
                        if cc is not cc_com:
                            pids[mcast][pid]['error'] = pids[mcast][pid]['error']+1
                            print ("%s Error expected %s got %s (%s) %s %s" %
                                    (datetime.datetime.now(),cc_com,cc,mcast,hex(pid),length),
                                    color='red')
                            syslog.syslog(syslog.LOG_ERR, "%s Error expected %s got %s (%s) %s %s" %
                                    (datetime.datetime.now(),cc_com,cc,mcast,hex(pid),length))

class MainHandler(tornado.web.RequestHandler):ß
    def get(self):
        from platform import uname
        hostname = uname()[1]
        run_time = datetime.datetime.now() - start_time
        packet_time = datetime.datetime.now() - start_time_packet
        bits=((bits_second*1316)*8/packet_time.total_seconds())/1000000
        self.render('index.html',version=ts_analyzer.__version__,addresses=dict(addresses),hostname=hostname, bits=round(bits,2), run_time=run_time)


class ChannelHandler(tornado.web.RequestHandler):
    def get(self):
        pids_new=pids.copy()
        for key in pids_new.keys():
            if type(key) is not str:
                try:
                    pids_new[str(key)] = pids_new[key]
                except:
                    try:
                        pids_new[repr(key)] == pids_new[key]
                    except:
                        pass
            del pids_new[key]
        self.write(pids_new)

class ChannelOverviewHandler(tornado.web.RequestHandler):
    def get(self):
        pids_new=pids.copy()
        for key in pids_new.keys():
            if type(key) is not str:
                try:
                    pids_new[str(key)] = pids_new[key]
                except:
                    try:
                        pids_new[repr(key)] == pids_new[key]
                    except:
                        pass
            del pids_new[key]
        self.render('base.html',pids_new=pids_new)
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(pids)

class NewChannelHandler(tornado.web.RequestHandler):
    def post(self):
        # Debug
        #self.write(tornado.escape.json_encode(self.request.arguments["post"]))
        try:
            posted_config=tornado.escape.json_decode(self.request.body)
        except:
            print("Invalid JSON")

        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(posted_config)

if __name__ == "__main__":

    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/channels/overview", ChannelOverviewHandler),
        (r"/channels", ChannelHandler),
        (r"/channels/new", NewChannelHandler)
    ])

    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version="ts_analyzer %s" % ts_analyzer.__version__ )

    args = parser.parse_args()

    os.system( [ 'clear', 'cls' ][ os.name == 'nt' ] )

    print ("TS_Analyzer version %s (Using PyUV version %s)" % (ts_analyzer.__version__,pyuv.__version__),color='white',background='blue')
    template_path=os.path.join(os.path.dirname(__file__), "templates")

    pids = {}

    addresses = {}
    addresses[("239.192.80.1", 1234)] = 1

    start_time_packet='unset'
    bits_second = 1
    start_time=datetime.datetime.now()
    #pp2 = pprint.PrettyPrinter(indent=4)
    #pp2.pprint(addresses)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    application.listen(8889)
    loop = tornado.ioloop.IOLoop.instance()

    server = pyuv.UDP(loop._loop)
    server.bind(("239.192.71.3", 1234))
    server.set_membership("239.192.71.3", pyuv.UV_JOIN_GROUP)
    server.start_recv(on_read)

    server1 = pyuv.UDP(loop._loop)
    server1.bind(("239.192.27.1", 1234))
    server1.set_membership("239.192.27.1", pyuv.UV_JOIN_GROUP)
    server1.start_recv(on_read)

#    server2 = pyuv.UDP(loop._loop)
#    server2.bind(("239.192.27.2", 1234))
#    server2.set_membership("239.192.27.2", pyuv.UV_JOIN_GROUP)
#    server2.start_recv(on_read)

#    server3 = pyuv.UDP(loop._loop)
#    server3.bind(("239.192.27.1", 1234))
#    server3.set_membership("239.192.27.1", pyuv.UV_JOIN_GROUP)
#    server3.start_recv(on_read)

#    server5 = pyuv.UDP(loop._loop)
#    server5.bind(("239.192.49.2", 1234))
#    server5.set_membership("239.192.49.2", pyuv.UV_JOIN_GROUP)
#    server5.start_recv(on_read)

#    server4 = pyuv.UDP(loop._loop)
#    server4.bind(("239.192.72.1", 1234))
#    server4.set_membership("239.192.72.1", pyuv.UV_JOIN_GROUP)
#    server4.start_recv(on_read)

#    server6 = pyuv.UDP(loop._loop)
#    server6.bind(("239.192.23.2", 1234))
#    server6.set_membership("239.192.23.2", pyuv.UV_JOIN_GROUP)
#    server6.start_recv(on_read)

#    server7 = pyuv.UDP(loop._loop)
#    server7.bind(("239.192.25.2", 1234))
#    server7.set_membership("239.192.25.2", pyuv.UV_JOIN_GROUP)
#    server7.start_recv(on_read)


    loop.start()
    tornado.ioloop.IOLoop.instance().close()
