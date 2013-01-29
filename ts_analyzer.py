from __future__ import print_function
from colorprint import *

import tornado_pyuv
tornado_pyuv.install()

import signal

import tornado.ioloop
import tornado.web

import os
import sys
import pyuv
import struct
import pprint
from sys import stdout
import datetime

def handle_signal(sig, frame):
    tornado.ioloop.IOLoop.instance().add_callback(tornado.ioloop.IOLoop.instance().stop)

if sys.version_info >= (3, 0):
    LINESEP = os.linesep.encode()
else:
    LINESEP = os.linesep

def on_read(handle, ip_port, data, error):
    if error is not None:
        print (error,color='red')
        return
    data = data.strip()
    mcast=handle.getsockname()
    if data:
        ip, port = ip_port
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
                        cc_com=(pids[mcast][pid]['cc']+1) % 16
                        pids[mcast][pid]['cc']=cc
                        if cc is not cc_com:
                            pids[mcast][pid]['error'] = pids[mcast][pid]['error']+1
                            print ("%s Error expected %s got %s (%s) %s %s" %
                                    (datetime.datetime.now(),cc_com,cc,mcast,hex(pid),length),
                                    color='red')

class MainHandler(tornado.web.RequestHandler):
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
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(pids)

application = tornado.web.Application([
    (r"/", MainHandler),
])


if __name__ == "__main__":
    os.system( [ 'clear', 'cls' ][ os.name == 'nt' ] )

    print ("PyUV version %s" % pyuv.__version__,color='white',background='blue')
    template_path=os.path.join(os.path.dirname(__file__), "templates")

    pids = {}
    
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    application.listen(8889)
    loop = tornado.ioloop.IOLoop.instance()

    server = pyuv.UDP(loop._loop)
    server.bind(("239.192.80.1", 1234))
    server.set_membership("239.192.80.1", pyuv.UV_JOIN_GROUP)
    server.start_recv(on_read)

    server5 = pyuv.UDP(loop._loop)
    server5.bind(("239.192.49.2", 1234))
    server5.set_membership("239.192.49.2", pyuv.UV_JOIN_GROUP)
    server5.start_recv(on_read)

    server6 = pyuv.UDP(loop._loop)
    server6.bind(("239.192.3.41", 1234))
    server6.set_membership("239.192.3.41", pyuv.UV_JOIN_GROUP)
    server6.start_recv(on_read)

    server7 = pyuv.UDP(loop._loop)
    server7.bind(("239.192.72.3", 1234))
    server7.set_membership("239.192.72.3", pyuv.UV_JOIN_GROUP)
    server7.start_recv(on_read)


    loop.start()
    tornado.ioloop.IOLoop.instance().close()