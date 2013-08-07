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

def output_program_association_table(f, length, payload_start):
    #pids[mcast][pid]['extra']='test'
    #print("    <program_association_table>")
    pointer_field = None
    cursor = 0
    if payload_start:
        pointer_field = ord(f[0:1])
        # if pointer_field:
        #     print("        <pointer_field>"+str(pointer_field)+"</pointer_field>")
        cursor+=1
    table_id = ord(f[1:2]);  cursor+=1
    # if table_id:
    #     #=str(pointer_field)
    #     print("        <table_id>"+str(pointer_field)+"</table_id>")
    byte3 = ord(f[2:3])   ;  cursor+=1
    # if byte3 & 0x80 != 0x80:
    #     print("        <!-- selection_syntax_indicator is not 1 -->")
    # if byte3 & 0x40 != 0x00:
    #     print("        <!-- reserved1 is not 0 -->")
    # if byte3 & 0x30 != 0x30:
    #     print("        <!-- reserved2 is not 11 -->")
    # if byte3 & 0x0C != 0x00:
    #     print("        <!-- two higher bits of secrion_length is are not 00 -->")
    byte4 = ord(f[3:4])  ; cursor+=1
    section_length = byte4 | ((byte3 & 0x07) << 8)
    # if section_length:
    #     print("        <section_length>"+str(section_length)+"</section_length>")
    byte5 = ord(f[4:5]) ; cursor += 1
    byte6 = ord(f[5:6]) ; cursor += 1
    transport_stream_ID = byte5 << 8 | byte6
    # if transport_stream_ID:
    #     print("        <transport_stream_ID>"+str(transport_stream_ID)+"</transport_stream_ID>")
    byte7 = ord(f[6:7]) ; cursor += 1
    # if byte7 & 0xC0 != 0xC0:
    #     # print("        <!-- reserved3 is not 11 -->")
    version_number = (byte7 & 0x3E) >> 1
    # print("        <version_number>"+str(version_number)+"</version_number>")
    current_indicator = bool(byte7 & 0x01)
    # if not current_indicator:
    #     print("        <not_appliable_yet/>")
    section_number = ord(f[7:8]) ; cursor += 1
    last_section_number = ord(f[8:9]) ; cursor += 1

    # if last_section_number:
    #     print("        <section_number>"+str(section_number)+"</section_number>")
    #     print("        <last_section_number>"+str(last_section_number)+"</last_section_number>")

    for i in range(0,(section_length-5-4)/4):
        # print("        <program>")
        cursor+=4
        program_num  = (ord(f[9+i:10+i]) << 8) | ord(f[10+i:11+i])
        b1 = ord(f[11+i:12+i])
        b2 = ord(f[12+i:13+i])
        if b1 & 0xE0 != 0xE0:
            print("            <!-- reserved is not 111 -->")
        program_pid = b2 | ((b1 & 0x1F) << 8)
        # print("            <program_num>"+str(program_num)+"</program_num>")
        # print("            <program_pid>"+hex(program_pid)+"</program_pid>")
        # print("        </program>\n")

        #program_map_pids.add(program_pid)

    crc32 = f[cursor:cursor+4]; cursor+=4

    length -= cursor

    if length>0:
        rest = f[cursor:cursor+length]
        if (rest != '\xff' * length) and (rest != '\x00' * length):
            print("        <rest>"+binascii.hexlify(rest)+"</rest>\n")

    # print("    </program_association_table>\n")
    return({'table_id':str(pointer_field),'transportstream_id':str(transport_stream_ID),'program':str(program_num),'pmt':hex(program_pid) })


def output_adaptation_field(f):
    print("    <adaptation_field>\n")
    additional_length = ord(f.read(1))
    if additional_length == 0:
        print("    </adaptation_field>\n")
        return 1

    flags = ord(f.read(1))
    discontinuity = bool(flags & 0x80)
    random_access = bool(flags & 0x40)
    elementary_stream_priority = bool(flags & 0x20)
    pcr = bool(flags & 0x10)
    opcr = bool(flags & 0x08)
    splicing_point = bool(flags & 0x04)
    transport_private = bool(flags & 0x02)
    adaptation_field_extension = bool(flags & 0x01)

    if discontinuity:    print("        <discontinuity/>\n")
    if random_access:    print("        <random_access/>\n")
    if elementary_stream_priority:    print("        <elementary_stream_priority/>\n")

    length = additional_length+1 # size byte
    additional_length-=1 # flags

    def read_pcr():
        pcr_byte_1 = ord(f.read(1)) # base
        pcr_byte_2 = ord(f.read(1)) # base
        pcr_byte_3 = ord(f.read(1)) # base
        pcr_byte_4 = ord(f.read(1)) # base
        pcr_byte_5 = ord(f.read(1)) # 1 bit base, 6 bits paddding, 1 bit ext
        pcr_byte_6 = ord(f.read(1)) # 8 bits ext

        base = (pcr_byte_1 << (1+8*3)) +  \
               (pcr_byte_2 << (1+8*2)) +  \
               (pcr_byte_3 << (1+8*1)) +  \
               (pcr_byte_4 << (1+8*0)) +  \
               (pcr_byte_5 >> 7)

        ext = ((pcr_byte_5 & 0x01) << 8) + pcr_byte_6

        time = base / 90000.0 + ext / 27000000.0

        return time


    if pcr:
        if additional_length>=6:
            additional_length-=6
            val = read_pcr()

            print("        <program_clock_reference>"+str(val)+"</program_clock_reference>\n")
    if opcr:
        if additional_length>=6:
            additional_length-=6
            val = read_pcr()
            print("        <original_program_clock_reference>"+str(val)+"</original_program_clock_reference>\n")
    if splicing_point:
        if additional_length>=1:
            additional_length-=1
            splice_count = ord(f.read(1))
            print("        <splice_countdown>"+str(splice_count)+"</splice_countdown>\n")

    if additional_length:
        print("       <!-- ignoring " + str(additional_length) + " bytes -->\n")

    f.read(additional_length)

    print("    </adaptation_field>\n")
    return length

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
            length = len(data)

            # We have sync:
            if sync == 0x47:
                if mcast not in pids:
                    pids[mcast]={}
                if pid not in pids[mcast]:
                    pids[mcast][pid]={'packets': 1, 'cc': cc, 'error': 0, 'ip': ip, 'type': 'unknown', 'extra': {}}
                    print ("===> Found new PID in stream %s (src=%s)" % (mcast,ip),end='')
                    if pid == 0:
                        pids[mcast][pid]['type'] = "PAT"
                        print (" [PAT] ",end='')
                        buf.append("%s Found new PID in stream %s (src=%s)(PID: %s [%s]) [PAT]" %
                                (datetime.datetime.now(),mcast,ip,hex(pid),pid))

                    buf.append("%s Found new PID in stream %s (src=%s) (PID: %s [%s])" %
                            (datetime.datetime.now(),mcast,ip,hex(pid),pid))
                    print ("(PID: ",end='')
                    print ("%s"% hex(pid), color='green',end='')
                    print (" [%s])"% pid)
                else:
                    pids[mcast][pid]['packets']= pids[mcast][pid]['packets']+1
                    if adaptation_field != 2:
                        cc_com = (pids[mcast][pid]['cc']+1) % 16
                        pids[mcast][pid]['cc'] = cc
                        if cc is not cc_com:
                            pids[mcast][pid]['error'] = pids[mcast][pid]['error']+1
                            print ("%s Error expected %s got %s (%s) %s %s" %
                                    (datetime.datetime.now(), cc_com, cc,
                                        mcast, hex(pid), length),
                                    color='red')
                            syslog.syslog(syslog.LOG_ERR, "%s Error expected %s got %s (%s) %s %s" %
                                    (datetime.datetime.now(), cc_com, cc, mcast, hex(pid), length))
                            buf.append( "%s Error expected %s got %s (%s) %s %s" %
                                    (datetime.datetime.now(), cc_com, cc, mcast, hex(pid), length))

                if pid == 0x00:
                    #adaptation_field_size = 0
                    #print(have_adaptation_field)
                    #if have_adaptation_field:
                    adaptation_field_size = 167

                    payload_size = 188 - 4 - adaptation_field_size
                    #print(payload_unit_start);
                    #print(mcast)
                    pids[mcast][pid]['extra']=output_program_association_table(data[offset+4:offset+188], payload_size, payload_unit_start)
                    #pp = pprint.PrettyPrinter(indent=4)
                    #pp.pprint(pids)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        from platform import uname
        hostname = uname()[1]
        run_time = datetime.datetime.now() - start_time
        packet_time = datetime.datetime.now() - start_time_packet
        bits=((bits_second*1316)*8/packet_time.total_seconds())/1000000
        self.render('index.html',version=ts_analyzer.__version__,addresses=dict(addresses),hostname=hostname,
                location=location,bits=round(bits,2), run_time=run_time,buf=buf,peers=peers)


class LogHandler(tornado.web.RequestHandler):
    def get(self):
        from platform import uname
        hostname = uname()[1]
        self.render('log.html',buf=buf, hostname=hostname)

class SelfLogHandler(tornado.web.RequestHandler):
    def get(self):
        from platform import uname
        hostname = uname()[1]
        self.render('self_log.html',buf=buf, hostname=hostname)

class LogsHandler(tornado.web.RequestHandler):
    def get(self):
        from platform import uname
        hostname = uname()[1]
        self.render('logs.html',buf=buf, peers=peers, hostname=hostname )

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

class RingBuffer:
    def __init__(self, size):
        self.data = [None for i in xrange(size)]

    def append(self, x):
        self.data.pop(0)
        self.data.append(x)

    def get(self):
        return reversed(self.data)

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
            posted_config = tornado.escape.json_decode(self.request.body)
        except:
            print("Invalid JSON")

        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(posted_config)

#class Server(object):
#    def __init__(self,address)
#        self.server = pyuv.UDP(loop._loop)
#        self.server.bind(key)
#        self.server.set_membership(key[0], pyuv.UV_JOIN_GROUP)
#        self.server.start_recv(on_read)

if __name__ == "__main__":

    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/channels/overview", ChannelOverviewHandler),
        (r"/channels", ChannelHandler),
        (r"/channels/new", NewChannelHandler),
        (r"/logs", LogsHandler),
        (r"/log", LogHandler),
        (r"/selflog", SelfLogHandler)
    ])

    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version="ts_analyzer %s" % ts_analyzer.__version__)

    args = parser.parse_args()

    os.system(['clear', 'cls'][os.name == 'nt'])

    print ("TS_Analyzer version %s (Using PyUV version %s)" % (ts_analyzer.__version__, pyuv.__version__), color='white', background='blue')
    template_path = os.path.join(os.path.dirname(__file__), "templates")

    syslog.syslog("TS_Analyzer version %s (Using PyUV version %s)" % (ts_analyzer.__version__, pyuv.__version__))

    pids = {}

    location = ''
    location = 'Vrijhof - 253'
    addresses = {}
    addresses[("239.192.71.3", 1234)] = 1
    addresses[("239.192.27.1", 1234)] = 1
    addresses[("239.192.23.1", 1234)] = 1
    buf = RingBuffer(100)

    peers = {}
    peers["iptv2-cam"]=("130.89.175.42",8889)

    start_time_packet='unset'
    bits_second = 1
    start_time=datetime.datetime.now()
    #pp2 = pprint.PrettyPrinter(indent=4)
    #pp2.pprint(addresses)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    application.listen(8889)
    loop = tornado.ioloop.IOLoop.instance()

#    for addr in addresses.keys():
#        print ("In dict: %s" % (addr))

    counter=0
    servers={}
    for key in addresses:
        print ('%s corresponds to' % key[0])

        servers[counter] = pyuv.UDP(loop._loop)
        servers[counter].bind(key)
        servers[counter].set_membership(key[0], pyuv.UV_JOIN_GROUP)
        servers[counter].start_recv(on_read)
        counter = counter + 1
#    server1 = pyuv.UDP(loop._loop)
#    server1.bind(("239.192.27.1", 1234))
#    server1.set_membership("239.192.27.1", pyuv.UV_JOIN_GROUP)
#    server1.start_recv(on_read)
#    server = pyuv.UDP(loop._loop)
#    server.bind(("239.192.71.3", 1234))
#    server.set_membership("239.192.71.3", pyuv.UV_JOIN_GROUP)
#    server.start_recv(on_read)

#    server1 = pyuv.UDP(loop._loop)
#    server1.bind(("239.192.27.1", 1234))
#    server1.set_membership("239.192.27.1", pyuv.UV_JOIN_GROUP)
#    server1.start_recv(on_read)

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
