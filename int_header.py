from scapy.all import *
import sys, os

TYPE_IPV4 = 0x800
TYPE_INT = 0x811

class causal_int_header(Packet):
    fields_desc = [ IntField("swid", 0),
                    IntField("logical_clock", 0),
                    BitField("next_header", 0, 16)]

bind_layers(Ether, causal_int_header, type=TYPE_INT)
bind_layers(causal_int_header, causal_int_header, next_header=TYPE_INT)
bind_layers(causal_int_header, IP, next_header=TYPE_IPV4)
