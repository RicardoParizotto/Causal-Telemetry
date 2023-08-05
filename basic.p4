/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define SINK 0
#define ENTRY 1
#define FORWARD 2


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_INT  = 0x811;

const bit<32> MAX_INT = 10;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header int_header_t {
	bit<32>     swid;
  bit<32>     logical_clock;
	bit<16>     next_header;
}


struct metadata {
    bit<32> switch_meta;
    bit<32> local_virtual_time;
    bit<32> int_hdrs_number;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    int_header_t[MAX_INT]    int_header;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.int_hdrs_number = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_INT: parse_int;
            TYPE_IPV4: parse_ipv4;
        }
    }

    state parse_int{
        packet.extract(hdr.int_header.next);
        meta.int_hdrs_number = meta.int_hdrs_number + 1;
        transition select(hdr.int_header.last.next_header){
            TYPE_INT: parse_int;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

register <bit<32>>(1) packet_dir;


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action clone_packet() {
        // Clone from egress to egress pipeline
        clone(CloneType.I2E, 500);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<32> switch_m) {
        standard_metadata.egress_spec = port;
        meta.switch_meta = switch_m;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            packet_dir.write(0, meta.switch_meta);
            if(meta.switch_meta == SINK){
                clone_packet();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

register <bit<32>>(1) logical_clock;

	action add_swtrace(bit<32> swid){
	 	hdr.int_header.push_front(1);
		hdr.int_header[0].setValid();
    hdr.int_header[0].logical_clock = meta.local_virtual_time;
		hdr.int_header[0].next_header = TYPE_INT;
		hdr.int_header[0].swid = swid;
	}



	table swtrace {
		actions = {
			add_swtrace;
  			NoAction;
		}
		default_action = NoAction();
	}

	apply {
      logical_clock.read(meta.local_virtual_time, 0);
      logical_clock.write(0, meta.local_virtual_time + 1);
      swtrace.apply();
      if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
         standard_metadata.egress_spec = 4;
      } else {
        //if it is the first switch, update pointers in headers
        if(meta.switch_meta == ENTRY){
           hdr.ethernet.etherType = TYPE_INT;
           hdr.int_header[0].next_header = TYPE_IPV4;
        }else if(meta.switch_meta == SINK){
            if(meta.int_hdrs_number == 1){
               hdr.int_header.pop_front(1);
            }else if(meta.int_hdrs_number == 2){
               hdr.int_header.pop_front(2);
            }
            //hdr.int_header.pop_front(2);
            hdr.int_header[0].setInvalid();
            hdr.ethernet.etherType = TYPE_IPV4;
        }
      }
	 }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_header);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
