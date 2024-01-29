# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from scapy.arch import get_if_hwaddr


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.avoid_dict = {}
        self.server_num = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        avoid_dst = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.100"]
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        protocols_in_pkt = [p.protocol_name for p in pkt if not type(p) is str]
        mac_address = get_if_hwaddr("enp0s3")
        if "udp" in protocols_in_pkt and pkt[1].dst in avoid_dst:
            current_ip = avoid_dst[self.server_num % 3]
            current_mac =  self.avoid_dict[current_ip][0]
            current_out_port = self.avoid_dict[current_ip][1]
            pkt[1].dst = str.encode(current_ip)
            pkt[0].dst = str.encode(current_mac)
            self.server_num += 1
        elif "udp" in protocols_in_pkt and pkt[1].src in avoid_dst:
            og_source = pkt[1].src
            og_mac =  pkt[0].src
            pkt[1].src = str.encode("10.0.0.100")
            pkt[0].src = str.encode(mac_address)
        elif "arp" in protocols_in_pkt and pkt[1].dst_ip == "10.0.0.100":
            if pkt[1].src_ip in avoid_dst:
                self.avoid_dict[pkt[1].src_ip] = [pkt[0].src, in_port]
            arp_packet = packet.Packet()
            arp_packet.add_protocol(ethernet.ethernet(ethertype=pkt[0].ethertype, dst=pkt[0].src, src=mac_address))
            arp_packet.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=mac_address, src_ip=pkt[1].dst_ip, dst_mac=pkt[1].src_mac, dst_ip=pkt[1].src_ip))
            arp_packet.serialize()
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_packet)

            datapath.send_msg(out)
            return
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        og_source = None

        if "udp" in protocols_in_pkt:
            source_name = "Server " if  pkt[1].src in avoid_dst else "Client "
            source_ip = pkt[1].src
            if og_source:
                source_name = "Server " if og_source in avoid_dst else "Client "
                source_ip = og_source
            dest_name = "Server " if  pkt[1].dst in avoid_dst else "Client "
            self.logger.info("Incoming Packet from Source %s= %s \nBeing sent to Destination %s= %s", source_name, source_ip, dest_name, pkt[1].dst)
            if "udp" in protocols_in_pkt and pkt[1].dst not in avoid_dst:
                self.logger.info("This is the first packet from this Server to this Client. All further communication will be handeled by Flow")
            self.logger.info("________________________________________________________________________")


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        #if "udp" in protocols_in_pkt:
        #    print(out_port != ofproto.OFPP_FLOOD, pkt[1].dst)
        if out_port != ofproto.OFPP_FLOOD:
            if "udp" in protocols_in_pkt and pkt[1].dst not in avoid_dst:
                client_out_port = self.mac_to_port[dpid][pkt[0].dst]
                actions = []
                actions.append(parser.OFPActionSetField(ipv4_src="10.0.0.100"))
                actions.append(parser.OFPActionSetField(eth_src=mac_address))
                actions.append(parser.OFPActionOutput(client_out_port))
                pkt.serialize()
                data = pkt.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=og_mac, eth_type=0x800)
                self.add_flow(datapath, 1, match, actions)
        data = None
        if "udp" in protocols_in_pkt and pkt[1].dst in avoid_dst:
            actions = [parser.OFPActionOutput(current_out_port)]
            pkt.serialize()
            data = pkt.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        else:
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
