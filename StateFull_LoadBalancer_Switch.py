from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from scapy.arch import get_if_hwaddr


class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.mapping_dict = {}
        self.mac_to_port = {}
        self.avoid_dict = {}
        self.server_num = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        avoid_dst = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.100"]
        protocols_in_pkt = [p.protocol_name for p in pkt if not type(p) is str]
        in_port = msg.match['in_port']

        actions = [ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        controller_mac_address = get_if_hwaddr("enp0s3")
        og_source = None

        if "arp" in protocols_in_pkt and pkt[1].dst_ip == "10.0.0.100":
            if pkt[1].src_ip in avoid_dst:
                self.avoid_dict[pkt[1].src_ip] = [pkt[0].src, in_port]
            arp_packet = packet.Packet()
            arp_packet.add_protocol(ethernet.ethernet(ethertype=pkt[0].ethertype, dst=pkt[0].src, src=controller_mac_address))
            arp_packet.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=controller_mac_address, src_ip=pkt[1].dst_ip, dst_mac=pkt[1].src_mac, dst_ip=pkt[1].src_ip))
            arp_packet.serialize()
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))

            out = ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_packet)
            datapath.send_msg(out)
            return

        elif "udp" in protocols_in_pkt and pkt[1].dst in avoid_dst:
            if pkt[1].src in self.mapping_dict:
                current_ip = self.mapping_dict[pkt[1].src]
                current_mac =  self.avoid_dict[current_ip][0]
                current_out_port = self.avoid_dict[current_ip][1]
            else:
                current_ip = avoid_dst[self.server_num % 3]
                current_mac =  self.avoid_dict[current_ip][0]
                current_out_port = self.avoid_dict[current_ip][1]
                self.server_num += 1
                self.mapping_dict[pkt[1].src] = current_ip
            pkt[1].dst = str.encode(current_ip)
            pkt[0].dst = str.encode(current_mac)
        elif "udp" in protocols_in_pkt and pkt[1].src in avoid_dst:
            og_source = pkt[1].src
            pkt[1].src = str.encode("10.0.0.100")
            pkt[0].src = str.encode(controller_mac_address)

        data = None
        if "udp" in protocols_in_pkt:
            source_name = "Server " if  pkt[1].src in avoid_dst else "Client "
            source_ip = pkt[1].src
            if og_source:
                source_name = "Server " if og_source in avoid_dst else "Client "
                source_ip = og_source
            dest_name = "Server " if  pkt[1].dst in avoid_dst else "Client "
            self.logger.info("Incoming Packet from Source %s= %s \nBeing sent to Destination %s= %s", source_name, source_ip, dest_name, pkt[1].dst)
            self.logger.info("________________________________________________________________________")


        if "udp" in protocols_in_pkt and pkt[1].dst in avoid_dst:
            actions = [ofproto_parser.OFPActionOutput(current_out_port)]
            pkt.serialize()
            data = pkt.data
            out = ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        elif "udp" in protocols_in_pkt and pkt[1].src in avoid_dst:
            client_out_port = self.mac_to_port[dpid][pkt[0].dst]
            actions = [ofproto_parser.OFPActionOutput(client_out_port)]
            pkt.serialize()
            data = pkt.data
            out = ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        else:
             if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                 data = msg.data

             out = ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data = data)
        datapath.send_msg(out)
