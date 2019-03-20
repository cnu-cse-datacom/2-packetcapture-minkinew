import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x" + ethernet_header[12].hex()

    print("========etheret header========")
    print("src_mac_address : ", ether_src)
    print("dest_mac_address : ", ether_dest)
    print("ip_version", ip_header)


def convert_ethernet_address(data):
        ethernet_addr = list()
        for i in data:
            ethernet_addr.append(i.hex())
        ethernet_addr = ":".join(ethernet_addr)
        return ethernet_addr


def parsing_ip_header(data):
    ip_header = struct.unpack("!1c1c2s2s2s1c1c2s4c4c", data)
    print("========ip header========")
    
    ver = int(ip_header[0].hex()[0], 16)
    print("ip_version:", ver)

    leng = int(ip_header[0].hex()[1], 16)
    print("ip_Length:", leng)

    dif = ip_header[1].hex()[0]
    print("differentiated_service_codepoint:", dif)
    
    exp = ip_header[1].hex()[1]
    print("explicit_congestion_notification:", exp)
    
    tot = int(ip_header[2].hex(),16)
    print("total_length:", tot)
    
    iden = int(ip_header[3].hex(),16)
    print("identification:", iden)
    
    flag = "0x" + ip_header[4].hex()
    print("flags:", flag)
    
    res_bit =  ip_header[4].hex()[0]
    print(">>>reserved_bit:", res_bit)
    
    not_frag = ip_header[4].hex()[1]
    print(">>>not_fragments:", not_frag)
    
    frag = ip_header[4].hex()[2]
    print(">>>fragments:", frag)
    
    frag_off = ip_header[4].hex()[3]
    print(">>>fragments_offset:", frag_off) 
    
    time = int(ip_header[5].hex(),16)
    print("Time to live:", time) 
    
    protocol = int(ip_header[6].hex(),16)
    print("protocol:", protocol) 
    
    check = "0x" + ip_header[7].hex()
    print("header checksum:", check) 
    
    src = convert_ip_address(ip_header[8:12])
    print("source_ip_address:", src)
    
    dest = convert_ip_address(ip_header[12:16])
    print("dest_ip_address:", dest)

    return protocol;


def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(int(i.hex(), 16)))
    ip_addr = ".".join(ip_addr)
    return ip_addr


def parsing_tcp_header(data):
    tcp_header=struct.unpack("!2s2s1I1I2s2s2s2s",data)
    print("========tcp header========")
    
    src = int(tcp_header[0].hex(), 16)
    print("src_port:", src)
    
    dec = int(tcp_header[1].hex(), 16)
    print("dec_port:", dec)

    seqn = tcp_header[2]
    print("seq_num:", seqn)
    
    ackn = tcp_header[3]
    print("ack_num:", ackn)
    
    header_len = (int(tcp_header[4].hex(), 16) >> 12) & 0x000f
    print("header_len:", header_len)

    flag = int(tcp_header[4].hex(), 16) & 0x0fff
    print("flags:", flag)
    
    res = flag >> 9
    print(">>>reserved:",res)
    
    non = (flag >> 8) & 0x001
    print(">>>nonce:", non)
    
    cwr = (flag >> 7) & 0x001
    print(">>>cwr:", cwr)
    
    urg = (flag >> 5) & 0x001
    print(">>>urgent:", urg)
    
    ack = (flag >> 4) & 0x001
    print(">>>ack:", ack)
    
    push = (flag >> 3) & 0x001
    print(">>>push:", push)
    
    reset = (flag >> 2) & 0x001
    print(">>>reset:", reset)
    
    syn = (flag >> 1) & 0x001
    print(">>>syn:", syn)
    
    fin = flag & 0x001
    print(">>>fin:", fin)
    
    win = int(tcp_header[5].hex(),16)
    print("window_size_value:", win)
    
    check = int(tcp_header[6].hex(), 16)
    print("checksum:", check)
    
    pointer = int(tcp_header[7].hex(),16)
    print("urgent_pointer:", pointer)


def parsing_udp_header(data): 
    udp_header = struct.unpack("!2s2s2s2s", data) 
    print("========udp_header========")

    src = int(udp_header[0].hex(),16)  
    print("src_port:", src)
    
    dec = int(udp_header[1].hex(),16) 
    print("dec_port:", dec)
    
    leng = int(udp_header[2].hex(),16) 
    print("leng:",leng)
    
    header_check = "0x"+ udp_header[3].hex() 
    print("header_checksum:",header_check)

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    protocol = parsing_ip_header(data[0][14:34])
    if (protocol == 6):
        parsing_tcp_header(data[0][34:54])
    if (protocol == 17):
        parsing_udp_header(data[2][34:42])
