import socket, struct,sys,telnetlib
import scapy.all as scapy

def banner_grabbing(t_host,t_port):
    wanted_banner=sys.argv[4].lower()
    banner=""
    if t_port==23:
        tn=telnetlib.Telnet(t_host)
        banner=tn.read_until(b":").decode("utf-8")
        tn.close()
        if banner.lower().find(wanted_banner)!=-1:
            result=t_host+"|"+banner
            print(result)
        else:
            print("host found but not equal:"+t_host)
    else:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((t_host,t_port))
        banner=s.recv(2048).decode("utf-8")
        s.close()
        if banner.lower().find(wanted_banner)!=-1:
            result=t_host+"|"+banner
            print(result)
        else:
            print("host found but not equal:"+t_host)
    

def port_scan(host,port):
    try:
        sport = scapy.RandShort()
        pkt = scapy.sr1(scapy.IP(dst=host)/scapy.TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(scapy.TCP):
                if pkt[scapy.TCP].flags == 18:
                    banner_grabbing(host,port)
                else:
                    print("failed:"+host)
    except KeyboardInterrupt:
        sys.exit()

def get_input():
    start = struct.unpack('>I', socket.inet_aton(sys.argv[1]))[0]
    end = struct.unpack('>I', socket.inet_aton(sys.argv[2]))[0]
    for i in range(start, end):
        port_scan(socket.inet_ntoa(struct.pack('>I', i)),int(sys.argv[3]))
get_input()