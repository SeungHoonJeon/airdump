import pcap

sniffer = pcap.pcap(name='wlan1', promisc=True, immediate=True, timeout_ms=50)
#print(sniffer)
#print(type(sniffer))

cnt = 1 

Beacon_frame_stuct = {}
Wireless_management_Fixed_param_stuct = {}
Wireless_management_Tagged_param_stuct = {}

Wireless_SSID = []
Beacon_total = {}
for ts,pkt in sniffer:
    
    cnt += 1
    #print(pkt)
    #print(pkt[2])
    radio_header_length = pkt[2]
    #print(radio_header_length)
    if pkt[radio_header_length] == 0x80:
        Beacon_frame = pkt[radio_header_length:radio_header_length+24]
        #print("---------------Beacon_frame---------------")
        #print(Beacon_frame)
        #print("-------------------------------------------")
        Beacon_frame_stuct['Beacon_frame_start'] = Beacon_frame[0]
        Beacon_frame_stuct['Beacon_frame_flags'] = Beacon_frame[1]
        Beacon_frame_stuct['Duration'] = Beacon_frame[2:4]
        Beacon_frame_stuct['Destincation'] = Beacon_frame[4:10]
        Beacon_frame_stuct['Source_address'] = Beacon_frame[10:16]
        Beacon_frame_stuct['BSSID'] = Beacon_frame[16:22]
        Beacon_frame_stuct['Fragment_number'] = Beacon_frame[22:24]

        Wireless_management = pkt[radio_header_length+24:]
        #print("---------------Wireless_management---------------")
        #print(Wireless_management)
        #print("-------------------------------------------------")

        Wireless_management_Fixed_param_stuct['timestamp'] = Wireless_management[0:8]
        Wireless_management_Fixed_param_stuct['Beacon_interval'] = Wireless_management[8:10]
        Wireless_management_Fixed_param_stuct['Capabilities_information'] = Wireless_management[10:12]

        Wireless_management_Tagged_param_stuct['SSID_tag_number'] = Wireless_management[12]
        Wireless_management_Tagged_param_stuct['SSID_tag_length'] = Wireless_management[13]
        Wireless_management_Tagged_param_stuct['SSID'] = Wireless_management[14:14+Wireless_management_Tagged_param_stuct['SSID_tag_length']]
        if Wireless_management_Tagged_param_stuct['SSID'] == b'\x00\x00\x00\x00\x00\x00\x00':
            continue
        Wireless_management_Tagged_param_stuct['Supproted_rates_tag'] = Wireless_management[14+Wireless_management_Tagged_param_stuct['SSID_tag_length']]
        Wireless_management_Tagged_param_stuct['Supproted_rates_tag_length'] = Wireless_management[14+Wireless_management_Tagged_param_stuct['SSID_tag_length']+1]
        Wireless_management_Tagged_param_stuct['Supproted_rates'] = Wireless_management[14+Wireless_management_Tagged_param_stuct['SSID_tag_length']+2:14+Wireless_management_Tagged_param_stuct['SSID_tag_length']+2+Wireless_management_Tagged_param_stuct['Supproted_rates_tag_length']]
        Wireless_management_Tagged_param_stuct['DS_param_set'] = Wireless_management[14+Wireless_management_Tagged_param_stuct['SSID_tag_length']+2+Wireless_management_Tagged_param_stuct['Supproted_rates_tag_length']]
        Wireless_management_Tagged_param_stuct['DS_param_set_tag_length'] = Wireless_management[14+Wireless_management_Tagged_param_stuct['SSID_tag_length']+2+Wireless_management_Tagged_param_stuct['Supproted_rates_tag_length']+1]
        Wireless_management_Tagged_param_stuct['DS_param_set_current_channel'] = Wireless_management[14+Wireless_management_Tagged_param_stuct['SSID_tag_length']+2+Wireless_management_Tagged_param_stuct['Supproted_rates_tag_length']+2:14+Wireless_management_Tagged_param_stuct['SSID_tag_length']+2+Wireless_management_Tagged_param_stuct['Supproted_rates_tag_length']+2+Wireless_management_Tagged_param_stuct['DS_param_set_tag_length']]

        if Wireless_management_Tagged_param_stuct['SSID'] not in Wireless_SSID:
            print(f"BSSID : {':'.join('%02X' % i for i in Beacon_frame_stuct['BSSID'])}")
            print(f"SSID : {Wireless_management_Tagged_param_stuct['SSID'].decode('utf-8')}")
            
            Beacon_total[Wireless_management_Tagged_param_stuct['SSID']] = 0
            print(f"Beacons : {Beacon_total[Wireless_management_Tagged_param_stuct['SSID']]}")
            Beacon_total[Wireless_management_Tagged_param_stuct['SSID']] = 1

            print(f"Channel : {int.from_bytes(Wireless_management_Tagged_param_stuct['DS_param_set_current_channel'],'big')}")
            Wireless_SSID.append(Wireless_management_Tagged_param_stuct['SSID'])
        else:
            Beacon_total[Wireless_management_Tagged_param_stuct['SSID']] += 1

            print(f"BSSID : {':'.join('%02X' % i for i in Beacon_frame_stuct['BSSID'])}")
            print(f"SSID : {Wireless_management_Tagged_param_stuct['SSID'].decode('utf-8')}")
            print(f"Beacons : {Beacon_total[Wireless_management_Tagged_param_stuct['SSID']]}")
            print(f"Channel : {int.from_bytes(Wireless_management_Tagged_param_stuct['DS_param_set_current_channel'],'big')}")
            Wireless_SSID.append(Wireless_management_Tagged_param_stuct['SSID'])
            
        
        if cnt > 100:
            break


