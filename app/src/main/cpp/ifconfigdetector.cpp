#include <jni.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <fstream>
#include <algorithm>

#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct AddressEntry {
    int family = 0;
    std::string address;
    std::string netmask;
    std::string peerOrBroadcast;
    bool isPointToPoint = false;
    bool isBroadcast = false;
};

struct InterfaceDump {
    std::string name;
    unsigned int flags = 0;
    std::vector<AddressEntry> addresses;
};

static std::string sockaddrToString(const sockaddr* sa) {
    if (!sa) return "";

    char buf[INET6_ADDRSTRLEN] = {0};

    if (sa->sa_family == AF_INET) {
        const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(sa);
        if (inet_ntop(AF_INET, &(sin->sin_addr), buf, sizeof(buf))) {
            return std::string(buf);
        }
    } else if (sa->sa_family == AF_INET6) {
        const sockaddr_in6* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
        if (inet_ntop(AF_INET6, &(sin6->sin6_addr), buf, sizeof(buf))) {
            return std::string(buf);
        }
    }

    return "";
}

static std::string readFirstLine(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";

    std::string line;
    std::getline(file, line);
    return line;
}

static int readIntFromFile(const std::string& path, int fallback = -1) {
    std::ifstream file(path);
    if (!file.is_open()) return fallback;

    int value = fallback;
    file >> value;
    return file.fail() ? fallback : value;
}

static std::string formatFlagNames(unsigned int flags) {
    std::vector<std::string> parts;

    if (flags & IFF_UP) parts.emplace_back("UP");
    if (flags & IFF_BROADCAST) parts.emplace_back("BROADCAST");
    if (flags & IFF_DEBUG) parts.emplace_back("DEBUG");
    if (flags & IFF_LOOPBACK) parts.emplace_back("LOOPBACK");
    if (flags & IFF_POINTOPOINT) parts.emplace_back("POINTOPOINT");
    if (flags & IFF_RUNNING) parts.emplace_back("RUNNING");
    if (flags & IFF_NOARP) parts.emplace_back("NOARP");
    if (flags & IFF_PROMISC) parts.emplace_back("PROMISC");
    if (flags & IFF_ALLMULTI) parts.emplace_back("ALLMULTI");
    if (flags & IFF_MULTICAST) parts.emplace_back("MULTICAST");

    std::ostringstream oss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) oss << ",";
        oss << parts[i];
    }
    return oss.str();
}

static int ipv6PrefixLenFromMask(const sockaddr* sa) {
    if (!sa || sa->sa_family != AF_INET6) return -1;

    const sockaddr_in6* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
    int bits = 0;

    for (int i = 0; i < 16; ++i) {
        unsigned char byte = sin6->sin6_addr.s6_addr[i];
        for (int bit = 7; bit >= 0; --bit) {
            if (byte & (1u << bit)) {
                bits++;
            }
        }
    }

    return bits;
}

static bool addressEntryLess(const AddressEntry& a, const AddressEntry& b) {
    if (a.family != b.family) {
        return a.family == AF_INET;
    }
    return a.address < b.address;
}

static std::string buildIfconfigLikeBlock(const InterfaceDump& iface, const std::map<std::string, int>& mtuMap, const std::map<std::string, int>& txQueueMap) {
    std::ostringstream oss;

    const auto mtuIt = mtuMap.find(iface.name);
    const auto txIt = txQueueMap.find(iface.name);

    const int mtu = (mtuIt != mtuMap.end()) ? mtuIt->second : -1;
    const int txq = (txIt != txQueueMap.end()) ? txIt->second : -1;

    oss << iface.name << ": flags=" << iface.flags
        << "<" << formatFlagNames(iface.flags) << ">";

    if (mtu >= 0) {
        oss << "  mtu " << mtu;
    }

    oss << "\n";

    std::vector<AddressEntry> sorted = iface.addresses;
    std::sort(sorted.begin(), sorted.end(), addressEntryLess);

    for (const auto& addr : sorted) {
        if (addr.family == AF_INET) {
            oss << "        inet " << (addr.address.empty() ? "-" : addr.address);

            if (!addr.netmask.empty()) {
                oss << "  netmask " << addr.netmask;
            }

            if (!addr.peerOrBroadcast.empty()) {
                if (addr.isPointToPoint) {
                    oss << "  destination " << addr.peerOrBroadcast;
                } else if (addr.isBroadcast) {
                    oss << "  broadcast " << addr.peerOrBroadcast;
                }
            }

            oss << "\n";
        } else if (addr.family == AF_INET6) {
            oss << "        inet6 " << (addr.address.empty() ? "-" : addr.address);

            if (!addr.netmask.empty()) {
                oss << "  prefixlen " << addr.netmask;
            }

            if (!addr.peerOrBroadcast.empty() && addr.isPointToPoint) {
                oss << "  destination " << addr.peerOrBroadcast;
            }

            oss << "\n";
        }
    }

    if (txq >= 0) {
        oss << "        txqueuelen " << txq << "\n";
    }

    return oss.str();
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_com_cherepavel_vpndetector_detector_IfconfigTermuxLikeDetector_getInterfacesNative(
        JNIEnv* env,
        jobject /* thiz */) {

    jclass stringCls = env->FindClass("java/lang/String");
    if (stringCls == nullptr) {
        return nullptr;
    }

    std::map<std::string, InterfaceDump> interfaces;
    std::map<std::string, int> mtuMap;
    std::map<std::string, int> txQueueMap;

    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1 || ifaddr == nullptr) {
        return env->NewObjectArray(0, stringCls, nullptr);
    }

    for (struct ifaddrs* it = ifaddr; it != nullptr; it = it->ifa_next) {
        if (!it->ifa_name) continue;

        std::string name(it->ifa_name);
        auto& iface = interfaces[name];

        iface.name = name;
        iface.flags |= static_cast<unsigned int>(it->ifa_flags);

        if (mtuMap.find(name) == mtuMap.end()) {
            mtuMap[name] = readIntFromFile("/sys/class/net/" + name + "/mtu", -1);
        }
        if (txQueueMap.find(name) == txQueueMap.end()) {
            txQueueMap[name] = readIntFromFile("/sys/class/net/" + name + "/tx_queue_len", -1);
        }

        if (!it->ifa_addr) continue;

        const int family = it->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;

        AddressEntry entry;
        entry.family = family;
        entry.address = sockaddrToString(it->ifa_addr);
        entry.isPointToPoint = (it->ifa_flags & IFF_POINTOPOINT) != 0;
        entry.isBroadcast = (it->ifa_flags & IFF_BROADCAST) != 0;

        if (family == AF_INET) {
            entry.netmask = sockaddrToString(it->ifa_netmask);
        } else if (family == AF_INET6) {
            int prefixLen = ipv6PrefixLenFromMask(it->ifa_netmask);
            if (prefixLen >= 0) {
                entry.netmask = std::to_string(prefixLen);
            }
        }

        if (entry.isPointToPoint && it->ifa_dstaddr) {
            entry.peerOrBroadcast = sockaddrToString(it->ifa_dstaddr);
        } else if (entry.isBroadcast && it->ifa_ifu.ifu_broadaddr) {
            entry.peerOrBroadcast = sockaddrToString(it->ifa_ifu.ifu_broadaddr);
        }

        iface.addresses.push_back(entry);
    }

    freeifaddrs(ifaddr);

    std::vector<std::string> dumps;
    dumps.reserve(interfaces.size());

    for (const auto& pair : interfaces) {
        dumps.push_back(buildIfconfigLikeBlock(pair.second, mtuMap, txQueueMap));
    }

    jobjectArray result = env->NewObjectArray(
            static_cast<jsize>(dumps.size()),
            stringCls,
            nullptr
    );

    for (jsize i = 0; i < static_cast<jsize>(dumps.size()); ++i) {
        jstring text = env->NewStringUTF(dumps[i].c_str());
        env->SetObjectArrayElement(result, i, text);
        env->DeleteLocalRef(text);
    }

    return result;
}
