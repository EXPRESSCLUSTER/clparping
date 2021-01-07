#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define HW_TYPE 1
#define BUF_SIZE 256
#define MAX_IFR 64
#define SELECT_TIMEOUT_SEC 3
#define SELECT_TIMEOUT_NSEC 0

#define ERR_NO_PROPER_NIC 1

#define ERR_CLPLOGCMD 1
#define ERR_SYSTEM 2

#define EVT_INVALIDIP 1
#define EVT_NOPROPERNIC 2
#define EVT_SELECTTIMEOUT 3

void print_arp(struct ether_arp *packet);
int call_clplogcmd(char *msg, int id, char *level);
int specify_nic(int sd, uint32_t dst_ip, char *ifname);