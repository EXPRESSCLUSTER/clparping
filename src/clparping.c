#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "clparping.h"

int main
(
    int argc,
    char *argv[]
)
{
    int i, ret, if_num, sd;
    struct ifreq ifr;
    struct ifconf ifc;
    struct ether_arp arp_packet;
    struct sockaddr_ll sock_addr;
    struct timeval timeout_val;
    struct timespec start_time, cur_time, timeout, remain_time;
    fd_set fds, readfds;
    char buf[BUF_SIZE];
    char logmsg[BUF_SIZE];
    char ifname[IFNAMSIZ], *ip;
    uint32_t src_ip, tmp_ip, dst_ip;

    /* Check arguments */
    int opt;
    int qflag = 0;
    int wflag = 0, wtime = SELECT_TIMEOUT_SEC;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <DEST_IP> [-q] [-w timeout]\n", argv[0]);
        exit(1);
    }

    while ((opt = getopt(argc, argv, "qw:")) != -1) {
        switch (opt) {
        case 'q':
            qflag = 1;
            break;
        case 'w':
            wflag = 1;
            wtime = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s <DEST_IP> [-q] [-w timeout]\n", argv[0]);
            exit(1);
        }
    }

    if (wflag == 1 && wtime == 0) {
        fprintf(stderr, "Timeout must be numeric more than 0\n");
        exit(1);
    }

    if (argc - optind > 1) {
        fprintf(stderr, "Too many arguments.\n");
        exit(1);
    }

    ip = argv[optind];
    dst_ip = inet_addr(ip);
    if (dst_ip == INADDR_NONE) {
        sprintf(logmsg, "Invalid IP address. (Target IP is %s)", ip);
        fprintf(stderr, "%s\n", logmsg);
        if (qflag == 0) {
            ret = call_clplogcmd(logmsg, EVT_INVALIDIP, "WARN");
            if (ret != 0) {
                fprintf(stderr, "clplogcmd failed.\n");
            }
        }
        exit(1);
    }
    
    /* Create socket */
    sd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (sd == -1) {
        perror("create socket");
        exit(1);
    }

    /* Find NIC name to send ARP request */
    ret = specify_nic(sd, dst_ip, ifname);
    if (ret == ERR_NO_PROPER_NIC) {
        sprintf(logmsg, "Proper NIC is not found. (Target IP is %s)", ip);
        fprintf(stderr, "%s\n", logmsg);
        if (qflag == 0) {
            ret = call_clplogcmd(logmsg, EVT_NOPROPERNIC, "WARN");
            if (ret != 0) {
                fprintf(stderr, "clplogcmd failed.\n");
            }
        }
        exit(1);
    }
    else if (ret != 0) {
        fprintf(stderr, "specify_nic error: %d\n", ret);
        exit(1);
    }

    /* Get sender IP address */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
        perror("get IP address");
        exit(1);
    }
    src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    /* Get sender MAC address */
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("get MAC address");
        exit(1);
    }
 
    /* Set socket */
    memset(&sock_addr, 0x0, sizeof(sock_addr));
    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_protocol = htons(ETH_P_ARP);
    sock_addr.sll_ifindex = if_nametoindex(ifname);
    sock_addr.sll_halen = MAC_LENGTH;
    memset(&sock_addr.sll_addr, 0xff, MAC_LENGTH);

    /* Bind socket */
    ret = bind(sd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
    if (ret == -1) {
        perror("bind()");
        exit(1);
    }

    /* Create SEND packet */
    memset(&arp_packet, 0x0, sizeof(arp_packet));
    arp_packet.arp_hrd = htons(HW_TYPE);
    arp_packet.arp_pro = htons(ETHERTYPE_IP);
    arp_packet.arp_hln = MAC_LENGTH;
    arp_packet.arp_pln = IPV4_LENGTH;
    arp_packet.arp_op  = htons(ARPOP_REQUEST);
    memcpy(arp_packet.arp_sha, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);
    memcpy(arp_packet.arp_spa, &src_ip, sizeof(uint32_t));
    memcpy(arp_packet.arp_tpa, &dst_ip, sizeof(uint32_t));

    #ifdef DEBUG
    printf("--------\n");
    printf("SEND\n");
    print_arp(&arp_packet);
    printf("--------\n");
    #endif

    /* Preparation for select */
    FD_ZERO(&readfds);
    FD_SET(sd, &readfds);

    /* Send ARP request */
    if (sendto(sd, (char *)&arp_packet, sizeof(arp_packet), 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
        perror("sendto");
        exit(1);
    }

    /* Get timestamp before entering while roop. */
    /* The timestamp will be used to leave the roop by comparing with current time. */
    ret = clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    if (ret == -1) {
        perror("clock_gettime");
        exit(1);
    }
    timeout.tv_sec = start_time.tv_sec + wtime;
    timeout.tv_nsec = start_time.tv_nsec + SELECT_TIMEOUT_NSEC;

    while (1) {
        /* Check timestamp */
        /* If it has been wtime since entering roop, exit from the program. */
        ret = clock_gettime(CLOCK_MONOTONIC_RAW, &cur_time);
        if (ret == -1) {
            perror("clock_gettime");
            exit(1);
        }

        #ifdef DEBUG
        printf("start time: %10ld.%09ld\n", start_time.tv_sec, start_time.tv_nsec);
        printf("  cur time: %10ld.%09ld\n", cur_time.tv_sec, cur_time.tv_nsec);
        printf("   timeout: %10ld.%09ld\n", timeout.tv_sec, timeout.tv_nsec);
        #endif

        remain_time.tv_sec = timeout.tv_sec - cur_time.tv_sec;
        remain_time.tv_nsec = timeout.tv_nsec - cur_time.tv_nsec;
        if (timeout.tv_nsec - cur_time.tv_nsec < 0) {
            remain_time.tv_sec--;
            remain_time.tv_nsec += 1000000000;
        }

        if (remain_time.tv_sec < 0) {           
            #ifdef DEBUG
            printf("TIMEOUT value is %d sec.\n", wtime);
            #endif

            sprintf(logmsg, "Timeout. (Target IP is %s)", ip);
            fprintf(stderr, "%s\n", logmsg);
            if (qflag == 0) {
                ret = call_clplogcmd(logmsg, EVT_SELECTTIMEOUT, "WARN");
                if (ret != 0) {
                    fprintf(stderr, "clplogcmd failed.\n");
                }
            }
            exit(1);
        }

        #ifdef DEBUG
        printf("    remain: %10ld.%09ld\n\n", remain_time.tv_sec, remain_time.tv_nsec);
        #endif
 
        /* Wait for socket to become ready */
        memcpy(&fds, &readfds, sizeof(fd_set));
        timeout_val.tv_sec = remain_time.tv_sec;
        timeout_val.tv_usec = remain_time.tv_nsec / 1000;
        ret = select(sd + 1, &fds, NULL, NULL, &timeout_val);
        if (ret == -1) {
            perror("select");
            exit(1);
        }
        else if (ret == 0) {
            #ifdef DEBUG
            printf("TIMEOUT value is %d sec.\n", wtime);
            #endif

            sprintf(logmsg, "Timeout. (Target IP is %s)", ip);
            fprintf(stderr, "%s\n", logmsg);
            if (qflag == 0) {
                ret = call_clplogcmd(logmsg, EVT_SELECTTIMEOUT, "WARN");
                if (ret != 0) {
                    fprintf(stderr, "clplogcmd failed.\n");
                }
            }
            exit(1);
        }

        /* Receive ARP reply */
        if (FD_ISSET(sd, &fds)) {
            memset(buf,0x0,sizeof(buf));
            ret = recvfrom(sd, buf, sizeof(buf), 0, NULL, NULL);
            if(ret == -1) {
                perror("recvfrom");
                exit(1);
            }

            /* Receive only packet of which target is my IP */
            memcpy(&arp_packet, buf, sizeof(arp_packet));
            memcpy(&tmp_ip, arp_packet.arp_tpa, sizeof(tmp_ip));
            if (tmp_ip != src_ip || ntohs(((struct ether_arp*)buf)->ea_hdr.ar_op) != 2) {       
                continue;
            }

            #ifdef DEBUG
            printf("--------\n");
            printf("RECV\n");
            print_arp(&arp_packet);
            printf("arp_packet operation : %d\n", ntohs(((struct ether_arp*)buf)->ea_hdr.ar_op));
            printf("--------\n");
            #endif
        }

        break;
    }

    ret = close(sd);
    if (ret == -1) {
        perror("close socket");
        exit(1);
    }

    printf("Success\n");
    return 0;
}

void print_arp
(
    struct ether_arp *packet
)
{
    printf("arp_packet sender IP : %3d.%3d.%3d.%3d\n",
        packet->arp_spa[0], packet->arp_spa[1],
        packet->arp_spa[2], packet->arp_spa[3]);
    printf("arp_packet target IP : %3d.%3d.%3d.%3d\n",
        packet->arp_tpa[0], packet->arp_tpa[1],
        packet->arp_tpa[2], packet->arp_tpa[3]);
    printf("arp_packet sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        packet->arp_sha[0], packet->arp_sha[1], packet->arp_sha[2],
        packet->arp_sha[3], packet->arp_sha[4], packet->arp_sha[5]);
    printf("arp_packet target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        packet->arp_tha[0], packet->arp_tha[1], packet->arp_tha[2],
        packet->arp_tha[3], packet->arp_tha[4], packet->arp_tha[5]);
}

int call_clplogcmd
(
    char *msg,
    int id,
    char *level
)
{
    int ret;
    char evt_id[BUF_SIZE];
    char cmd_line[BUF_SIZE] = "clplogcmd -m ";

    sprintf(evt_id, "%d", id);

    strcat(cmd_line, "\"");
    strcat(cmd_line, msg);
    strcat(cmd_line, "\" -i ");
    strcat(cmd_line, evt_id);
    strcat(cmd_line, " -l ");
    strcat(cmd_line, level);
    strcat(cmd_line, " > /dev/null 2>&1");

    ret = system(cmd_line);
    if (WIFEXITED(ret)) {
        if (WEXITSTATUS(ret) != 0) {
            return ERR_CLPLOGCMD;
        }
    } else {
        return ERR_SYSTEM;
    }

    return 0;
}

int specify_nic
(
    int sd,
    uint32_t dst_ip,
    char *ifname
)
{
    struct ifconf ifc;
    struct ifreq ifr, ifr_array[MAX_IFR];
    int i, if_num, max_ipmatch = 0;
    uint32_t src_ip, net_mask, src_net, dst_net, bit, bit_array[IPV4_LENGTH];
    uint8_t ip_print[4];

    /* Get all NIC information */
    ifc.ifc_len = sizeof(struct ifreq) * MAX_IFR;
    ifc.ifc_ifcu.ifcu_buf = (void *)ifr_array;
    if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
        perror("get all NIC information");
        exit(1);
    }

    if_num = ifc.ifc_len / (int)sizeof(struct ifreq);

    /* Check network address of each NICs */
    for (i = 0; i < if_num; i++) {
        /* Get IP address of the NIC */
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
        if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
            perror("get IP address");
            exit(1);
        }
        src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

        /* Get netmask of the NIC */
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifr_array[i].ifr_name, IFNAMSIZ);
        if (ioctl(sd, SIOCGIFNETMASK, &ifr) < 0) {
            perror("get netmask");
            exit(1);
        }
        net_mask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;

        src_net = src_ip & net_mask;
        dst_net = dst_ip & net_mask;

        #ifdef DEBUG
        printf("NIC name        : %s\n", ifr_array[i].ifr_name);
        memcpy(ip_print, &src_ip, sizeof(uint32_t));
        printf("src IP          : %3d.%3d.%3d.%3d\n", ip_print[0], ip_print[1], ip_print[2], ip_print[3]);
        memcpy(ip_print, &net_mask, sizeof(uint32_t));
        printf("netmask         : %3d.%3d.%3d.%3d\n", ip_print[0], ip_print[1], ip_print[2], ip_print[3]);
        memcpy(ip_print, &src_net, sizeof(uint32_t));
        printf("src network     : %3d.%3d.%3d.%3d\n", ip_print[0], ip_print[1], ip_print[2], ip_print[3]);
        memcpy(ip_print, &dst_net, sizeof(uint32_t));
        printf("dst network     : %3d.%3d.%3d.%3d\n\n", ip_print[0], ip_print[1], ip_print[2], ip_print[3]);
        #endif

        /* Specify proper NIC by comparing both network addresses */
        if (src_net == dst_net) {

            #ifdef DEBUG
            printf("** MATCH **\n\n");
            #endif

            strncpy(ifname, ifr_array[i].ifr_name, sizeof(ifr_array[i].ifr_name));
            return 0;
        }
    }

    /*  Proper NIC is not found.  */

    return ERR_NO_PROPER_NIC;
}