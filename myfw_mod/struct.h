#ifndef _STRUCT_H
#define _STRUCT_H

#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/version.h>
#include<linux/skbuff.h>
#include <linux/net.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/ip.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/kdev_t.h>
#include <linux/kmod.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/if_arp.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/proc_fs.h>


#define TCP 6
#define UDP 17
#define ICMP 1
#define ANY -1
#define ICMP_PORT 12345
#define MAX_RULE_NUM 50
#define MAX_STATU_NUM 101
#define MAX_NAT_NUM 100
#define MAX_LOG_NUM 1000
#define NETLINK_TEST (25)

// rule struct (get from socket)
typedef struct {
    char sip[20];
    char dip[20];
    int sport;
    int dport;
    char protocol;
    bool action;
    bool log;
}Rule;

// connection struct (record in kernel)
typedef struct {
    unsigned sip;
    unsigned short sport;
    unsigned dip;
    unsigned short dport;
    unsigned char protocol;
    unsigned long t;
}Connection;

// log struct (record in kernel)
typedef struct {
    unsigned sip;
    unsigned dip;
    unsigned short sport;
    unsigned short dport;
    unsigned char protocol;
    unsigned char action;
}Log;

// nat entry struct
typedef struct {
    unsigned nat_ip;
    unsigned short fw_port;
    unsigned short nat_port;
}NatEntry;
static unsigned short firewall_port = 20000;
static unsigned net_ip, net_mask, firewall_ip;

static Rule rules[MAX_RULE_NUM];
static Connection cons[MAX_STATU_NUM];
static Connection cons2[MAX_STATU_NUM];
static NatEntry natTable[MAX_NAT_NUM];
static Log logs[MAX_LOG_NUM];

static int rnum = 0; //rules num
static int cnum = 0; //nat rules num
static int nnum = 0; //nat rules num
static int lnum = 0;//logs num

static dev_t devId;
static struct class *cls = NULL;

static bool isAccept = true;

char * addr_from_net(char * buff, __be32 addr){
    __u8 *p = (__u8*)&addr;
    snprintf(buff, 16, "%u.%u.%u.%u",
        (__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
    return buff;
}

void print_ip(unsigned long ip) {
    printk("%ld.%ld.%ld.%ld\n", (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, (ip>>0)&0xff);
}



#endif _STRUCT_H