#ifndef _STRUCT_H
#define _STRUCT_H

#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
//#include <linux/jiffies.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define TCP 6
#define UDP 17
#define ICMP 1
#define ANY -1
#define MAX_RULE_NUM 50
#define MAX_STATU_NUM 101
#define MAX_NAT_NUM 100
#define MAX_LOG_NUM 1000
#define NETLINK_TEST (25)
#define MAX_PAYLOAD (1024)
#define TEST_PID (100)
#define MSG_LEN	(256)

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

static Rule rules[MAX_RULE_NUM];
static Connection cons[MAX_STATU_NUM];
static Connection cons2[MAX_STATU_NUM];
static NatEntry natTable[MAX_NAT_NUM];
static Log logs[MAX_LOG_NUM];

static int rnum = 0; //rules num
static int cnum = 0; //nat rules num
static int nnum = 1; //nat rules num (has icmp default)
static int lnum = 0;//logs num

static unsigned net_ip = 0, net_mask = 0, firewall_ip = 0;

#endif _STRUCT_H