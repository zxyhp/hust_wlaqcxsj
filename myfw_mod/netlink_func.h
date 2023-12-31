#ifndef _NETLINK_FUNC_H
#define _NETLINK_FUNC_H

#include "./struct.h"

static struct sock *nl_sk = NULL;

unsigned ipstr_to_num(const char *ip_str){
    int count = 0;
    unsigned tmp = 0,ip = 0, i;
    for(i = 0; i < strlen(ip_str); i++){
        if(ip_str[i] == '.'){
            ip = ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += ip_str[i] - '0';
    }
    ip = ip | tmp;
    return ip;
}



static void netlink_clear(void){
    netlink_kernel_release(nl_sk);
    // device_destroy(cls, devId);
    // class_destroy(cls);
    // unregister_chrdev_region(devId, 1);
}

static int netlink_send(int pid, char* info, int len){
	struct sk_buff *skb_1;
    struct nlmsghdr *nlh;
    if(!info || !nl_sk) {
        return;
    }
    skb_1 = alloc_skb(NLMSG_SPACE(len), GFP_KERNEL);
    if( !skb_1 ) {
        printk(KERN_ERR "alloc_skb error!\n");
    }
    nlh = nlmsg_put(skb_1, 0, 0, 0, len, 0);
    NETLINK_CB(skb_1).portid = 0;
    NETLINK_CB(skb_1).dst_group = 0;
    memcpy(NLMSG_DATA(nlh), info, len);
	// printk("[kernel space] skb->data send to user: '%s'\n",(char *) NLMSG_DATA(nlh));
    netlink_unicast(nl_sk, skb_1, pid, MSG_DONTWAIT);
	return 0;
}

static void netlink_recv(struct sk_buff *__skb){
	int i,pid;
    struct sk_buff *skb;
    char str[1000];
	char buff[20], buff2[20];
    struct nlmsghdr *nlh;

    if( !__skb ) {
        return;
    }

    skb = skb_get(__skb);
    if( skb->len < NLMSG_SPACE(0)) {
        return;
    }

    nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk("Illegal netlink packet!\n");
		return;
	}

    memset(str, 0, sizeof(str));
    memcpy(str, NLMSG_DATA(nlh), 1000);

	pid = nlh->nlmsg_pid;

	switch (str[0])
	{
	case 1:
		//flush rules
		rnum = str[1];
		memcpy(rules, str + 2, rnum * sizeof(Rule));
		printk("\n!!! update rules !!!\n");
		for(i = 0; i < rnum; i++){
			printk("rnum:%d ", i);
			printk("sip:%s ", rules[i].sip);
			printk("dip:%s ", rules[i].dip);
			printk("sport:%d ", rules[i].sport);
			printk("dport:%d ", rules[i].dport);
			printk("protocol:%d ", rules[i].protocol);
			printk("log:%hhu ", rules[i].log);
			printk("action:%hhu\n", rules[i].action);
		}
		break;
	case 2:
		//get logs
		printk("\n!!! log list !!!\n");
		for(i = 0; i < lnum; i++){
			printk("lnum:%d ", i);
			printk("sip:%s ", addr_from_net(buff,ntohl(logs[i].sip)));
			printk("dip:%s ", addr_from_net(buff,ntohl(logs[i].dip)));
			printk("sport:%hu ", logs[i].sport);
			printk("dport:%hu ", logs[i].dport);
			printk("protocol:%hhu ", logs[i].protocol);
			printk("action:%hhu\n", logs[i].action);
		}
		netlink_send(nlh->nlmsg_pid, (char *)logs, lnum * sizeof(Log));
		break;
	case 3:
		//get connections
		printk("\n!!! connection list !!!\n");
		UpdateHashList();
		for(i = 0; i < cnum; i++){
			printk("cnum:%d ", i);
			printk("sip:%s ", addr_from_net(buff,ntohl(cons2[i].sip)));
			printk("dip:%s ", addr_from_net(buff,ntohl(cons2[i].dip)));
			printk("sport:%hu ", cons2[i].sport);
			printk("dport:%hu ", cons2[i].dport);
			printk("protocol:%hhu\n", cons2[i].protocol);
		}
		netlink_send(nlh->nlmsg_pid, (char *)cons2, cnum * sizeof(Connection));
		break;
	case 4:
		// change default rule
		printk("\n!!! change default rule !!!\n");
		switch(str[1]){
			case 'd':
				isAccept = false;
				break;
			default:
				isAccept = true;
				break;
		}
		break;
	case 5:
		//flush nat rules
		nnum = str[1];
		memcpy(&net_ip, str + 2, sizeof(unsigned));
		memcpy(&net_mask, str + 6, sizeof(unsigned));
		memcpy(&firewall_ip, str + 10, sizeof(unsigned));
		memcpy(&natTable[1], str + 14, (nnum-1) * sizeof(NatEntry));
		natTable[0].fw_port = ICMP_PORT;
		natTable[0].nat_port = ICMP_PORT;
		natTable[0].nat_ip = ipstr_to_num("192.168.164.2");
		printk("\n!!! update nat rules !!!\n");
		printk("global_fireip:%s net_ip:%s net_mask:%x\n", addr_from_net(buff,ntohl(firewall_ip)), addr_from_net(buff2,ntohl(net_ip)), net_mask);
		for(i = 0; i < nnum; i++){
			printk("nnum:%d ", i);
			printk("nat_ip:%s firewall_port:%u nat_port:%u\n", addr_from_net(buff2, natTable[i].nat_ip), natTable[i].fw_port, natTable[i].nat_port);
		}
		break;
	case 6:
		// get the newest nat rules
		printk("\n!!! nat rules list !!!\n");
		for(i = 0; i < nnum; i++){
			printk("nnum:%d ", i);
			printk("nat_ip:%s ", addr_from_net(buff,ntohl(natTable[i].nat_ip)));
			printk("nat_port:%hu ", natTable[i].nat_port);
			printk("fw_port:%hu \n", natTable[i].fw_port);
		}
		netlink_send(nlh->nlmsg_pid, (char *)natTable, nnum * sizeof(NatEntry));
		break;
	default:
		break;
	}
    return;
}


#endif _NETLINK_FUNC_H