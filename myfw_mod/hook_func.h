#ifndef _HOOK_FUNC_H
#define _HOOK_FUNC_H

#include "./struct.h"

// TrafficExist return 101
// FullNow return 102
// return 0-100 find the place to insert
unsigned CHashCheck(unsigned sip,unsigned dip,unsigned char protocol,unsigned short sport,unsigned short dport){
    // Hash表的计算方法
    unsigned p = (sip ^ dip ^ protocol ^ sport ^ dport) % MAX_STATU_NUM;
    unsigned tmp = p;
    // 全局变量jiffies取值为自操作系统启动以来的时钟滴答的数目 用时间替代也类似
    while(time_before(jiffies,cons[p].t)){
        if((protocol==cons[p].protocol && sip==cons[p].sip && dip==cons[p].dip && sport==cons[p].sport && dport==cons[p].dport) || 
        (protocol==cons[p].protocol && sip==cons[p].dip && dip==cons[p].sip && sport==cons[p].dport && dport==cons[p].sport)){
            // 是记录表中已记录的出流量或入流量
            cons[p].t = jiffies + 15*HZ; // TODO
            printk("HashCheck: traffic exist\n");
            printk("\n");
            return 101;
        }
        p = (p+7)%MAX_STATU_NUM;
        if(p==tmp){
            printk("HashCheck: HashList Full Now\n");
            return 102;
        }
    }
    printk("HashCheck: find place p:%u to insert\n",p);
    return p;
}

void UpdateHashList(void){
    cnum=0;
    char buff[20], buff2[20];
    int i=0;
    for(i=0;i<MAX_STATU_NUM;i++){
        if(cons[i].sip!=0 && cons[i].dip!=0){
        // if(time_before(jiffies,cons[i].t)){
            printk("i:%dth ",i);
            printk("sip:%s ",addr_from_net(buff,ntohl(cons[i].sip)));
            printk("dip:%s ",addr_from_net(buff2,ntohl(cons[i].dip)));
            printk("sport:%hu ", cons[i].sport);
		    printk("dport:%hu ", cons[i].dport);
		    printk("protocol:%hhu\n", cons[i].protocol);
            cons2[cnum].sip = cons[i].sip;
            cons2[cnum].dip = cons[i].dip;
            cons2[cnum].sport = cons[i].sport;
            cons2[cnum].dport = cons[i].dport;
            cons2[cnum].protocol = cons[i].protocol;
            cons2[cnum].t = 0;
            cnum++;
        }
    }
    printk("UpdateHashList cnum:%d\n",cnum);
}

void HashInsert(unsigned sip,unsigned dip,unsigned char protocol,unsigned short sport,unsigned short dport,unsigned p){
    printk("HashInsert:%dth\n",p);
    cons[p].sip = sip;
    cons[p].dip = dip;
    cons[p].sport = sport;
    cons[p].dport = dport;
    cons[p].protocol = protocol;
    cons[p].t = jiffies + 15*HZ;
}




void GetPort(struct sk_buff* skb, struct iphdr* hdr, unsigned short *sport, unsigned short *dport){
    struct tcphdr *mytcphdr;
    struct udphdr *myudphdr;
    switch(hdr->protocol){
        case TCP:
            mytcphdr = (struct tcphdr *)(skb->data + (hdr->ihl*4));
            *sport = ntohs(mytcphdr->source);
            *dport = ntohs(mytcphdr->dest);
            break;
        case UDP:
            myudphdr = (struct udphdr *)(skb->data + (hdr->ihl*4));
            *sport = ntohs(myudphdr->source);
            *dport = ntohs(myudphdr->dest);
            break;
        case ICMP:
            *sport = ICMP_PORT;
            *dport = ICMP_PORT;
            break;
        default:
            printk("UNKNOW PROTOCOL\n");
            *sport = 0;
            *dport = 0;
            break;
    }
}

bool IsMatch(unsigned ip, const char *ip_range){
    char tmp_ip[20];
    int p = -1, count = 0;
    unsigned len = 0, tmp = 0, mask = 0, r_ip = 0,i;
    strcpy(tmp_ip, ip_range);
    for(i = 0; i < strlen(tmp_ip); i++){
        if(p != -1){
            len *= 10;
            len += tmp_ip[i] - '0';
        }
        else if(tmp_ip[i] == '/')
            p = i;
    }
    if(p != -1){
        tmp_ip[p] = '\0';
        if(len)
            mask = 0xFFFFFFFF << (32 - len);
    }
    else mask = 0xFFFFFFFF;
    for(i = 0; i < strlen(tmp_ip); i++){
        if(tmp_ip[i] == '.'){
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += tmp_ip[i] - '0';
    }
    r_ip = r_ip | tmp;
    return (r_ip & mask) == (ip & mask);
}




unsigned int hook_func(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int(*okfn)(struct sk_buff*)
){
    short sport,dport;
    struct iphdr *hdr;
    hdr = ip_hdr(skb);

    // get port
    GetPort(skb,hdr,&sport,&dport);

    char buff[20],buff2[20];
    printk("hook get ip_pkt sip:");
    print_ip(ntohl(hdr->saddr));
    printk("hook get ip_pkt dip:");
    print_ip(ntohl(hdr->daddr));
    GetPort(skb, hdr, &sport, &dport);
	printk("src_port:%hu dst_port:%hu\n", sport, dport);
    printk("\n");

    int ret;
    // check status list
    ret = CHashCheck(hdr->saddr,hdr->daddr,hdr->protocol,sport,dport);
    if(ret == 101) return NF_ACCEPT;
    else if(ret == 102){
        printk("connection list full!\n");
        return NF_DROP;
    }
    else if(ret<0 || ret>102){
        printk("connection list error!\n");
        return NF_DROP;
    }
    


    // match rule list
    int i=0;
    for(i =0;i<rnum;i++){
        printk("matching the %dth rules........\n",i);
        if(strcmp(rules[i].sip,"any") && (!IsMatch(ntohl(hdr->saddr),rules[i].sip)))
            continue;
        if(strcmp(rules[i].dip,"any") && (!IsMatch(ntohl(hdr->daddr),rules[i].dip)))
            continue;
        if(rules[i].protocol != ANY && rules[i].protocol != hdr->protocol) continue;
        if(rules[i].sport != ANY && sport != rules[i].sport) continue;
        if(rules[i].dport != ANY && dport != rules[i].dport) continue;
        if(rules[i].log && lnum<MAX_LOG_NUM){
            logs[lnum].dip = hdr->daddr;
			logs[lnum].sip = hdr->saddr;
			logs[lnum].dport = dport;
			logs[lnum].sport = sport;
			logs[lnum].protocol = hdr->protocol;
			logs[lnum].action = rules[i].action;
			lnum++;
        }
        if(rules[i].action){
            HashInsert(hdr->saddr,hdr->daddr,hdr->protocol,sport,dport,ret);
            printk("insert a connection with hash in %dth\n",ret);
            return NF_ACCEPT;
        }
        else{
            printk("rule deny!\n");
            return NF_DROP;
        }
    }

    if(isAccept){
        // default accept
        HashInsert(hdr->saddr,hdr->daddr,hdr->protocol,sport,dport,ret);
        printk("default accept: insert a connection with hash in %d\n",ret);
        return NF_ACCEPT;
    }
    else{
        // default deny
        printk("default deny!\n");
        return NF_DROP;
    }
}

unsigned int hook_func_nat_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff*)){
    unsigned short sport,dport;
    struct iphdr *hdr;
    struct tcphdr *tcph;
    struct udphdr *udph;
    int hdr_len,tot_len,i;

    hdr = ip_hdr(skb);

    // show packet info
    printk("Before DNAT: \n");
    // printk("nat in: %s -> %s\n", in->name, out->name);
	printk("this pkt src ip is ");
    print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
    print_ip(ntohl(hdr->daddr));
	GetPort(skb, hdr, &sport, &dport);
	printk("src_port:%hu dst_port:%hu\n", sport, dport);

    for(i = 0; i < nnum; i++){
		if(ntohl(hdr->daddr) == firewall_ip && dport == natTable[i].fw_port){
			hdr->daddr = ntohl(natTable[i].nat_ip);
        	hdr_len = ip_hdrlen(skb);
        	tot_len = ntohs(hdr->tot_len);
            hdr->check = 0;
            hdr->check = ip_fast_csum(hdr,hdr->ihl);

			switch(hdr->protocol) {
				case TCP:
					tcph = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
					tcph->dest = htons(natTable[i].nat_port);
                	tcph->check = 0;
                	skb->csum = csum_partial((unsigned char *)tcph, tot_len - hdr_len,0);
                	tcph->check = csum_tcpudp_magic(hdr->saddr,
                                                hdr->daddr,
                                                ntohs(hdr->tot_len) - hdr_len,hdr->protocol,
                                                skb->csum);
					break;
				case UDP:
					udph = (struct udphdr *)(skb->data + (hdr->ihl * 4));
					udph->dest = htons(natTable[i].nat_port);
					udph->check = 0;
					skb->csum = csum_partial((unsigned char *)udph, tot_len - hdr_len,0);
                	udph->check = csum_tcpudp_magic(hdr->saddr,
                                                hdr->daddr,
                                                ntohs(hdr->tot_len) - hdr_len,hdr->protocol,
                                                skb->csum);
                	break;
				case ICMP:
					break;
			}
            printk("After DNAT(match nat rules): \n");
			printk("this pkt src ip is ");
    		print_ip(ntohl(hdr->saddr));
			printk("this pkt dst ip is ");
    		print_ip(ntohl(hdr->daddr));
            GetPort(skb, hdr, &sport, &dport);
	        printk("src_port:%hu dst_port:%hu\n", sport, dport);
			printk("\n");
    		return NF_ACCEPT;
		}
	}

    printk("Don't need DNAT: \n");
    printk("this pkt src ip is ");
    print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
    print_ip(ntohl(hdr->daddr));
    GetPort(skb, hdr, &sport, &dport);
	printk("src_port:%hu dst_port:%hu\n", sport, dport);
	printk("\n");
    return NF_ACCEPT;
}

// 源地址nat
unsigned int hook_func_nat_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff*)){
    unsigned short sport,dport;
    struct iphdr *hdr;
    struct tcphdr *tcph;
    struct udphdr *udph;
    int hdr_len,tot_len,i;

    hdr = ip_hdr(skb);

    // show packet info
    printk("Before SNAT: \n");
	printk("this pkt src ip is ");
    print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
    print_ip(ntohl(hdr->daddr));
	GetPort(skb, hdr, &sport, &dport);
	printk("src_port:%hu dst_port:%hu\n", sport, dport);

    for(i = 0; i < nnum; i++){
		if(ntohl(hdr->saddr) == natTable[i].nat_ip && sport == natTable[i].nat_port){
			printk("match snat rules!\n");	
			hdr->saddr = ntohl(firewall_ip);
        	hdr_len = ip_hdrlen(skb);
        	tot_len = ntohs(hdr->tot_len);
            hdr->check = 0;
            hdr->check = ip_fast_csum(hdr,hdr->ihl);

			switch(hdr->protocol) {
				case TCP:
					tcph = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
					tcph->source = htons(natTable[i].fw_port);
                	tcph->check = 0;
                	skb->csum = csum_partial((unsigned char *)tcph, tot_len - hdr_len,0);
                	tcph->check = csum_tcpudp_magic(hdr->saddr,
                                                hdr->daddr,
                                                ntohs(hdr->tot_len) - hdr_len,hdr->protocol,
                                                skb->csum);
					break;
				case UDP:
					udph = (struct udphdr *)(skb->data + (hdr->ihl * 4));
					udph->source = htons(natTable[i].fw_port);
					udph->check = 0;
					skb->csum = csum_partial((unsigned char *)udph, tot_len - hdr_len,0);
                	udph->check = csum_tcpudp_magic(hdr->saddr,
                                                hdr->daddr,
                                                ntohs(hdr->tot_len) - hdr_len,hdr->protocol,
                                                skb->csum);
                	break;
				case ICMP:
					break;
			}

		    printk("After SNAT(match nat rules): \n");
            printk("this pkt src ip is ");
    		print_ip(ntohl(hdr->saddr));
			printk("this pkt dst ip is ");
    		print_ip(ntohl(hdr->daddr));
            GetPort(skb, hdr, &sport, &dport);  
	        printk("src_port:%hu dst_port:%hu\n", sport, dport);
			printk("\n");
            return NF_ACCEPT;
		}
	}


    if((ntohl(hdr->saddr) & net_mask) == (net_ip & net_mask)){
        printk("Add a nat rule!\n");
        if(hdr->protocol == ICMP){
            natTable[0].nat_ip = ntohl(hdr->saddr);
            natTable[0].nat_port = ICMP_PORT;
            natTable[0].fw_port = ICMP_PORT;
            return NF_REPEAT;
        }
        natTable[nnum].nat_ip = ntohl(hdr->saddr);
        natTable[nnum].nat_port = sport;
        natTable[nnum].fw_port = firewall_port;
        firewall_port++;
        nnum++;
        return NF_REPEAT;
    }

    printk("Dont't need SNAT: \n");
    printk("this pkt src ip is ");
    print_ip(ntohl(hdr->saddr));
	printk("this pkt dst ip is ");
    print_ip(ntohl(hdr->daddr));
    GetPort(skb, hdr, &sport, &dport);
	printk("src_port:%hu dst_port:%hu\n", sport, dport);
	printk("\n");
    return NF_ACCEPT;
}

#endif _HOOK_FUNC_H