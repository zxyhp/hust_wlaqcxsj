#ifndef _KT_APP_H
#define _KT_APP_H

#include "./struct.h"


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

char * addr_from_net(char * buff, __be32 addr){
    __u8 *p = (__u8*)&addr;
    snprintf(buff, 16, "%u.%u.%u.%u",
        (__u32)p[0], (__u32)p[1], (__u32)p[2], (__u32)p[3]);
    return buff;
}





int netlink_create_socket(){
    return socket(PF_NETLINK,SOCK_RAW,NETLINK_TEST);
}

int netlink_bind(int skfd){
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;
    return bind(skfd, (struct sockaddr *)&local, sizeof(local));
}

int netlink_send_message(int skfd, char* data,int dlen){

	struct sockaddr_nl kpeer;
	int ret, kpeerlen = sizeof(struct sockaddr_nl);

	struct nlmsghdr *nlh;
	char *retval;

    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;

    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(dlen));
	if (nlh == NULL) {
		printf("malloc() error\n");
		return -1;
	}

    // memset(nlh, '\0', sizeof(struct nlmsghdr));
	nlh->nlmsg_len = NLMSG_SPACE(dlen);
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = 0;
	nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = getpid();
    retval = memcpy(NLMSG_DATA(nlh), data, dlen);

    printf("message sendto kernel, content: '%s', len: %d\n", (char *) NLMSG_DATA(nlh), nlh->nlmsg_len);
	ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&kpeer, sizeof(kpeer));
	if (!ret) {
		perror("sendto:");
		exit(-1);
	}
    free(nlh);
    return 0;
}

int netlink_recv_message(int sock_fd, unsigned char* message,int* len){
	// struct sockaddr_nl kpeer;
	// int ret, kpeerlen = sizeof(struct sockaddr_nl);
	// struct nlmsghdr *nlh;
	// char *retval;

    // memset(&kpeer, 0, sizeof(kpeer));
    // kpeer.nl_family = AF_NETLINK;
	// kpeer.nl_pid = 0;
	// kpeer.nl_groups = 0;

    // ret = recvfrom(skfd, msg, MSG_LEN, 0, (struct sockaddr *) &kpeer, &kpeerlen);
	// if (!ret) {
	// 	perror("recvfrom:");
	// 	exit(-1);
	// }
	// printf("message recvfrom kernel, content: '%s'\n", msg);
    // free(nlh);
    // return 0;
    struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl source_addr;
	struct iovec iov;
	struct msghdr msg;
	if( !message || !len ) {
		return -1;
	}
	//create message
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if( !nlh ) {
		perror("malloc");
		return -2;
	}
	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
	memset(&source_addr, 0, sizeof(struct sockaddr_nl));
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&source_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if ( recvmsg(sock_fd, &msg, 0) < 0 ) {
		printf("recvmsg error!\n");
		return -3;
	}
	*len = nlh->nlmsg_len - NLMSG_SPACE(0);
	memcpy(message, (unsigned char *)NLMSG_DATA(nlh), *len);
    printf("message recvfrom kernel, content: '%s'\n", message);
	free(nlh);
	return 0;
}





int SendRules(){
    unsigned char a[MAX_PAYLOAD*10];
    memset(a,0,MAX_PAYLOAD*10);
	int len=0;

	int sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}

	if(netlink_bind(sock_fd)<0){
		printf("bind() error\n");
        close(sock_fd);
		exit(EXIT_FAILURE);
	}

    a[0]=1;
    a[1]=rnum;
    memcpy(a+2,rules,rnum*sizeof(Rule));
	netlink_send_message(sock_fd,a,rnum*sizeof(Rule)+2);
	close(sock_fd);

    return 1;
}

bool AddRule(const char* sip,const char* dip,int sport,int dport,char protocol,bool action,bool log){
    if(rnum<MAX_RULE_NUM){
        strcpy(rules[rnum].sip,sip);
        strcpy(rules[rnum].dip,dip);
        rules[rnum].sport = sport;
        rules[rnum].dport = dport;
        rules[rnum].protocol = protocol;
        rules[rnum].action = action;
        rules[rnum].log = log;
        rnum++;
        SendRules();
        return true;
    }
    return false;
}

bool DelRule(int pos){
    if(pos >= rnum || pos<0){
        return false;
    }
    memcpy(rules + pos, rules + pos + 1, sizeof(Rule) * (rnum - pos));
	rnum--;
    SendRules();
	return true;
}

void PrintRules(){
    printf("|----------------------------------------------------------------------|\n");
	printf("|   src_ip    |   dst_ip    |src_port|dst_port|protocol| action |  log  |\n");
	printf("|----------------------------------------------------------------------|\n");
	for(int i = 0; i < rnum; i++){
		printf("|%15.20s|%15.20s|%7hd|%7hd|%7hhd|%7d|%7d|\n", rules[i].sip, rules[i].dip, rules[i].sport, rules[i].dport, rules[i].protocol, rules[i].action, rules[i].log);
		printf("|----------------------------------------------------------------------|\n");
	}
	return;
}

void ChangeDefaultRule(bool res){
    unsigned char a[5];
    memset(a,0,5);
	int len=0;

	int sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}

	if(netlink_bind(sock_fd)<0){
		printf("bind() error\n");
        close(sock_fd);
		exit(EXIT_FAILURE);
	}

    a[0]=4;
    if(res){
        a[1] = 'a';
    }
    else{
        a[1] = 'd';
    }
	netlink_send_message(sock_fd,a,2);
	close(sock_fd);

    return 1;
}




void PrintLogs(){
    int choice;
    // choice the kind of log to see
    printf("Logs(1.all; 2.part): ");
    scanf("%d",&choice);
	
    if(choice==1){
		printf("\nLogs:\n");
		printf("|---------------------------------------------------------------|\n");
		printf("|   src_ip    |   dst_ip    |src_port|dst_port|protocol| action |\n");
		printf("|---------------------------------------------------------------|\n");
	    for(int i = 0; i < lnum; i++){
		    char buff[20], buff2[20];
		    printf("|%15s|%15s|%5hu|%5hu|%5hhu|%5hhu|\n", addr_from_net(buff, logs[i].sip), addr_from_net(buff2, logs[i].dip), logs[i].sport, logs[i].dport, logs[i].protocol, logs[i].action);
	    }
    }
    else{
        char sip[20];
	    char dip[20];
		memset(sip,0,20);
		memset(dip,0,20);
	    int sport,dport;
	    int pro_ch;
	    unsigned char protocol;
        printf("input the filter info: \n");
        printf("src_ip: ");
		scanf("%s",sip);
		printf("dest_ip: ");
		scanf("%s",dip);
		printf("src_port(-1:ANY): ");
		scanf("%d",&sport);
		printf("dest_port(-1:ANY): ");
		scanf("%d",&dport);
		printf("protocol(-1.ANY; 0.TCP; 1.UDP; 2.ICMP): ");
        scanf("%d",&pro_ch);

        switch(pro_ch){
            case 0:
                protocol = TCP;
                break;
            case 1:
                protocol = UDP;
                break;
            case 2:
                protocol = ICMP;
                break;
            default:
                protocol = ANY;
                break;
        }
		printf("\nLogs:\n");
		printf("|---------------------------------------------------------------|\n");
		printf("|   src_ip    |   dst_ip    |src_port|dst_port|protocol| action |\n");
		printf("|---------------------------------------------------------------|\n");
        for(int i = 0; i < lnum; i++){
			char buff[20], buff2[20];
            if(strcmp(sip,"any") && strcmp(sip,addr_from_net(buff, logs[i].sip)))
				continue;
            if(strcmp(dip,"any") && strcmp(dip,addr_from_net(buff, logs[i].dip)))
                continue;
            if(pro_ch != ANY && logs[i].protocol != protocol) continue;
            if(sport != ANY && sport != logs[i].sport) continue;
            if(dport != ANY && dport != logs[i].dport) continue;
		    printf("|%15s|%15s|%5hu|%5hu|%5hhu|%5hhu|\n", addr_from_net(buff, logs[i].sip), addr_from_net(buff2, logs[i].dip), logs[i].sport, logs[i].dport, logs[i].protocol, logs[i].action);
	    }   
    }

}

int GetLogs(){
    unsigned char buf[MAX_PAYLOAD],a[5];
	memset(buf,0,MAX_PAYLOAD);
    memset(a,0,5);
    int len=0;

    int sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}

	if(netlink_bind(sock_fd)<0){
		printf("bind() error\n");
        close(sock_fd);
		exit(EXIT_FAILURE);
	}

    a[0]=2;
    netlink_send_message(sock_fd,(const unsigned char*)a,1);
    if(netlink_recv_message(sock_fd, buf, &len) == 0){
        printf("recvlen:%d\n",len);
		memcpy(logs, buf, len);
		lnum = len / sizeof(Log);
    }
    close(sock_fd);

    PrintLogs();

    return 0;
}

void PrintConnections(){
	printf("Connections:\n");
	for(int i = 0; i < cnum; i++){
		char buff[20], buff2[20];
		printf("|%15s|%15s|%5hu|%5hu|%5hhu|\n", addr_from_net(buff, cons[i].sip), addr_from_net(buff2, cons[i].dip), cons[i].sport, cons[i].dport, cons[i].protocol);
	}
}

int GetConnections(){
    unsigned char buf[MAX_PAYLOAD],a[5];
	memset(buf,0,MAX_PAYLOAD);
    memset(a,0,5);
    int len=0;

    int sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}

	if(netlink_bind(sock_fd)<0){
		printf("bind() error\n");
        close(sock_fd);
		exit(EXIT_FAILURE);
	}

    a[0]=3;
    netlink_send_message(sock_fd,(const unsigned char*)a,1);
    if( netlink_recv_message(sock_fd, buf, &len) == 0 ) {
		printf("recvlen:%d\n",len);
		memcpy(cons, buf, len);
		cnum = len / sizeof(Connection);
	}
	close(sock_fd);
    PrintConnections();
	return 1;

}



void GetNatRules(){
	unsigned char buf[MAX_PAYLOAD],a[5];
	memset(buf,0,MAX_PAYLOAD);
    memset(a,0,5);
    int len=0;

    int sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}

	if(netlink_bind(sock_fd)<0){
		printf("bind() error\n");
        close(sock_fd);
		exit(EXIT_FAILURE);
	}

    a[0]=6;
    netlink_send_message(sock_fd,(const unsigned char*)a,1);
    if(netlink_recv_message(sock_fd, buf, &len) == 0){
        printf("recvlen:%d\n",len);
		memcpy(natTable, buf, len);
		nnum = len / sizeof(NatEntry);
    }
    close(sock_fd);
}

void SetNat(unsigned net, unsigned mask, unsigned ip){
	firewall_ip = ip;
	net_ip = net;
	net_mask = mask;
}

int SendNatRules(){
	unsigned char a[MAX_PAYLOAD*10];
    memset(a,0,MAX_PAYLOAD*10);
	int len=0;

	int sock_fd = netlink_create_socket();
	if(sock_fd == -1) {
		printf("socket error!\n");
		return -1;
	}

	if(netlink_bind(sock_fd)<0){
		printf("bind() error\n");
        close(sock_fd);
		exit(EXIT_FAILURE);
	}

    a[0]=5;
    a[1]=nnum;
    memcpy(a+2,&net_ip,sizeof(unsigned));
	memcpy(a+6,&net_mask,sizeof(unsigned));
	memcpy(a+10,&firewall_ip,sizeof(unsigned));
	memcpy(a+14,&natTable[1],(nnum-1)*sizeof(NatEntry));
	netlink_send_message(sock_fd,(const unsigned char *)a,(nnum-1)*sizeof(NatEntry)+14);
	close(sock_fd);

    return 1;
}

bool AddNatRule(unsigned nat_ip,unsigned short nat_port, unsigned fw_port){
	GetNatRules();
	if(nnum==0) nnum=1;
	if(nnum<MAX_NAT_NUM){
		natTable[nnum].nat_ip = nat_ip;
		natTable[nnum].nat_port = nat_port;
		natTable[nnum].fw_port = fw_port;
		nnum++;
		SendNatRules();
		return true;
	}
	return false;
}

bool DelNatRule(int pos){
	if(pos>=nnum || pos<1){
		return false;
	}
	memcpy(natTable+pos,natTable+pos+1,sizeof(NatEntry)*(nnum-pos));
	nnum--;
	SendNatRules();
	return true;
}

// update and print
void PrintNatRules(){
	GetNatRules();
	printf("|----------------------------------------------------------------------|\n");
	printf("|  nat_ip    |    firewall_port    |    nat_port    |\n");
	printf("|----------------------------------------------------------------------|\n");
	for(int i = 0; i < nnum; i++){
		char buff[20], buff2[20];
		printf("|%15s|%15d|%15d|\n",addr_from_net(buff2, natTable[i].nat_ip), natTable[i].fw_port, natTable[i].nat_port);
		printf("|----------------------------------------------------------------------|\n");
	}
	return;
}

#endif _KT_APP_H