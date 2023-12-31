#include "./kt_app.h"

// #define NETLINK_TEST	17
// #define MSG_LEN	256

// char *default_data = "Netlink Test Default Data";

// struct msg_to_kernel {
// 	struct nlmsghdr hdr;
// 	char data[MSG_LEN];
// };

// struct u_packet_info {
// 	struct nlmsghdr hdr;
// 	char msg[MSG_LEN];
// };

void menu(){
	printf("\n******************************* MENU *******************************\n");
	printf("*                         1. add rule                              *\n");
	printf("*                         2. del rule                              *\n");
	printf("*                         3. show rule-list                        *\n");
	printf("*                         4. show conn-list                        *\n");
	printf("*                         5. show log-list                         *\n");
	printf("*                         6. change default rule                   *\n");
	// printf("*                         7. add nat rule                          *\n");
	printf("*                         7. del nat rule                          *\n");
	printf("*                         8. show nat-rule-list                    *\n");
	printf("*                         9. quit                                  *\n");
	printf("********************************************************************\n");
	printf("input your choice:");
}

void test(){
	int choice = 1;

	char sip[20];
	char dip[20];
	int sport, dport;
	int pro_ch,act_ch,log_ch;
	unsigned char protocol;
	bool action,llog;
	int pos;

	printf("test???\n");

	while(choice!=0){
		menu();
		scanf("%d",&choice);
		switch(choice){
			case 1:
				printf("src_ip: ");
				scanf("%s",sip);
				printf("dest_ip: ");
				scanf("%s",dip);
				printf("src_port(-1:ANY): ");
				scanf("%d",&sport);
				printf("dest_port(-1:ANY): ");
				scanf("%d",&dport);
				printf("protocol(0.ANY; 1.TCP; 2.UDP; 3.ICMP): ");
				scanf("%d",&pro_ch);
				printf("action(0.deny; 1.accept): ");
				scanf("%d",&act_ch);
				printf("log(0.no; 1.yes): ");
				scanf("%d",&log_ch);
				switch(pro_ch){
					case 1:
						protocol = TCP;
						break;
					case 2:
						protocol = UDP;
						break;
					case 3:
						protocol = ICMP;
						break;
					default:
						protocol = ANY;
						break;
				}
				if(act_ch) action = true;
				else action = false;
				if(log_ch) llog = true;
				else llog = false;
				printf("add rule!\n");
				AddRule(sip,dip,sport,dport,protocol,action,llog);
				break;
			case 2:
				PrintRules();
				printf("Select the rule that you want to delete: ");
				scanf("%d",&pos);
				DelRule(pos);
				break;
			case 3:
				PrintRules();
				break;
			case 4:
				GetConnections();
				break;
			case 5:
				GetLogs();
				break;
			case 6:
				printf("default rule(0.deny; 1.accept): ");
				scanf("%d",&act_ch);
				if(act_ch){
					ChangeDefaultRule(true);
				}
				else{
					ChangeDefaultRule(false);
				}
				break;
			// case 7:
			// 	printf("nothing now!\n");
			// 	break;
			case 7:
				PrintNatRules();
				printf("Select the rule that you want to delete: ");
				scanf("%d",&pos);
				DelNatRule(pos);
				break;
			case 8:
				PrintNatRules();
				break;
			case 9:
				return 0;
				break;
			default:
				printf("reinput!\n");
				break;
		}
	}
}

int main(int argc, char *argv[])
{
	// test hook rules
	AddRule("192.168.152.2","192.168.164.2",-1,-1,ANY,true,true);
	AddRule("192.168.164.2","192.168.152.2",-1,-1,ANY,true,true);
	AddRule("192.168.164.2","192.168.164.1",-1,-1,ANY,true,true);
	AddRule("192.168.164.1","192.168.164.2",-1,-1,ANY,true,true);
	AddRule("192.168.152.2","192.168.152.1",-1,-1,ANY,true,true);
	AddRule("192.168.152.1","192.168.152.2",-1,-1,ANY,true,true);
	AddRule("192.168.164.1","192.168.152.2",-1,-1,ANY,true,true);
	AddRule("192.168.152.2","192.168.164.1",-1,-1,ANY,true,true);
	AddRule("192.168.152.1","192.168.164.2",-1,-1,ANY,true,true);
	AddRule("192.168.164.2","192.168.152.1",-1,-1,ANY,true,true);
	ChangeDefaultRule(false);

	SetNat(ipstr_to_num("192.168.164.0"),0xffffff00,ipstr_to_num("192.168.152.1"));
	
	char firewall_ip[20] = "192.168.152.1";
	char nat_ip[20] = "192.168.164.2";
	unsigned short fw_port = 8888;
	unsigned short nat_port = 80;

	AddNatRule(ipstr_to_num(nat_ip),nat_port,fw_port);

	test();

	return 0;
}
