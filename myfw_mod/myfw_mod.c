#include "./hook_func.h"
#include "./netlink_func.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zxy");


static struct nf_hook_ops input_filter = {
	.hook = (nf_hookfn *)hook_func,
	//.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops output_filter = {
	.hook = (nf_hookfn *)hook_func,
	//.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops input_nat_filter = {
	.hook = (nf_hookfn *)hook_func_nat_in,
	//.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_NAT_DST
};
static struct nf_hook_ops output_nat_filter = {
	.hook = (nf_hookfn *)hook_func_nat_out,
	//.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_NAT_SRC
};


struct netlink_kernel_cfg nkc = {
	.groups = 0,
	.flags = 0,
	.input = netlink_recv,
	.cb_mutex = NULL,
	.bind = NULL,
	.compare = NULL
};



static int myfw_init(void)
{
	int res;
	printk("my firewall module loaded.\n");

	net_ip = ipstr_to_num("192.168.164.0");
	net_mask = 0xffffff00;
	firewall_ip = ipstr_to_num("192.168.152.1");

	nf_register_hook(&input_filter);
	nf_register_hook(&output_filter);
	nf_register_hook(&input_nat_filter);
	nf_register_hook(&output_nat_filter);

	// if(( res = alloc_chrdev_region(&devId, 0, 1, "stone-alloc-dev") ) != 0) {
	// 	printk(KERN_WARNING "register dev id error:%d\n", res);
    //     	netlink_clear();
	// 	return -1;
	// }
	// else printk(KERN_WARNING "register dev id success!\n");

	// // 动态创建设备节点
	// // 建立逻辑设备 在/sys/class/下新建了“stone-class”目录
	// cls = class_create(THIS_MODULE, "stone-class");
	// if(IS_ERR(cls)) {
	// 	printk(KERN_WARNING "create class error!\n");
    //     netlink_clear();
	// 	return -1;
	// }
	// // 在/dev下自动建立了"stone-class"的设备节点
	// if(device_create(cls, NULL, devId, "", "hello%d", 0) == NULL) {
	// 	printk(KERN_WARNING "create device error!\n");
    //     netlink_clear();
	// 	return -1;
	// }
	
	printk("Netlink test module initializing...\n");
	nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &nkc);
	if( !nl_sk ) {
		printk(KERN_ERR "[netlink] can not create a netlink socket!\n");
        netlink_clear();
		return -1;
	}
	printk("netlink_kernel_create() success, nlsk = %p\n", nl_sk);
	
	return 0;
}

static void myfw_exit(void)
{
	printk("my firewall module exit ...\n");
	nf_unregister_hook(&input_filter);
	nf_unregister_hook(&output_filter);
	nf_unregister_hook(&input_nat_filter);
	nf_unregister_hook(&output_nat_filter);
	netlink_clear();
}

module_init(myfw_init);
module_exit(myfw_exit);
