#include <net/ip.h>
#include <uapi/linux/rtnetlink.h>
#include <linux/kprobes.h>

// Structure to hold data during probe
struct ip_route_kretprobe_data {
    struct sk_buff *skb;
    struct fib_result *res;
};

// Get VRF device
struct net_device *get_vrf_dev(struct net_device *dev)
{
    if (netif_is_l3_master(dev))
        return dev;
    if (netif_is_l3_slave(dev))
        return netdev_master_upper_dev_get_rcu(dev);
    return NULL;
}

// kretprobe pre-handler
static int ip_route_input_slow_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ip_route_kretprobe_data *data;
    struct sk_buff *skb;
    struct fib_result *res;

#if defined(CONFIG_X86_64)
    skb = (struct sk_buff *)regs->di;
    res = (struct fib_result *)regs->r9;
#elif defined(CONFIG_ARM64)
    skb = (struct sk_buff *)regs->regs[0];
    res = (struct fib_result *)regs->regs[5];
#else
#error Unsupported architecture
#endif

    data = (struct ip_route_kretprobe_data *)ri->data;
    data->skb = skb;
    data->res = res;
    return 0;
}

// kretprobe post-handler
static int ip_route_input_slow_post(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ip_route_kretprobe_data *data = (struct ip_route_kretprobe_data *)ri->data;
    struct sk_buff *skb = data->skb;
    struct fib_result *res = data->res;
    struct net_device *in_dev, *out_dev, *in_vrf_dev, *out_vrf_dev;

    if (res->type == RTN_UNICAST || res->type == RTN_LOCAL) {
        struct fib_nh_common *nhc = FIB_RES_NHC(*res);
        if (!nhc) {
            pr_info("post ip_route_input_slow - res.nhc is NULL\n");
            return 0;
        }

        in_dev = skb->dev;
        out_dev = nhc->nhc_dev; // Use nhc_dev from nh_common

        if (!out_dev) {
            pr_info("post ip_route_input_slow - out_dev is NULL\n");
            return 0;
        }

        rcu_read_lock();
        in_vrf_dev = get_vrf_dev(in_dev);
        out_vrf_dev = get_vrf_dev(out_dev);
        rcu_read_unlock();

        if ((in_vrf_dev || out_vrf_dev) && in_vrf_dev != out_vrf_dev) {
            pr_debug("in_vrf_dev != out_vrf_dev - Clearing IPSKB_L3SLAVE flag!\n");
            IPCB(skb)->flags &= ~IPSKB_L3SLAVE;
        } else {
            pr_debug("in_vrf_dev == out_vrf_dev or one is NULL - NOT DOING ANYTHING!\n");
        }
    }

    return 0;
}

// Define kretprobe
static struct kretprobe ip_route_input_slow_kretprobe = {
    .kp.symbol_name = "ip_route_input_slow",
    .handler = ip_route_input_slow_post,
    .entry_handler = ip_route_input_slow_pre,
    .data_size = sizeof(struct ip_route_kretprobe_data),
    .maxactive = 20,
};

// Module init
static int __init vrf_local_route_sync_init(void)
{
    int ret = register_kretprobe(&ip_route_input_slow_kretprobe);
    if (ret < 0) {
        pr_err("register_kretprobe failed, returned %d\n", ret);
        return ret;
    }
    return 0;
}

// Module exit
static void __exit vrf_local_route_sync_exit(void)
{
    unregister_kretprobe(&ip_route_input_slow_kretprobe);
    pr_info("kretprobe unregistered\n");
}

module_init(vrf_local_route_sync_init)
module_exit(vrf_local_route_sync_exit)

// Module metadata
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oskar Stenman");
MODULE_DESCRIPTION("VRF packet-untagging module when packets exit VRF");
MODULE_VERSION("0.1");
