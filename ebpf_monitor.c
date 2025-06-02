#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

struct data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
    char message[256];
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    // Фильтрация только нужных портов
    u16 dport = sk->__sk_common.skc_dport;
    if (dport != htons(1234) && dport != htons(1235)) {
        return 0;
    }

    // Сбор информации о соединении
    struct data_t data = {};
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.daddr = sk->__sk_common.skc_daddr;
    data.sport = sk->__sk_common.skc_num;
    data.dport = htons(dport);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Чтение сообщения (первые 256 байт)
    if (msg && msg->msg_iter.iov) {
        struct iovec *iov = (struct iovec *)msg->msg_iter.iov;
        if (iov->iov_base) {
            bpf_probe_read_kernel(&data.message, sizeof(data.message), iov->iov_base);
        }
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
