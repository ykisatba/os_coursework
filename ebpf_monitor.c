#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_MESSAGE_SIZE 256

struct container_info {
    char sender_ip[16];
    char sender_name[64];
    char receiver_ip[16];
    char receiver_name[64];
    char message[MAX_MESSAGE_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    // Проверяем, что это локальное соединение
    if (sk->sk_family != AF_INET || sk->sk_state != TCP_ESTABLISHED)
        return 0;

    // Получаем порты
    unsigned short dest_port = bpf_ntohs(sk->sk_dport);
    unsigned short src_port = sk->sk_num;
    
    // Нас интересуют только порты 1234 и 1235
    if (dest_port != 1234 && dest_port != 1235)
        return 0;

    // Читаем сообщение
    struct container_info info = {};
    bpf_probe_read_kernel_str(&info.message, MAX_MESSAGE_SIZE, msg->msg_iter.iov->iov_base);

    // Получаем IP адреса
    __be32 saddr = sk->sk_rcv_saddr;
    __be32 daddr = sk->sk_daddr;
    
    // Преобразуем IP в строку
    bpf_snprintf(info.sender_ip, sizeof(info.sender_ip), "%pI4", &saddr);
    bpf_snprintf(info.receiver_ip, sizeof(info.receiver_ip), "%pI4", &daddr);

    // Получаем имена контейнеров (это упрощенный пример)
    if (src_port == 1234) {
        bpf_snprintf(info.sender_name, sizeof(info.sender_name), "container1");
    } else if (src_port == 1235) {
        bpf_snprintf(info.sender_name, sizeof(info.sender_name), "container2");
    }

    if (dest_port == 1234) {
        bpf_snprintf(info.receiver_name, sizeof(info.receiver_name), "container1");
    } else if (dest_port == 1235) {
        bpf_snprintf(info.receiver_name, sizeof(info.receiver_name), "container2");
    }

    // Отправляем данные в пользовательское пространство
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    
    return 0;
}

char _license[] SEC("license") = "GPL";
