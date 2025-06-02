#!/usr/bin/env python3

from bcc import BPF
import ctypes
import socket
import struct

# Определение структуры данных для передачи из eBPF
class Data(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("comm", ctypes.c_char * 16),
        ("message", ctypes.c_char * 256),
    ]

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("!I", ip))

def get_container_name(pid):
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            for line in f:
                if "docker" in line or "kubepods" in line:
                    parts = line.strip().split("/")
                    if len(parts) > 3:
                        return parts[-1]
    except:
        pass
    return "unknown"

def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    
    src_ip = ip_to_str(event.saddr)
    dst_ip = ip_to_str(event.daddr)
    src_port = event.sport
    dst_port = event.dport
    
    # Получаем PID отправителя
    pid = BPF.get_kprobe_functions(b'tcp_sendmsg')[0].perf_event_pid()
    
    # Получаем имена контейнеров
    src_container = event.comm.decode()
    dst_container = get_container_name(pid)
    
    message = event.message.decode(errors='ignore').strip()
    
    print(f"Source IP: {src_ip}:{src_port}")
    print(f"Destination IP: {dst_ip}:{dst_port}")
    print(f"Source Container: {src_container}")
    print(f"Destination Container: {dst_container}")
    print(f"Message: {message}")
    print("-" * 50)

if __name__ == "__main__":
    bpf = BPF(src_file="ebpf_monitor.c")
    bpf["events"].open_perf_buffer(print_event)
    
    print("Monitoring container communications...")
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
