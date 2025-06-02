#!/usr/bin/env python3

from bcc import BPF
import ctypes
import time
import docker
import socket
import struct

# Подключение к Docker API
docker_client = docker.from_env()

# Определение структуры данных для передачи из ядра
class ContainerInfo(ctypes.Structure):
    _fields_ = [
        ("sender_ip", ctypes.c_char * 16),
        ("sender_name", ctypes.c_char * 64),
        ("receiver_ip", ctypes.c_char * 16),
        ("receiver_name", ctypes.c_char * 64),
        ("message", ctypes.c_char * 256),
    ]

# Функция для получения имени контейнера по IP
def get_container_name(ip):
    try:
        containers = docker_client.containers.list()
        for container in containers:
            container.reload()  # Обновляем информацию о контейнере
            settings = container.attrs['NetworkSettings']
            if 'IPAddress' in settings and settings['IPAddress'] == ip:
                return container.name
    except Exception as e:
        print(f"Error getting container name: {e}")
    return "unknown"

# Загрузка eBPF программы
bpf = BPF(src_file="ebpf_monitor.c")

# Функция обработки событий
def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(ContainerInfo)).contents
    
    # Получаем имена контейнеров (если они не были установлены в eBPF)
    sender_name = event.sender_name.decode() if event.sender_name else get_container_name(event.sender_ip.decode())
    receiver_name = event.receiver_name.decode() if event.receiver_name else get_container_name(event.receiver_ip.decode())
    
    print("\n=== Inter-container Communication ===")
    print(f"Sender: {event.sender_ip.decode()} ({sender_name})")
    print(f"Receiver: {event.receiver_ip.decode()} ({receiver_name})")
    print(f"Message: {event.message.decode()}")
    print("="*40)

# Настройка обработчика событий
bpf["events"].open_perf_buffer(print_event)

print("Monitoring inter-container communication... Press Ctrl+C to exit.")

# Основной цикл
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Exiting...")
        exit()
