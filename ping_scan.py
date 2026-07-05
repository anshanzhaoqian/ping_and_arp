#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Ping 扫描脚本：从 192.168.1.1 到 192.168.1.255
并行 ping 所有 IP，最后执行 arp -a
"""

import subprocess
import sys
import os
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置
NETWORK_PREFIX = "192.168.1"
START_IP = 1
END_IP = 255
MAX_WORKERS = 50  # 并行线程数，不宜过大以免触发系统限制


def ping_ip(ip: str, timeout_ms: int = 1000) -> tuple[str, bool]:
    """
    Windows: ping -n 1 -w <timeout_ms> <ip>
    Linux/macOS: ping -c 1 -W <timeout_sec> <ip>
    返回 (ip, 是否可达)
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_ms / 1000 * 2,  # 给子进程超时一些余量
        )
        return (ip, result.returncode == 0)
    except subprocess.TimeoutExpired:
        return (ip, False)
    except Exception:
        return (ip, False)


def main():
    print(f"开始扫描 {NETWORK_PREFIX}.{START_IP} ~ {NETWORK_PREFIX}.{END_IP} ...")
    print(f"并发线程数: {MAX_WORKERS}")
    print("=" * 50)

    ip_list = [f"{NETWORK_PREFIX}.{i}" for i in range(START_IP, END_IP + 1)]
    reachable = []
    unreachable = []
    total = len(ip_list)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(ping_ip, ip): ip for ip in ip_list}

        done_count = 0
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ip_addr, is_alive = future.result()
            except Exception:
                is_alive = False
                ip_addr = ip

            done_count += 1
            if is_alive:
                reachable.append(ip_addr)
                # 实时打印可达 IP
                print(f"[{done_count:>3}/{total}] ✓ {ip_addr} 可达")
            else:
                unreachable.append(ip_addr)

            # 每 20 个打印一次进度（避免刷屏）
            if done_count % 20 == 0:
                print(
                    f"[{done_count:>3}/{total}] 进度: {done_count}/{total} "
                    f"(已发现 {len(reachable)} 个可达)"
                )

    print("=" * 50)
    print(f"扫描完成！")
    print(f"  可达 IP 数量: {len(reachable)}")
    print(f"  不可达 IP 数量: {len(unreachable)}")
    print()

    # 打印可达 IP 列表
    if reachable:
        print("可达 IP 列表：")
        for r in reachable:
            print(f"  ✓ {r}")
    else:
        print("没有发现可达 IP。")
    print()

    # 执行 arp -a
    print("=" * 50)
    print("执行 arp -a ...")
    print("=" * 50)
    system = platform.system().lower()
    try:
        if system == "windows":
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                encoding="gbk",
                errors="replace",
            )
        else:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
            )
        print(result.stdout)
        if result.stderr:
            print("[stderr]", result.stderr)
    except Exception as e:
        print(f"执行 arp -a 失败: {e}")


if __name__ == "__main__":
    main()