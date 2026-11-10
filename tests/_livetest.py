"""联调测试的公共配置：从环境变量取目标机，不写死任何地址。

公开仓库里不该出现某个人的内网 IP。需要跑真实联调测试时显式给变量：

    set INTLINK_TEST_SSH_HOST=192.168.1.10
    set INTLINK_TEST_SSH_USER=root
    set INTLINK_TEST_LOW_USER=nobody   （非 root 降级测试用）

没给变量时，需要目标机的测试会打印 SKIP 并返回 0，而不是失败 ——
这样在别人的机器上 `run_all.py` 也能全绿。
"""
from __future__ import annotations

import os
import sys


def target_host() -> str:
    return os.environ.get("INTLINK_TEST_SSH_HOST", "").strip()


def target_user() -> str:
    return os.environ.get("INTLINK_TEST_SSH_USER", "root").strip() or "root"


def low_priv_user() -> str:
    return os.environ.get("INTLINK_TEST_LOW_USER", "").strip()


def target_port() -> int:
    raw = os.environ.get("INTLINK_TEST_SSH_PORT", "22").strip()
    try:
        return int(raw)
    except ValueError:
        return 22


def skip(reason: str) -> int:
    """需要目标机但没配时，明确跳过不算失败。"""
    print("  SKIP %s" % reason)
    print("  设置 INTLINK_TEST_SSH_HOST / INTLINK_TEST_SSH_USER 后可运行")
    return 0


def require_host() -> str:
    h = target_host()
    if not h:
        return ""
    return h
