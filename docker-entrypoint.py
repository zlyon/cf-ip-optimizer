#!/usr/bin/env python3
"""容器入口：修正数据目录属主后降权，再执行真正的服务进程。

为什么要这一层：
  docker 在宿主机上自动创建 bind mount 的目录时，属主是 root（默认 0755）。
  镜像里服务是以非 root 用户跑的，于是 SQLite 只会抛一句
  "unable to open database file"，看不出是权限问题——NAS 上尤其常见。

这里做的事：
  1. 以 root 启动（Dockerfile 不再写 USER），把 DATA_DIR 的属主改成 PUID:PGID
  2. 丢弃 root 权限，以 PUID:PGID 身份 exec 真正的命令
  3. 已经以非 root 启动时什么都不做，直接 exec（支持 compose 里写 user: "uid:gid"）
"""
from __future__ import annotations

import os
import sys

DATA_DIR = os.getenv("DATA_DIR", "/data")
PUID = os.getenv("PUID", "1000")
PGID = os.getenv("PGID", "1000")


def _warn(msg: str) -> None:
    print(f"[entrypoint] {msg}", file=sys.stderr, flush=True)


def _chown_tree(path: str, uid: int, gid: int) -> None:
    """把目录整棵树改成 uid:gid，属主已正确的跳过，避免每次启动都刷盘。"""
    for root, dirs, files in os.walk(path):
        for name in [root] + [os.path.join(root, n) for n in dirs + files]:
            try:
                st = os.lstat(name)
                if st.st_uid == uid and st.st_gid == gid:
                    continue
                os.chown(name, uid, gid)
            except OSError as exc:
                _warn(f"无法修改属主 {name}: {exc}")


def main() -> None:
    if len(sys.argv) < 2:
        _warn("没有指定要执行的命令")
        raise SystemExit(2)

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        # 已经是非 root（例如 compose 里指定了 user:），无从改属主，直接跑
        os.execvp(sys.argv[1], sys.argv[1:])

    try:
        uid = int(PUID)
        gid = int(PGID)
    except ValueError:
        _warn(f"PUID/PGID 必须是数字，收到 PUID={PUID!r} PGID={PGID!r}，回退到 1000")
        uid = gid = 1000

    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError as exc:
        _warn(f"无法创建数据目录 {DATA_DIR}: {exc}")

    if os.path.isdir(DATA_DIR):
        _chown_tree(DATA_DIR, uid, gid)
        try:
            probe = os.path.join(DATA_DIR, ".write_test")
            with open(probe, "w", encoding="utf-8") as fh:
                fh.write("ok")
            os.unlink(probe)
        except OSError as exc:
            _warn(
                f"{DATA_DIR} 对 uid={uid} 仍不可写（{exc}）。"
                f"如果宿主机目录是只读挂载或 ACL 限制，请改用可写目录，"
                f"或设置 PUID/PGID 为该目录的属主。"
            )

    # 降权后 HOME 还指向 /root 会写不进去（Python 想写 ~/.cache 时会报错）
    if os.environ.get("HOME", "").rstrip("/") in ("", "/root"):
        os.environ["HOME"] = "/tmp"
    try:
        os.setgroups([])
    except OSError:
        pass
    try:
        os.setgid(gid)
        os.setuid(uid)
    except OSError as exc:
        _warn(f"降权到 {uid}:{gid} 失败：{exc}，继续以当前身份运行")

    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
