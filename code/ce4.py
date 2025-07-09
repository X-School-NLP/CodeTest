import os

print(f"当前 UID（用户ID）: {os.getuid()}")
print(f"当前 GID（用户组ID）: {os.getgid()}")
# try_write_hosts.py
try:
    with open("/etc/hosts", "a") as f:
        f.write("# This is a harmless test line\n")
    print("✅ 写入成功！你可能是 root 用户。")
except PermissionError:
    print("❌ 权限错误：你不是 root 用户，不能写入 /etc/hosts。")
except Exception as e:
    print(f"⚠️ 发生其他错误：{e}")