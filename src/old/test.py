#!/usr/bin/python3
from bcc import BPF
import ctypes as ct
import subprocess
import sys

# 対象となる libc のパス（ディストリによって異なります）
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

# BPFプログラム（Cコード）
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// ユーザスタックトレースを格納するマップ（最大1024エントリ）
BPF_STACK_TRACE(stack_traces, 1024);

struct data_t {
    u32 pid;
    int stack_id;
};

BPF_PERF_OUTPUT(events);

// _exit() 呼び出し時のハンドラ
int trace_exit(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    // ユーザ空間のスタックトレースを取得
    data.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# BPFプログラムのロードと uprobe のアタッチ
b = BPF(text=bpf_text)
b.attach_uprobe(name=LIBC_PATH, sym="_exit", fn_name="trace_exit")

# イベントデータの構造体定義（C側と一致させる）
class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("stack_id", ct.c_int)
    ]

def resolve_with_addr2line(binary, addr):
    """
    addr2line を呼び出して、指定したバイナリ中のアドレスをシンボリケーションする。
    -f オプションで関数名も表示します。
    """
    try:
        output = subprocess.check_output(["addr2line", "-f", "-e", binary, hex(addr)])
        return output.decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return "??"

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("PID {} _exit() called, user stack id: {}".format(event.pid, event.stack_id))
    if event.stack_id >= 0:
        for addr in b["stack_traces"].walk(event.stack_id):
            # シンボル解決を試みる
            try:
                sym = b.sym(addr, event.pid)
            except Exception as e:
                sym = None
            # sym が bytes 型の場合はデコードする
            if sym is not None:
                try:
                    sym = sym.decode("utf-8")
                except Exception:
                    sym = str(sym)
            # シンボリケーションに失敗している場合は addr2line を利用
            if sym is None or "??" in sym:
                sym = resolve_with_addr2line(LIBC_PATH, addr)
            print("    0x{:x} : {}".format(addr, sym))
    else:
        print("    No valid user stack trace available.")
    print("----")

# perf イベントの出力をオープン
b["events"].open_perf_buffer(print_event)

print("Tracing _exit events... Ctrl-C to exit.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        sys.exit(0)
