#!/usr/bin/env python3
#
# PostgreSQLのブロックアクセス（タイムスタンプ、リレーション番号、ブロック番号）を
# eBPFでキャプチャするサンプルコード (BCC/Python)
#
# 前提：
#   - PostgreSQLのReadBufferExtended()関数は以下のシグネチャを持つ
#       Buffer ReadBufferExtended(RelationData *reln, ForkNumber forkNum,
#                                 BlockNumber blockNum, int mode, BufferAccessStrategy strategy);
#   - RelationData構造体は、内部に以下の構造体を持つと仮定する
#
#       struct RelFileLocator {
#           unsigned int spcOid;     // tablespace
#           unsigned int dbOid;      // database
#           unsigned int relNumber;  // relation (リレーション番号)
#       };
#
#       struct RelationData {
#           struct RelFileLocator rd_locator;
#       };
#
# 使用例:
#   1. BINARY_PATH を実行中のPostgreSQLバイナリのパスに合わせる
#   2. root 権限で実行する
#
from bcc import BPF
from bcc.utils import printb
import sys

# PostgreSQLバイナリのパスを適宜修正してください
BINARY_PATH = "/home/seinoyu/pgsql/master/bin/postgres"

# eBPFプログラム (Cコード)
bpf_text = r"""
#include <uapi/linux/ptrace.h>

// bpftraceで定義している構造体と同等の定義
struct RelFileLocator {
    unsigned int spcOid;      // tablespace
    unsigned int dbOid;       // database
    unsigned int relNumber;   // relation (リレーション番号)
};

struct RelationData {
    struct RelFileLocator rd_locator;
};

struct event_t {
    u64 ts;          // タイムスタンプ (ns)
    u32 pid;         // プロセスID
    u32 relfilenode; // RelationData内の rd_locator.relNumber
    u32 blocknum;    // ブロック番号
};

BPF_PERF_OUTPUT(events);

/*
 * ReadBufferExtended()の呼び出し時の引数:
 *   arg0: RelationData * (キャストして構造体から rd_locator.relNumber を取得)
 *   arg2: BlockNumber (ブロック番号)
 */
int probe_readbufferextended(struct pt_regs *ctx)
{
    struct event_t event = {};
    // 第一引数をRelationData*として取得
    struct RelationData *reln = (struct RelationData *)PT_REGS_PARM1(ctx);
    // 第三引数をブロック番号として取得
    u32 blocknum = (u32)PT_REGS_PARM3(ctx);

    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.blocknum = blocknum;

    // RelationData構造体の内部フィールド rd_locator.relNumber を読み出す
    bpf_probe_read(&event.relfilenode, sizeof(event.relfilenode), &reln->rd_locator.relNumber);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# BPFオブジェクトを生成してeBPFプログラムをロード
b = BPF(text=bpf_text)

# PostgreSQLバイナリの ReadBufferExtended シンボルにuprobeをアタッチ
b.attach_uprobe(name=BINARY_PATH, sym="ReadBufferExtended", fn_name="probe_readbufferextended")

# イベント受信用のコールバック関数
def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.relfilenode > 16000:
        print("%d,%d,%d" %
            (event.ts, event.relfilenode, event.blocknum))

# perf buffer をオープンしてイベント待受
b["events"].open_perf_buffer(print_event, page_cnt=65536)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
