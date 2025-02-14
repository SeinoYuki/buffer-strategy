#!/usr/bin/env python3
# coding: utf-8
"""
PostgreSQL のクエリ文字列を抽出するサンプルコード

本サンプルでは、PostgreSQL の関数 exec_simple_query のエントリに uprobe をアタッチし、
その第一引数からクエリ文字列を取得して出力します。
"""

from bcc import BPF

# BPF プログラム（C 言語）
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define QUERY_LEN 256

struct RelFileLocator {
    unsigned int spcOid;
    unsigned int dbOid;
    unsigned int relNumber;
};

struct RelationData {
    struct RelFileLocator rd_locator;
};

// クエリ情報を格納する構造体
struct rel_info_t {
    unsigned int relfilenode;
    unsigned int max_block;
    unsigned int min_block;
};

// クエリ情報を格納する構造体
struct query_info_t {
    char query[QUERY_LEN];
    struct rel_info_t rel_info;
};

// イベント出力用構造体
struct event_t {
    u32 pid;
    u32 relfilenode; // RelationData 内の rd_locator.relNumber
    char query[QUERY_LEN];
};

// イベント送信用マップ
BPF_HASH(query_map, u32, struct query_info_t);
BPF_PERF_OUTPUT(events);

/*
 * exec_simple_query のエントリにアタッチするプローブ関数
 * ※ 第一引数にクエリ文字列へのポインタが渡されると仮定
 */
int probe_query(struct pt_regs *ctx) {
    struct event_t event = {};
    struct query_info_t info = {};
    
    // プロセスIDを取得
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    // 第一引数からクエリ文字列のポインタを取得
    char *query_ptr = (char *)PT_REGS_PARM1(ctx);
    // ユーザ空間からクエリ文字列をコピー（最大 QUERY_LEN バイト）
    bpf_probe_read_user(&info.query, sizeof(info.query), query_ptr);
   
    query_map.update(&tgid, &info);
    return 0;
}

/*
 * クエリ終了時のプローブ（例: exec_simple_query のリターン時）
 */
int probe_query_end(struct pt_regs *ctx) {
    bpf_trace_printk("debug code 5\n");
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    query_map.delete(&tgid);
    return 0;
}

/*
 * ブロック IO 操作時のプローブ（例: read_page）
 */
int probe_block_io(struct pt_regs *ctx) {
    struct event_t event = {};
    
    
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    
    
    struct RelationData *reln = (struct RelationData *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&event.relfilenode, sizeof(event.relfilenode), &reln->rd_locator.relNumber);
    
    struct query_info_t *info = query_map.lookup(&tgid);


    if (event.relfilenode > 16000) {
        bpf_trace_printk("pid: %d, relid: %d\n", tgid, event.relfilenode);
    }
    bpf_trace_printk("pid: %d, relid: %d\n", tgid, event.relfilenode);
    
    if (!info)
    {
        return 0;  // クエリ開始時の情報がなければ何もしない        
    }
    bpf_trace_printk("Query Start: %s\n", info->query);
    
    return 0;
}
"""

# BPF オブジェクトの生成
b = BPF(text=bpf_text)

# PostgreSQL のバイナリパス（環境に合わせて変更してください）
postgres_path = "/home/seinoyu/pgsql/master/bin/postgres"

# exec_simple_query のエントリに uprobe をアタッチしてクエリを抽出
b.attach_uprobe(name=postgres_path, sym="exec_simple_query", fn_name="probe_query")

# クエリ終了のプローブ（exec_simple_query のリターンにアタッチ）
b.attach_uretprobe(name=postgres_path, sym="exec_simple_query", fn_name="probe_query_end")

# ブロック IO 操作時のプローブ（例: read_page にアタッチ）
b.attach_uprobe(name=postgres_path, sym="ReadBuffer_common", fn_name="probe_block_io")

print("Tracing queries... Ctrl-C で終了します。")

# イベント受信用コールバック
def print_event(cpu, data, size):
    event = b["events"].event(data)
    # 固定長の文字列バッファなので、NULL 終端で切る
    query = event.query.split(b'\0', 1)[0].decode('utf-8', errors='replace')
    print("PID: %-6d Query: %s" % (event.pid, query))

# イベントバッファのオープン
b["events"].open_perf_buffer(print_event)

# イベントループ
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
