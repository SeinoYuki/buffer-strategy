#!/usr/bin/env python3
# coding: utf-8
"""
複数の relfilenode 情報を持つクエリのブロック IO 集計サンプル

・exec_simple_query のエントリでクエリ文字列を記録
・ブロック IO 操作（例: ReadBuffer_common）の際に、各 relfilenode 毎にアクセスしたブロック番号の最大／最小を記録
・exec_simple_query のリターン時に、保持していた複数の relfilenode 情報をまとめて出力
"""

from bcc import BPF
from ctypes import Structure, c_uint, c_char, string_at

# 定数（BPF 側と合わせる）
QUERY_LEN = 256
MAX_REL = 16

# ctypes で C の構造体に対応する型を定義
class RelInfo(Structure):
    _fields_ = [
        ("relfilenode", c_uint),
        ("max_block",   c_uint),
        ("min_block",   c_uint),
    ]

class Event(Structure):
    _fields_ = [
        ("pid", c_uint),
        ("query", c_char * QUERY_LEN),
        ("rel_info", RelInfo * MAX_REL),
        ("num_rel", c_uint),
    ]

# BPF プログラム（C 言語）
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define QUERY_LEN 256
#define MAX_REL   16   // 1 クエリにつき最大 16 件の relfilenode 情報を保持

// ブロック IO の情報（リレーション単位）
struct rel_info_t {
    u32 relfilenode;   // RelationData 内の rd_locator.relNumber
    u32 max_block;     // アクセスしたブロック番号の最大値
    u32 min_block;     // アクセスしたブロック番号の最小値
};

// 1 クエリにつき保持する情報（クエリ文字列と複数のリレーション情報）
struct query_info_t {
    char query[QUERY_LEN];
    struct rel_info_t rel_info[MAX_REL];
    u32 num_rel;       // 記録している rel_info の件数
};

// ユーザ空間へ送出するイベント（クエリ終了時）
struct event_t {
    u32 pid;
    char query[QUERY_LEN];
    struct rel_info_t rel_info[MAX_REL];
    u32 num_rel;
};

BPF_HASH(query_map, u32, struct query_info_t);
BPF_PERF_OUTPUT(events);

/*
 * クエリ開始時のプローブ
 * 第一引数にクエリ文字列のポインタが渡されると仮定
 */
int probe_query(struct pt_regs *ctx) {
    struct query_info_t info = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    // exec_simple_query の第一引数からクエリ文字列をコピー
    char *query_ptr = (char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user(&info.query, sizeof(info.query), query_ptr);

    // リレーション情報はまだないので、件数 0 で初期化
    info.num_rel = 0;

    query_map.update(&tgid, &info);
    return 0;
}

/*
 * ブロック IO 操作時のプローブ（例: ReadBuffer_common）
 *
 * 第一引数: RelationData*（その中の rd_locator.relNumber が relfilenode）
 * 第二引数: アクセス対象のブロック番号（BlockNumber と仮定、u32 として扱う）
 */
int probe_block_io(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    // クエリ開始時の情報を取得。なければこのクエリでは追跡していないので return
    struct query_info_t *info = query_map.lookup(&tgid);
    if (!info)
        return 0;

    // RelationData 構造体の必要な部分のみ定義
    struct RelationData {
        struct {
            u32 spcOid;
            u32 dbOid;
            u32 relNumber;
        } rd_locator;
    };

    // 第一引数から RelationData* を取得し、relfilenode を読み出す
    struct RelationData *reln = (struct RelationData *)PT_REGS_PARM1(ctx);
    u32 relfilenode = 0;
    bpf_probe_read(&relfilenode, sizeof(relfilenode), &reln->rd_locator.relNumber);

    // 第二引数からブロック番号を取得
    u32 block_no = (u32)PT_REGS_PARM5(ctx);

    // 既にこの relfilenode の情報が記録されているかチェック
    int found = 0;
    #pragma unroll
    for (int i = 0; i < MAX_REL; i++) {
        if (i >= info->num_rel)
            break;  // まだ記録されていない領域に達したらループ終了

        if (info->rel_info[i].relfilenode == relfilenode) {
            // 既存エントリの場合、ブロック番号の最大／最小を更新
            if (block_no > info->rel_info[i].max_block)
                info->rel_info[i].max_block = block_no;
            if (block_no < info->rel_info[i].min_block)
                info->rel_info[i].min_block = block_no;
            found = 1;
            break;
        }
    }

    // 未記録なら、新規エントリとして追加（最大件数に達していなければ）
    if (!found && (info->num_rel < MAX_REL)) {
        int idx = info->num_rel;
        info->rel_info[idx].relfilenode = relfilenode;
        info->rel_info[idx].max_block = block_no;
        info->rel_info[idx].min_block = block_no;
        info->num_rel++;
    }
    return 0;
}

/*
 * クエリ終了時のプローブ（exec_simple_query のリターン時にアタッチ）
 * 記録済みの複数 relfilenode 情報をイベントとして送出する
 */
int probe_query_end(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    struct query_info_t *info = query_map.lookup(&tgid);
    if (!info)
        return 0;

    struct event_t event = {};
    event.pid = tgid;
    __builtin_memcpy(&event.query, info->query, sizeof(event.query));
    event.num_rel = info->num_rel;

    #pragma unroll
    for (int i = 0; i < MAX_REL; i++) {
        if (i >= info->num_rel)
            break;
        event.rel_info[i] = info->rel_info[i];
    }

    events.perf_submit(ctx, &event, sizeof(event));
    query_map.delete(&tgid);
    return 0;
}
"""

# BPF オブジェクトの生成
b = BPF(text=bpf_text)

# PostgreSQL のバイナリパス（環境に合わせて変更してください）
postgres_path = "/home/seinoyu/pgsql/master/bin/postgres"

# 各プローブのアタッチ
b.attach_uprobe(name=postgres_path, sym="exec_simple_query", fn_name="probe_query")
b.attach_uretprobe(name=postgres_path, sym="exec_simple_query", fn_name="probe_query_end")
b.attach_uprobe(name=postgres_path, sym="ReadBuffer_common", fn_name="probe_block_io")

print("Tracing queries... Ctrl-C で終了します。")

# イベント受信用のコールバック関数
def print_event(cpu, data, size):
    # data は raw ポインタなので、string_at() で bytes 化してから ctypes で変換する
    event = Event.from_buffer_copy(string_at(data, size))
    query = event.query.split(b'\0', 1)[0].decode('utf-8', errors='replace')
    print("PID: %-6d, Query: %s" % (event.pid, query))
    for i in range(event.num_rel):
        rel = event.rel_info[i]
        print("    relfilenode: %-6d, max_block: %-6d, min_block: %-6d" %
              (rel.relfilenode, rel.max_block, rel.min_block))
    print("")

# イベントバッファのオープン（ct パラメータは使わずに呼び出す）
b["events"].open_perf_buffer(print_event)

# イベントループ
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
