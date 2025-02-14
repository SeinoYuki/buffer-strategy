#!/usr/bin/env python3
#
# PostgreSQLのブロックアクセス（タイムスタンプ、リレーション番号、ブロック番号）を
# eBPFでキャプチャしてCSVファイルに出力し、一定サイズに達したら圧縮するサンプルコード (BCC/Python)
#
# 前提：
#   - PostgreSQLのReadBufferExtended()関数は以下のシグネチャを持つ
#       Buffer ReadBufferExtended(RelationData *reln, ForkNumber forkNum,
#                                 BlockNumber blockNum, int mode, BufferAccessStrategy strategy);
#   - RelationData構造体は内部に、rd_locator.relNumber を持つと仮定する
#
# 使用例:
#   1. BINARY_PATH を実行中のPostgreSQLバイナリのパスに合わせる
#   2. root 権限で実行する
#
from bcc import BPF
import csv
import os
import gzip
import time

# PostgreSQLバイナリのパスを適宜修正してください
BINARY_PATH = "/home/seinoyu/pgsql/master/bin/postgres"

# CSV 出力設定
CSV_FILENAME = "../data/bpf_blockread.csv"
FILE_SIZE_THRESHOLD = 1024 * 1024 * 1024  # 例: 1GB を閾値とする

# CSVファイルが存在しない場合は作成
if not os.path.exists(CSV_FILENAME):
    with open(CSV_FILENAME, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "relfilenode", "blocknum"])

# CSVファイルハンドルと writer のグローバル変数
csv_file = open(CSV_FILENAME, "a", newline="")
csv_writer = csv.writer(csv_file)

def rotate_csv_file():
    """
    CSVファイルのサイズが閾値を超えた場合、
    現在の CSV ファイルを gzip で圧縮し、新しい CSV ファイルを作成する。
    """
    global csv_file, csv_writer

    csv_file.close()
    # 圧縮後のファイル名にタイムスタンプを付与（例: events.csv.1678901234.gz）
    timestamp = int(time.time())
    compressed_filename = f"{CSV_FILENAME}.{timestamp}.gz"
    with open(CSV_FILENAME, "rb") as f_in, gzip.open(compressed_filename, "wb") as f_out:
        f_out.writelines(f_in)
    # 元のCSVファイルは削除
    os.remove(CSV_FILENAME)
    # 新たなCSVファイルを作成し、ヘッダーを書き込む
    csv_file = open(CSV_FILENAME, "a", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["timestamp", "relfilenode", "blocknum"])
    print(f"CSVファイルが圧縮されました: {compressed_filename}")

def write_event_to_csv(ts, relfilenode, blocknum):
    """
    取得したイベントをCSVファイルに1行追加し、
    ファイルサイズが閾値を超えていればファイルを圧縮する。
    """
    global csv_file, csv_writer

    csv_writer.writerow([ts, relfilenode, blocknum])
    csv_file.flush()  # ディスクへの書き出しを強制

    # ファイルサイズをチェックし、閾値超えならファイルをローテート
    if os.path.getsize(CSV_FILENAME) >= FILE_SIZE_THRESHOLD:
        rotate_csv_file()

# eBPF プログラム (Cコード)
bpf_text = r"""
#include <uapi/linux/ptrace.h>

struct RelFileLocator {
    unsigned int spcOid;
    unsigned int dbOid;
    unsigned int relNumber;
};

struct RelationData {
    struct RelFileLocator rd_locator;
};

struct event_t {
    u64 ts;          // タイムスタンプ (ns)
    u32 pid;         // プロセスID
    u32 relfilenode; // RelationData 内の rd_locator.relNumber
    u32 blocknum;    // ブロック番号
};

BPF_PERF_OUTPUT(events);

/*
 * ReadBufferExtended()の呼び出し時の引数:
 *   arg0: RelationData* (キャストして構造体から rd_locator.relNumber を取得)
 *   arg2: BlockNumber (ブロック番号)
 */
int probe_readbufferextended(struct pt_regs *ctx)
{
    struct event_t event = {};
    struct RelationData *reln = (struct RelationData *)PT_REGS_PARM1(ctx);
    u32 blocknum = (u32)PT_REGS_PARM3(ctx);

    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.blocknum = blocknum;

    bpf_probe_read(&event.relfilenode, sizeof(event.relfilenode), &reln->rd_locator.relNumber);

    if (event.relfilenode > 16000) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
"""

# BPFオブジェクトを生成して eBPF プログラムをロード
b = BPF(text=bpf_text)

# PostgreSQLバイナリの ReadBufferExtended シンボルに uprobe をアタッチ
b.attach_uprobe(name=BINARY_PATH, sym="ReadBufferExtended", fn_name="probe_readbufferextended")

# イベント受信用のコールバック関数
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    # 例として、relfilenode が 16000 より大きい場合のみ CSV に出力
    write_event_to_csv(event.ts, event.relfilenode, event.blocknum)

# perf buffer をオープンしてイベント待受 (ページ数は必要に応じて調整)
b["events"].open_perf_buffer(handle_event, page_cnt=65536)

print("イベントのキャプチャを開始します。Ctrl-Cで終了します。")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("終了します。")
finally:
    csv_file.close()
