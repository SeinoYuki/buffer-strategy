import glob
import os
import re
import pandas as pd
from datetime import datetime
import gc

def load_csv_with_time_labels(pattern):
    """
    指定されたパターンにマッチするCSVファイル群を読み込み、
    ファイル名から開始時刻と終了時刻を抽出し、それぞれ 'start_time', 'end_time' 列として追加する。
    """
    files = glob.glob(pattern)
    dfs = []
    # 正規表現: _YYYYMMDD_HHMMSS_YYYYMMDD_HHMMSS という部分を抽出
    time_regex = re.compile(r'(\d{8}_\d{6})_(\d{8}_\d{6})')
    for f in files:
        basename = os.path.basename(f)
        m = time_regex.search(basename)
        if m:
            start_str, end_str = m.groups()
            try:
                start_time = datetime.strptime(start_str, "%Y%m%d_%H%M%S")
                end_time = datetime.strptime(end_str, "%Y%m%d_%H%M%S")
            except Exception as e:
                print(f"Error parsing times from {basename}: {e}")
                start_time, end_time = None, None
        else:
            start_time, end_time = None, None
        
        # CSVファイルの読み込み
        try:
            df = pd.read_csv(f)
        except Exception as e:
            print(f"Error reading {f}: {e}")
            continue
        
        # 抽出した時刻情報を新たな列として追加
        df['start_time'] = start_time
        df['end_time'] = end_time
        dfs.append(df)
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    else:
        return pd.DataFrame()

def load_all_data(data_dir):
    """
    各種CSVファイルを読み込み、DataFrameとして返す。
    """
    # 各パターン（ファイル名に期間ラベルがついているファイル）
    statements_pattern = os.path.join(data_dir, "pg_stat_statements_*.csv")
    tables_pattern     = os.path.join(data_dir, "pg_statio_user_tables_*.csv")
    pg_class_pattern     = os.path.join(data_dir, "pg_class_*.csv")
    
    # 単一ファイルの場合
    bpf_file = os.path.join(data_dir, "bpf_read_block.csv")
    
    df_statements = load_csv_with_time_labels(statements_pattern)
    df_tables     = load_csv_with_time_labels(tables_pattern)
    df_pg_class     = load_csv_with_time_labels(pg_class_pattern)
    
    if os.path.exists(bpf_file):
        try:
            df_bpf = pd.read_csv(bpf_file, parse_dates=['timestamp'])
        except Exception as e:
            print(f"Error reading {bpf_file}: {e}")
            df_bpf = pd.DataFrame()
    else:
        df_bpf = pd.DataFrame()
    
    return df_statements, df_tables, df_bpf, df_pg_class

if __name__ == '__main__':
    data_dir = "../data"
    df_statements, df_tables, df_bpf, df_pg_class = load_all_data(data_dir)
    
    # 例として、df_bpf と df_pg_class が既に読み込まれている前提です
    # 1. 日時文字列を datetime 型に変換
    df_bpf['timestamp'] = pd.to_datetime(df_bpf['timestamp'])
    df_pg_class['start_time'] = pd.to_datetime(df_pg_class['start_time'])
    df_pg_class['end_time'] = pd.to_datetime(df_pg_class['end_time'])
    df_statements['start_time'] = pd.to_datetime(df_statements['start_time'])
    df_statements['end_time'] = pd.to_datetime(df_statements['end_time'])
    df_tables['start_time'] = pd.to_datetime(df_tables['start_time'])
    df_tables['end_time'] = pd.to_datetime(df_tables['end_time'])

    # 2. df_pg_class から必要なカラムのみ抽出（relfilenode, start_time, end_time, relname）
    df_pg_class_small = df_pg_class[['relfilenode', 'start_time', 'end_time', 'relname']]

    # 3. relfilenode をキーに、df_bpf と df_pg_class_small をマージ（left join）
    df_merged = pd.merge(df_bpf, df_pg_class_small, on='relfilenode', how='left')

    # 4. df_bpf の timestamp が、対応する df_pg_class の start_time ～ end_time の間にある行のみフィルタリング
    df_filtered = df_merged[
        (df_merged['timestamp'] >= df_merged['start_time']) &
        (df_merged['timestamp'] <= df_merged['end_time'])
    ]

    # 5. 集計： queryid, relfilenode, start_time, end_time, relname ごとにグループ化し、
    #    各グループ内の max_block の最大値と min_block の最小値を算出
    df_grouped = df_filtered.groupby(
        ['queryid', 'relfilenode', 'start_time', 'end_time', 'relname']
    ).agg(
        max_block=('max_block', 'max'),
        min_block=('min_block', 'min')
    ).reset_index()

    # 4. カラム名や順序の整形（queryid を query_id に変更）
    df_grouped.rename(columns={'queryid': 'query_id'}, inplace=True)
    df_grouped = df_grouped[['start_time', 'end_time', 'query_id', 'relfilenode', 'max_block', 'min_block']]

    # 1. df_pg_class から、relfilenode と relname のみを抜き出す
    df_pg_class_map = df_pg_class[['relfilenode', 'relname']]

    # 2. merge を使って、df_grouped に relname を付加する
    df_final = pd.merge(df_grouped, df_pg_class_map, on='relfilenode', how='left')

    # 3. 必要に応じてカラムの順番を調整する（例：start_time, end_time, query_id, relname, max_block, min_block）
    df_final = df_final[['start_time', 'end_time', 'query_id', 'relname', 'max_block', 'min_block']]

    # df_final は重複を含む DataFrame とします
    df_unique = df_final.drop_duplicates()

    # インデックスをリセットしたい場合は
    df_unique = df_unique.reset_index(drop=True)

    # --- 2. df_merge を軸に、query_id（もしくは queryid）で pg_stat_statements を結合 ---
    # ※ df_merge の query_id と pg_stat_statements の queryid の型が同じであることを確認してください
    df_join_stat = pd.merge(
        df_unique,
        df_statements,
        left_on=['query_id', 'start_time', 'end_time'],
        right_on=['queryid', 'start_time', 'end_time'],
        how='left',
        suffixes=('', '_stat')
    )

    # --- 3. df_join_stat をさらに、relname をキーに pg_stat_user_tables と結合 ---
    df_join_final = pd.merge(
        df_join_stat,
        df_tables,
        left_on=['relname', 'start_time', 'end_time'],
        right_on=['relname', 'start_time', 'end_time'],
        how='left',
        suffixes=('', '_user')
    )

    # --- 4. 必要なカラムの抽出・並び替え ---
    # たとえば、元の df_merge の情報に加えて、pg_stat_statements や pg_stat_user_tables の各統計情報をまとめて出力できます
    selected_columns = [
        'start_time', 'end_time', 'query_id', 'relname',
        'max_block', 'min_block',
        # pg_stat_statements 側の統計例（必要に応じて調整）
        'calls', 'total_exec_time',
        # pg_stat_user_tables 側の統計例
        'heap_blks_hit', 'heap_blks_read', 'cache_hit_ratio'
    ]
    df_result = df_join_final[selected_columns]

    print(df_result)
