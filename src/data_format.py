import glob
import os
import re
import pandas as pd
from datetime import datetime

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
    
    # df_bpf の relfilenode を pg_class の relfilenode, relname 情報をもとに relname に変換
    if 'relfilenode' in df_bpf.columns and 'relfilenode' in df_pg_class.columns:
        df_bpf = df_bpf.merge(df_pg_class[['relfilenode', 'relname']], on='relfilenode', how='left')
    else:
        print("relfilenode column not found in either df_bpf or df_pg_class")

    # 表示オプションの設定（全列表示）
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1200)
    
    print("=== pg_stat_statements ===")
    print(df_statements.head())
    
    print("\n=== pg_stat_user_tables ===")
    print(df_tables.head())
    
    print("\n=== bpf_read_block ===")
    print(df_bpf)
    
    print("\n=== pg_class ===")
    print(df_pg_class.head())
    
    # 例：df_pg_stat の start_time 列と df_bpf の timestamp 列を同じ解像度に変換
    df_statements['start_time'] = pd.to_datetime(df_statements['start_time']).astype('datetime64[ns]')
    df_bpf['timestamp'] = pd.to_datetime(df_bpf['timestamp']).astype('datetime64[ns]')

    # 両方ソート
    df_pg_stat_sorted = df_statements.sort_values('start_time')
    df_bpf_sorted = df_bpf.sort_values('timestamp')

    # merge_asof の実行
    merged = pd.merge_asof(
        df_bpf_sorted, 
        df_pg_stat_sorted, 
        left_on='timestamp', 
        right_on='start_time', 
        direction='backward'
    )

    # BPFログの timestamp が、対応する pg_stat_* の end_time より前かフィルタリング
    merged_filtered = merged[merged['timestamp'] <= merged['end_time']]

    print("Merged DataFrame (Filtered):")
    print(merged_filtered.head())
