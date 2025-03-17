import pandas as pd
import glob
import re

# 対象ファイルの一覧を取得
file_list = glob.glob("../data/pg_statio_user_tables_*.csv")

data_rows = []
# ファイル名からstart_timeとend_timeを抽出する正規表現パターン
pattern = r"pg_statio_user_tables_(\d{8}_\d{6})_(\d{8}_\d{6})\.csv"

for file in file_list:
    # ファイル名から start_time と end_time を抽出
    match = re.search(pattern, file)
    if match:
        start_time, end_time = match.groups()
    else:
        start_time, end_time = None, None

    # CSVを読み込む
    df = pd.read_csv(file)
    
    # テーブル名が "pgbench_" または "large" で始まる行のみを抽出
    filtered = df[df['relname'].str.startswith('pgbench_') | df['relname'].str.startswith('large')]
    
    # 1行分のデータを辞書にまとめる
    row_data = {'start_time': start_time, 'end_time': end_time}
    for _, row in filtered.iterrows():
        col_name = f"{row['relname']}_cache_hit_ratio"
        row_data[col_name] = row['cache_hit_ratio']
    
    data_rows.append(row_data)

# 辞書のリストから DataFrame を作成
result_df = pd.DataFrame(data_rows)

# start_time をキーにしてソート（YYYYMMDD_HHMMSS形式なら文字列のままでもソート可能）
result_df.sort_values(by='start_time', inplace=True)
result_df.to_csv("../data/cache_hit_ratio.csv", index=False)
print(result_df)