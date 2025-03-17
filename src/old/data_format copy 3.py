import pandas as pd
import os
import glob

def main():
    # ① ブロック読み込みCSVを読み込み、1分毎・relfilenodeごとに集計
    block_csv = "../data/bpf_read_block.csv"
    df = pd.read_csv(block_csv, header=0, low_memory=False)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S")
    # 1分毎に丸める（例: 17:00:59 → 17:00:00）
    df["minute"] = df["timestamp"].dt.floor("min")
    
    # minute, relfilenode ごとに集計
    result = df.groupby(["minute", "relfilenode"]).agg(
        agg_max_block=("max_block", "max"),
        agg_min_block=("min_block", "min")
    ).reset_index()
    result.rename(columns={"minute": "timestamp"}, inplace=True)
    
    # ② relfilenode を relname に変換するマッピング (pg_class.csv)
    mapping_csv = "../data/pg_class.csv"
    mapping_df = pd.read_csv(mapping_csv)
    mapping_dict = mapping_df.set_index("relfilenode")["relname"].to_dict()
    result["relname"] = result["relfilenode"].map(mapping_dict)
    # マッピングできなかった行を削除

    result = result.dropna(subset=["relname"])
    
    # ③ 複数のキャッシュCSVファイルをglobで取得
    cache_files = glob.glob("../data/pg_statio_user_tables_*.csv")
    
    merged_list = []
    for cache_csv in cache_files:
        cache_df = pd.read_csv(cache_csv)
        
        # ④ ファイル名からキャッシュ対象期間（開始・終了時刻）を抽出
        # 例: "pg_statio_user_tables_20250227_170020_20250227_170120.csv"
        filename = os.path.splitext(os.path.basename(cache_csv))[0]
        parts = filename.split("_")
        if len(parts) >= 8:
            # 抽出した開始時刻を丸めて分単位に揃える
            raw_cache_start = pd.to_datetime(parts[4] + " " + parts[5], format="%Y%m%d %H%M%S")
            cache_start = raw_cache_start.floor("min")
            # 終了時刻は開始時刻＋1分
            cache_end = cache_start + pd.Timedelta(minutes=1)
        else:
            continue
        
        # ⑤ 対象期間 [cache_start, cache_end) のデータのみ抽出
        result_interval = result[(result["timestamp"] >= cache_start) & (result["timestamp"] < cache_end)]
        
        # ⑥ キャッシュ情報とrelnameで結合
        merged = pd.merge(
            result_interval,
            cache_df[["relname", "heap_blks_hit", "heap_blks_read", "cache_hit_ratio"]],
            on="relname", how="left"
        )
        merged_list.append(merged)
    
    if merged_list:
        final_df = pd.concat(merged_list, ignore_index=True)
        # ⑦ キャッシュ情報のNaN行を削除
        final_df = final_df.dropna(subset=["heap_blks_hit", "heap_blks_read", "cache_hit_ratio"])
    else:
        final_df = pd.DataFrame()

    # df を timestamp, relname でソート
    final_df = final_df.sort_values(by=["timestamp", "relname"])

    print(final_df)
    # CSV に出力
    final_df.to_csv("../data/cache_hit_ratio.csv", index=False)

if __name__ == '__main__':
    main()
