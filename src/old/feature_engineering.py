import pandas as pd
import numpy as np

def feature_engineering(df):

    # タイムスタンプをインデックスに設定
    df.set_index("Timestamp", inplace=True)

    # ブロックIDを作成（例：'16407_0' のようにする）
    df["block_id"] = df["RelFileNode"].astype(str) + "_" + df["BlockNum"].astype(str)

    # 各ブロックごとに10分単位で集計（DataFrame の各列がブロックとなる）
    block_ts = df.groupby("block_id").resample("10min").size().unstack(level=0).fillna(0)

    # block_ts を使う場合：インデックスに基づいて特徴量を作成
    block_features = block_ts.copy()
    block_features["hour"] = block_features.index.hour
    # block_features["dayofweek"] = block_features.index.dayofweek
    block_features["minute"] = block_features.index.minute
    block_features["sin_hour"] = np.sin(2 * np.pi * block_features["hour"] / 24)
    block_features["cos_hour"] = np.cos(2 * np.pi * block_features["hour"] / 24)

    # # 各ブロックごとに10分単位で集計（DataFrame の各列がブロックとなる）
    # block_ts = df_org.groupby("block_id").resample("10min").size().unstack(level=0).fillna(0)

    # # ピボットテーブルからロング形式に戻す
    # block_long = block_ts.stack().reset_index()
    # block_long.rename(columns={0: "access_count"}, inplace=True)

    # block_long["hour"] = block_long["Timestamp"].dt.hour
    # block_long["minute"] = block_long["Timestamp"].dt.minute
    # block_long["dayofweek"] = block_long["Timestamp"].dt.dayofweek
    # block_long["sin_hour"] = np.sin(2 * np.pi * block_long["hour"] / 24)
    # block_long["cos_hour"] = np.cos(2 * np.pi * block_long["hour"] / 24)

    # # ブロックごとにソートしてからラグ特徴量を生成
    # block_long.sort_values(["block_id", "Timestamp"], inplace=True)

    # # ラグ特徴量（例：直前1ステップ＝10分前のアクセス件数）
    # block_long["lag_10min"] = block_long.groupby("block_id")["access_count"].shift(1)

    # # 1時間（6サンプル）の移動平均
    # block_long["rolling_mean_1h"] = block_long.groupby("block_id")["access_count"].transform(
    #     lambda x: x.rolling(window=6).mean()
    # )

    return block_features


