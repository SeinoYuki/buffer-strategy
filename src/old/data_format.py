import pandas as pd
import time

def data_format(df):
    # ブート後の経過時間 (ナノ秒単位) を元に実際の日時に変換する
    # 現在時刻 (Unix epoch) から、time.monotonic() を引くことでブート時刻の概算を得る
    boot_time_epoch = time.time() - time.monotonic()

    # 基準となる時刻をUTCで取得し、各イベントの経過時間を加算
    base_time_utc = pd.to_datetime(boot_time_epoch, unit='s', utc=True)
    df['Timestamp'] = base_time_utc + pd.to_timedelta(df['Timestamp'], unit='ns')

    # UTCからJST (Asia/Tokyo) に変換
    df['Timestamp'] = df['Timestamp'].dt.tz_convert('Asia/Tokyo')

    # RelFileNode が 16000 以下のものを削除
    df = df[df['RelFileNode'] > 16000]

    df.reset_index(drop=True, inplace=True)

    return df
