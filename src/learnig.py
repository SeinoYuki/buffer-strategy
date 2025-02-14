import pandas as pd
import re
import data_format
import feature_engineering

# テキストデータを読み込み
with open("../data/data.txt", "r") as file:
    lines = file.readlines()

# 正規表現でデータを抽出
pattern = r'Timestamp:\s*(\d+)\s+PID:\s*(\d+)\s+RelFileNode:\s*(\d+)\s+BlockNum:\s*(\d+)'
data = []
for line in lines:
    match = re.search(pattern, line)
    if match:
        data.append(match.groups())

# データフレームに変換
df_org = pd.DataFrame(data, columns=['Timestamp', 'PID', 'RelFileNode', 'BlockNum'])
df_org = df_org.astype({'Timestamp': 'int64', 'PID': 'int64', 'RelFileNode': 'int64', 'BlockNum': 'int64'})

# データの整形
df_df = data_format.data_format(df_org)
print(df_df)

# 特徴量エンジニアリング
df_fe = feature_engineering.feature_engineering(df_df)
print(df_fe)

# 特徴量エンジニアリング