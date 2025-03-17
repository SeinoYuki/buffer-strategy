# buffer-strategy

## source tree
* src/data_format.py
  - data/*.csvを成型する
* src/get_stats.py
  - pg_statio_user_tables, pg_stat_statementsを定期的に取得
* src/bench.py
  - pgbench と large_table の実行
  - (補足) large_tableの実行が正時とずれてしまうので、crontabの実行とした
* src/read_block.py
  - eBPF によりブロック番号を取得。実行にはsu権限が必要
* src/feature_engineering.py
  - 特徴量エンジニアリング(未使用)
* src/lerning.py
  - MLロジック(未使用)
