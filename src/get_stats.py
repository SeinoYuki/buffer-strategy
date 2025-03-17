import psycopg2
import csv
import time
from datetime import datetime

def export_query_to_csv(query, csv_filename, conn):
    """
    指定したSQLクエリの結果をCSVファイルに書き出す
    """
    with conn.cursor() as cur:
        cur.execute(query)
        # カラム名の取得
        columns = [desc[0] for desc in cur.description]
        rows = cur.fetchall()

    # CSVに書き出し
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(columns)  # ヘッダー行
        writer.writerows(rows)
    print(f"Exported {csv_filename}")

def reset_stats(conn):
    """
    pg_stat_statements および pg_stat_* の統計情報をリセットする
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_stat_statements_reset();")
        cur.execute("SELECT pg_stat_reset();")
    conn.commit()
    print("Statistics reset.")

def main():
    # データベース接続パラメータ
    conn_params = {
        'host': 'localhost',
        'port': 5432,
        'dbname': 'postgres',
        'user': 'seinoyu',
        'password': 'seinoyu'
    }

    try:
        # PostgreSQLに接続
        conn = psycopg2.connect(**conn_params)
        print("Connected to the database.")

        # 初回統計情報リセットと開始時刻の設定
        reset_stats(conn)
        start_time = datetime.now()

        file_pg_class = f"../data/pg_class.csv"
        export_query_to_csv(
            "SELECT relname, relfilenode FROM pg_class where relnamespace = '2200';",
            file_pg_class, conn
        )

        while True:
            print("Waiting for 5 minutes...")
            time.sleep(60)  # 5分待機

            # 5分経過後の終了時刻を取得
            end_time = datetime.now()

            # 開始、終了時刻をファイル名用にフォーマット（例: 20230405_120000）
            start_str = start_time.strftime("%Y%m%d_%H%M%S")
            end_str = end_time.strftime("%Y%m%d_%H%M%S")

            # ファイル名の作成（ディレクトリは必要に応じて調整）
            file_statements = f"../data/pg_stat_statements_{start_str}_{end_str}.csv"
            file_userio_tables = f"../data/pg_statio_user_tables_{start_str}_{end_str}.csv"
            file_userio_indexes = f"../data/pg_statio_user_indexes_{start_str}_{end_str}.csv"

            # 統計情報のエクスポート
            export_query_to_csv(
                "SELECT queryid, calls, total_exec_time, min_exec_time, max_exec_time, mean_exec_time, stddev_exec_time, rows, "
                "shared_blks_hit, shared_blks_read, shared_blks_dirtied, shared_blks_written, "
                "local_blks_hit, local_blks_read, local_blks_dirtied, local_blks_written, temp_blks_read, temp_blks_written, "
                "shared_blk_read_time, shared_blk_write_time, local_blk_read_time, local_blk_write_time, temp_blk_read_time, "
                "temp_blk_write_time, wal_records, wal_fpi, wal_bytes FROM pg_stat_statements;",
                file_statements, conn
            )
            export_query_to_csv(
                "SELECT relname, heap_blks_hit, heap_blks_read, "
                "ROUND( (heap_blks_hit::numeric / NULLIF(heap_blks_hit + heap_blks_read, 0)) * 100, 2) AS cache_hit_ratio "
                "FROM pg_statio_all_tables "
                "ORDER BY cache_hit_ratio DESC;",  
                file_userio_tables, conn
            )

            # 統計情報をリセットして次の期間へ
            reset_stats(conn)
            start_time = end_time  # 次回の期間の開始時刻を更新

    except Exception as e:
        print("Error:", e)
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

if __name__ == '__main__':
    main()
