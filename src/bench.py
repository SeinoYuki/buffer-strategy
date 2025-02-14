import subprocess
import time
import threading
import subprocess
import logging

# ログの設定
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    filename="../log/bench.log",
    filemode="w"
)

user = "seinoyu"
database = "postgres"

pgbench_command = "/home/seinoyu/pgsql/master/bin/pgbench"
psql_command = "/home/seinoyu/pgsql/master/bin/psql"

custom_function = """
CREATE OR REPLACE FUNCTION random_string(n integer) RETURNS text AS $$
    SELECT string_agg(
                     substr('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                                    (trunc(random() * 62)::int + 1), 1), '')
    FROM generate_series(1, n);
$$ LANGUAGE SQL IMMUTABLE;
"""
custom_drop1 = "DROP TABLE IF EXISTS large_table1"
custom_table1 = "CREATE TABLE large_table1 (id BIGSERIAL PRIMARY KEY, data TEXT)"
custom_initial_data1 = "INSERT INTO large_table1 (data) SELECT random_string(200) FROM generate_series(1, 50000000);"
custom_drop2 = "DROP TABLE IF EXISTS large_table2"
custom_table2 = "CREATE TABLE large_table2 (id BIGSERIAL PRIMARY KEY, data TEXT)"
custom_initial_data2 = "INSERT INTO large_table2 (data) SELECT random_string(200) FROM generate_series(1, 50000000);"

def init_pgbench():
    result = subprocess.run([pgbench_command, "-U", user, "-d", database, "-i", "-s", "1000"], capture_output=True, text=True)
    logout(result)

def run_pgbench():
    result = subprocess.run([pgbench_command, "-U", user, "-d", database, "-T", "90000", "-c", "100", "-P", "60", "--progress-timestamp"], capture_output=True, text=True)
    logout(result)

def init_custom_sql_per15min():
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_drop1], capture_output=True, text=True)
    logout(result)
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_table1], capture_output=True, text=True)
    logout(result)
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_function], capture_output=True, text=True)
    logout(result)
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_initial_data1], capture_output=True, text=True)
    logout(result)

def init_custom_sql_per1hour():
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_drop2], capture_output=True, text=True)
    logout(result)
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_table2], capture_output=True, text=True)
    logout(result)
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_function], capture_output=True, text=True)
    logout(result)
    result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", custom_initial_data2], capture_output=True, text=True)
    logout(result)

def wait_until_next_quarter():
    """
    次の15分区切り（00,15,30,45分）までの待ち時間を計算してsleepする。
    """
    now = datetime.datetime.now()
    # 現在の分・秒から次の15分の境界を計算
    minute = now.minute
    # 次の15分区切りの分（例：現在12:07なら15、12:17なら30）
    next_quarter_minute = ((minute // 15) + 1) * 15
    if next_quarter_minute >= 60:
        # 60分になったら次の時刻（00分）へ
        next_time = now.replace(hour=now.hour, minute=0, second=0, microsecond=0) + datetime.timedelta(hours=1)
    else:
        next_time = now.replace(minute=next_quarter_minute, second=0, microsecond=0)
    wait_seconds = (next_time - now).total_seconds()
    logging.info("Waiting %.2f seconds until next quarter (%s)", wait_seconds, next_time)
    time.sleep(wait_seconds)

def wait_until_next_hour():
    """
    次の時間（毎時0分）までの待ち時間を計算してsleepする。
    """
    now = datetime.datetime.now()
    next_time = now.replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=1)
    wait_seconds = (next_time - now).total_seconds()
    logging.info("Waiting %.2f seconds until next hour (%s)", wait_seconds, next_time)
    time.sleep(wait_seconds)

def run_custom_sql_per15min():
    """
    large_table1 に対してのクエリを、毎15分（00,15,30,45分）に合わせて実行する。
    """
    while True:
        wait_until_next_quarter()
        result = subprocess.run([psql_command, "-U", user, "-d", database, "-c",
                                 "EXPLAIN ANALYZE SELECT * from large_table1"],
                                capture_output=True, text=True)
        logout(result)

def run_custom_sql_per1hour():
    """
    large_table2 に対してのクエリを、毎時0分に合わせて実行する。
    """
    while True:
        wait_until_next_hour()
        result = subprocess.run([psql_command, "-U", user, "-d", database, "-c",
                                 "EXPLAIN ANALYZE SELECT * from large_table2"],
                                capture_output=True, text=True)
        logout(result)

def logout(result):
    # 標準出力の内容をログに記録
    if result.stdout:
        logging.info("標準出力:\n%s", result.stdout)
    # 標準エラーの内容があればログに記録
    if result.stderr:
        logging.error("標準エラー:\n%s", result.stderr)

def run_custom_sql_per15min():
    while True:
        result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", "EXPLAIN ANALYZE SELECT * from large_table1"], capture_output=True, text=True)
        logout(result)
        time.sleep(15 * 60)  # Sleep for 15 minutes
        # time.sleep(60)

def run_custom_sql_per1hour():
    while True:
        result = subprocess.run([psql_command, "-U", user, "-d", database, "-c", "EXPLAIN ANALYZE SELECT * from large_table2"], capture_output=True, text=True)
        logout(result)
        time.sleep(60 * 60)  # Sleep for 60 minutes
        # time.sleep(3 * 60)

def logout(result):
    # 標準出力の内容をログに記録
    if result.stdout:
        logging.info("標準出力:\n%s", result.stdout)

    # 標準エラーの内容があればログに記録
    if result.stderr:
        logging.error("標準エラー:\n%s", result.stderr)

def init():
    init_pgbench()
    init_custom_sql_per15min()
    init_custom_sql_per1hour()

def bench():
    pgbench_thread = threading.Thread(target=run_pgbench)
    custom_sql_per15min_thread = threading.Thread(target=run_custom_sql_per15min)
    custom_sql_per1hour_thread = threading.Thread(target=run_custom_sql_per1hour)

    pgbench_thread.start()
    custom_sql_per15min_thread.start()
    custom_sql_per1hour_thread.start()

    pgbench_thread.join()
    custom_sql_per15min_thread.join()
    custom_sql_per1hour_thread.join()

bench()