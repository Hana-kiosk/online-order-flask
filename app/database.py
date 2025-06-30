import mysql.connector
import os

# MySQL 연결 설정
def get_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        port=os.getenv('DB_PORT'),
        charset='utf8mb4',
        collation='utf8mb4_unicode_ci'
    ) 