from app.database import get_connection

# inventory_logs 테이블에 로그 기록 함수
def log_inventory_change(inventory_id, quantity, after_stock, memo, created_by):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        query = '''
            INSERT INTO inventory_logs (inventory_id, quantity, after_stock, memo, created_by, created_at) 
            VALUES (%s, %s, %s, %s, %s, NOW())
        '''
        params = (inventory_id, quantity, after_stock, memo, created_by)
        cursor.execute(query, params)
        conn.commit()
    except Exception as e:
        print(f'로그 기록 오류: {e}')
    finally:
        if conn:
            conn.close() 