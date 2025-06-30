from app.database import get_connection
from datetime import timedelta

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

def calculate_business_days(start_date, end_date):
    """주말을 제외한 실제 근무일 수 계산"""
    current_date = start_date
    business_days = 0
    
    while current_date <= end_date:
        # 월요일=0, 일요일=6
        if current_date.weekday() < 5:  # 월~금
            business_days += 1
        current_date += timedelta(days=1)
    
    return business_days 