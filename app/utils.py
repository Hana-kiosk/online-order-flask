from app.database import get_connection
from datetime import timedelta, date
import csv
import os

# 공휴일 캐시 변수
_holidays_cache = None
_cache_file_path = None
_cache_file_mtime = None

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

def load_holidays():
    """공휴일 데이터를 CSV 파일에서 로드 (캐시 기능 포함)"""
    global _holidays_cache, _cache_file_path, _cache_file_mtime
    
    # Flask 앱의 data 디렉토리에서 공휴일 파일 찾기
    current_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(current_dir, 'data', 'holidays.csv')
    
    try:
        # 파일 존재 확인
        if not os.path.exists(csv_path):
            print(f"공휴일 파일을 찾을 수 없습니다: {csv_path}")
            return set()
        
        # 파일 수정 시간 확인
        current_mtime = os.path.getmtime(csv_path)
        
        # 캐시가 유효한지 확인 (파일 경로와 수정 시간이 동일한지)
        if (_holidays_cache is not None and 
            _cache_file_path == csv_path and 
            _cache_file_mtime == current_mtime):
            return _holidays_cache
        
        # 캐시가 없거나 파일이 변경된 경우 새로 로드
        holidays = set()
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                try:
                    holiday_date = date.fromisoformat(row['date'])
                    holidays.add(holiday_date)
                except ValueError:
                    print(f"잘못된 날짜 형식: {row['date']}")
        
        # 캐시 업데이트
        _holidays_cache = holidays
        _cache_file_path = csv_path
        _cache_file_mtime = current_mtime
        
        print(f"공휴일 데이터 로드 완료: {len(holidays)}개")
        return holidays
        
    except Exception as e:
        print(f"공휴일 데이터 로드 오류: {e}")
        return set()

def clear_holidays_cache():
    """공휴일 캐시 초기화 (테스트나 업데이트 시 사용)"""
    global _holidays_cache, _cache_file_path, _cache_file_mtime
    _holidays_cache = None
    _cache_file_path = None
    _cache_file_mtime = None

def calculate_business_days(start_date, end_date):
    """주말과 공휴일을 제외한 실제 근무일 수 계산"""
    if start_date > end_date:
        return 0
    
    # 공휴일 데이터 로드
    holidays = load_holidays()
    
    current_date = start_date
    business_days = 0
    
    while current_date <= end_date:
        # 월요일=0, 일요일=6
        weekday = current_date.weekday()
        
        # 주말(토,일)이 아니고 공휴일도 아닌 경우만 근무일로 계산
        if weekday < 5 and current_date not in holidays:  # 월~금 + 공휴일 아님
            business_days += 1
        
        current_date += timedelta(days=1)
    
    return business_days

def load_holidays_with_details():
    """공휴일 데이터를 상세 정보와 함께 로드"""
    holidays_details = []
    
    # Flask 앱의 data 디렉토리에서 공휴일 파일 찾기
    current_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(current_dir, 'data', 'holidays.csv')
    
    try:
        if not os.path.exists(csv_path):
            print(f"공휴일 파일을 찾을 수 없습니다: {csv_path}")
            return []
        
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                try:
                    holiday_date = date.fromisoformat(row['date'])
                    holidays_details.append({
                        'date': holiday_date,
                        'name': row.get('name', ''),
                        'type': row.get('type', 'national')
                    })
                except ValueError:
                    print(f"잘못된 날짜 형식: {row['date']}")
        
        return holidays_details
        
    except Exception as e:
        print(f"공휴일 상세 데이터 로드 오류: {e}")
        return [] 