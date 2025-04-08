from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta
import jwt
import bcrypt
from functools import wraps

app = Flask(__name__)
CORS(app)  # CORS 미들웨어 설정
PORT = 5000

load_dotenv()

# JWT 비밀 키 설정
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
JWT_EXPIRATION_DELTA = timedelta(days=1)  # 토큰 유효 기간 (1일)

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

# 토큰 필수 데코레이터
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': '인증 토큰이 필요합니다'}), 401
        
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            user_id = payload['sub']
            
            # 사용자 존재 여부 확인
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT id, username, name, role FROM users WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            conn.close()
            
            if not user:
                return jsonify({'error': '유효하지 않은 사용자입니다'}), 401
            
            # 요청에 사용자 정보 추가
            request.user = user
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': '만료된 토큰입니다. 다시 로그인하세요'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': '유효하지 않은 토큰입니다'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# 로그인 API
@app.route('/api/auth/login', methods=['POST'])
def login():
    conn = None
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        print(f"로그인 시도: 사용자={username}")
        if not username or not password:
            return jsonify({'error': '아이디와 비밀번호를 모두 입력해주세요'}), 400
        
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 사용자 조회
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': '아이디 또는 비밀번호가 올바르지 않습니다'}), 401
        
        # 비밀번호 검증
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({'error': '아이디 또는 비밀번호가 올바르지 않습니다'}), 401
        
        # JWT 토큰 생성
        payload = {
            'sub': user['id'],
            'username': user['username'],
            'role': user['role'],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + JWT_EXPIRATION_DELTA
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
        
        # 응답에서 비밀번호 제거
        user.pop('password', None)
        
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'name': user['name'],
                'role': user['role']
            }
        })
        
    except Exception as e:
        print(f'로그인 오류 상세 정보: {str(e)}')  # 더 자세한 오류 정보
        import traceback
        traceback.print_exc()  # 스택 트레이스 출력
        return jsonify({'error': '로그인 처리 중 오류가 발생했습니다'}), 500
    finally:
        if conn:
            conn.close()

# 현재 사용자 정보 조회 API
@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify(request.user)

# 모든 발주 목록 조회 API
@app.route('/api/orders', methods=['GET'])
@token_required
def get_orders():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        year = request.args.get('year')
        month = request.args.get('month')
        search = request.args.get('search')

        query = 'SELECT * FROM orders'
        conditions = []
        params = []

        if year and year != 'all':
            conditions.append('YEAR(order_date) = %s')
            params.append(year)
        
        if month and month != 'all':
            conditions.append('MONTH(order_date) = %s')
            params.append(month)
        
        if search:
            conditions.append('(id LIKE %s OR item_code LIKE %s OR color_name LIKE %s)')
            search_param = f"%{search}%"
            params.extend([search_param] * 3)

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY order_date DESC, id DESC'
        
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        
        return jsonify(rows)
    except Exception as e:
        print(f'발주 목록 조회 오류: {e}')
        return jsonify({'error': '발주 목록을 불러오는 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

# 특정 발주 조회 API
@app.route('/api/orders/<id>', methods=['GET'])
@token_required
def get_order(id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute('SELECT * FROM orders WHERE id = %s', (id,))
        row = cursor.fetchone()

        if row is None:
            return jsonify({'error': '발주 정보를 찾을 수 없습니다.'}), 404
        
        return jsonify(row)
    except Exception as e:
        print(f'발주 정보 조회 오류: {e}')
        return jsonify({'error': '발주 정보를 불러오는 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

# 발주 생성 API
@app.route('/api/orders', methods=['POST'])
@token_required
def create_order():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        order_data = request.get_json()
        
        # 필드 이름 매핑 (클라이언트 -> 서버)
        if 'itemCode' in order_data and 'item_code' not in order_data:
            order_data['item_code'] = order_data['itemCode']
        
        if 'colorName' in order_data and 'color_name' not in order_data:
            order_data['color_name'] = order_data['colorName']
            
        if 'orderQuantity' in order_data and 'order_quantity' not in order_data:
            order_data['order_quantity'] = order_data['orderQuantity']
            
        if 'orderDate' in order_data and 'order_date' not in order_data:
            order_data['order_date'] = order_data['orderDate']
            
        if 'expectedArrivalStartDate' in order_data and 'expected_arrival_start_date' not in order_data:
            order_data['expected_arrival_start_date'] = order_data['expectedArrivalStartDate']
            
        if 'expectedArrivalEndDate' in order_data and 'expected_arrival_end_date' not in order_data:
            order_data['expected_arrival_end_date'] = order_data['expectedArrivalEndDate']
            
        if 'arrivalDate' in order_data and 'arrival_date' not in order_data:
            order_data['arrival_date'] = order_data['arrivalDate']
            
        if 'arrivalQuantity' in order_data and 'arrival_quantity' not in order_data:
            order_data['arrival_quantity'] = order_data['arrivalQuantity']
            
        if 'specialNote' in order_data and 'special_note' not in order_data:
            order_data['special_note'] = order_data['specialNote']
            
        if 'remarks' in order_data and 'remarks' not in order_data:
            order_data['remarks'] = order_data['remarks']
        
        print("변환 후 데이터:", order_data)
        
        # 발주번호 생성 (현재 연월 + 일련번호)
        today = datetime.today()
        year = today.year
        month = str(today.month).zfill(2)
        prefix = f"ORD-{year}{month}"

        # 같은 연월의 마지막 발주번호 조회
        cursor.execute('SELECT id FROM orders WHERE id LIKE %s ORDER BY id DESC LIMIT 1', (f'{prefix}%',))
        last_order_result = cursor.fetchone()
        
        if last_order_result:
            last_id = last_order_result['id']
            last_seq = int(last_id[len(prefix):]) if last_id[len(prefix):].isdigit() else 0
            new_order_id = f"{prefix}{str(last_seq + 1).zfill(4)}"
        else:
            new_order_id = f"{prefix}0001"

        # 날짜 형식 변환
        def format_date(date_str):
            if date_str and date_str != 'null':
                try:
                    return datetime.strptime(date_str, "%Y-%m-%d").date()
                except ValueError:
                    print(f"날짜 형식 오류: {date_str}")
                    return None
            return None
        
        order_date = format_date(order_data.get('order_date'))
        expected_arrival_start_date = format_date(order_data.get('expected_arrival_start_date'))
        expected_arrival_end_date = format_date(order_data.get('expected_arrival_end_date'))
        arrival_date = format_date(order_data.get('arrival_date'))

        # 상태 결정
        status = '대기'
        if arrival_date:
            if order_data.get('arrival_quantity', 0) >= order_data.get('order_quantity', 0):
                status = '입고완료'
            elif order_data.get('arrival_quantity', 0) > 0:
                status = '부분입고'
            
            # 지연 여부 확인
            if expected_arrival_end_date and arrival_date > expected_arrival_end_date:
                status = '지연'

        # 현재 로그인한 사용자 ID 추가
        user_id = request.user['id']

        cursor.execute(
            '''
            INSERT INTO orders (
                id, order_date, item_code, color_name, order_quantity,
                expected_arrival_start_date, expected_arrival_end_date,
                arrival_date, arrival_quantity, special_note, remarks, status, user_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''',
            (
                new_order_id, 
                order_date, 
                order_data.get('item_code', ''), 
                order_data.get('color_name', ''), 
                order_data.get('order_quantity', 0),
                expected_arrival_start_date, 
                expected_arrival_end_date,
                arrival_date, 
                order_data.get('arrival_quantity', None), 
                order_data.get('special_note', ''), 
                order_data.get('remarks', ''), 
                status,
                user_id
            )
        )
        conn.commit()

        return jsonify({'id': new_order_id, 'message': '발주 정보가 성공적으로 저장되었습니다.'}), 201
    except Exception as e:
        print(f'발주 생성 오류: {e}')
        if 'item_code' in str(e):
            return jsonify({'error': '품목 코드(item_code) 처리 중 오류가 발생했습니다. 데이터 형식을 확인해주세요.'}), 500
        elif 'order_date' in str(e):
            return jsonify({'error': '발주일자(order_date) 처리 중 오류가 발생했습니다. 날짜 형식을 확인해주세요.'}), 500
        elif 'expected_arrival' in str(e):
            return jsonify({'error': '입고예정일 처리 중 오류가 발생했습니다. 날짜 형식을 확인해주세요.'}), 500
        else:
            return jsonify({'error': f'발주 정보를 저장하는 중 오류가 발생했습니다: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

# 발주 수정 API
@app.route('/api/orders/<id>', methods=['PUT'])
@token_required
def update_order(id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        order_data = request.get_json()
        
        # 기존 발주 정보 가져오기
        cursor.execute('SELECT * FROM orders WHERE id = %s', (id,))
        existing_order = cursor.fetchone()
        if not existing_order:
            return jsonify({'error': '발주 정보를 찾을 수 없습니다.'}), 404
            
        # 상태 변경 여부 확인
        status_changed = 'status' in order_data and order_data['status'] != existing_order['status']
        
        # 상태가 변경되었는데 admin이 아닌 경우 권한 오류 반환
        if status_changed and request.user['role'] != 'admin':
            return jsonify({'error': '발주 상태 변경 권한이 없습니다. 관리자만 상태를 변경할 수 있습니다.'}), 403

        expected_arrival_start_date = order_data.get('expected_arrival_start_date')
        expected_arrival_end_date = order_data.get('expected_arrival_end_date')
        arrival_date = order_data.get('arrival_date')

        status = order_data.get('status', '대기')

        cursor.execute(
            '''
            UPDATE orders SET
                expected_arrival_start_date = %s,
                expected_arrival_end_date = %s,
                arrival_date = %s,
                arrival_quantity = %s,
                special_note = %s,
                remarks = %s,
                status = %s,
                user_id = %s
            WHERE id = %s
            ''',
            (
                expected_arrival_start_date, expected_arrival_end_date,
                arrival_date, order_data.get('arrival_quantity', None),
                order_data.get('special_note', None), order_data.get('remarks', None), 
                status, request.user['id'], id
            )
        )
        conn.commit()

        # 영향을 받은 행이 없는 경우 발주가 존재하는지 확인
        if cursor.rowcount == 0:
            cursor.execute('SELECT id FROM orders WHERE id = %s', (id,))
            existing_order = cursor.fetchone()
            if not existing_order:
                return jsonify({'error': '발주 정보를 찾을 수 없습니다.'}), 404

        return jsonify({'message': '발주 정보가 성공적으로 업데이트되었습니다.'})
    except Exception as e:
        print(f'발주 수정 오류: {e}')
        return jsonify({'error': '발주 정보를 업데이트하는 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()


# 발주 삭제 API
@app.route('/api/orders/<id>', methods=['DELETE'])
@token_required
def delete_order(id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute('DELETE FROM orders WHERE id = %s', (id,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': '발주 정보를 찾을 수 없습니다.'}), 404

        return jsonify({'message': '발주 정보가 성공적으로 삭제되었습니다.'})
    except Exception as e:
        print(f'발주 삭제 오류: {e}')
        return jsonify({'error': '발주 정보를 삭제하는 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

# 재고 전체 조회 API
@app.route('/api/inventory', methods=['GET'])
@token_required
def get_inventory():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        
        item_name = request.args.get('item_name')
        color = request.args.get('color')
        location = request.args.get('location')

        query = 'SELECT * FROM inventory'  # 모든 항목 조회 (visible 필터 제거)
        conditions = []
        params = []

        if item_name:
            conditions.append('item_name LIKE %s')
            params.append(f"%{item_name}%")
        
        if color:
            conditions.append('color LIKE %s')
            params.append(f"%{color}%")
        
        if location:
            conditions.append('location LIKE %s')
            params.append(f"%{location}%")

        if conditions:
            query += ' AND ' + ' AND '.join(conditions)
        
        query += ' ORDER BY item_name DESC'
        
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        
        return jsonify(rows)
    except Exception as e:
        print(f'재고 전체 조회 오류: {e}')
        return jsonify({'error': '재고 전체 조회 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

# inventory_logs 테이블에 로그 기록 함수 추가
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

# add_inventory API에 로그 기록 추가
@app.route('/api/inventory', methods=['POST'])
@token_required
def add_inventory():
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        data = request.json
        item_name = data.get('item_name')
        color = data.get('color', None)
        stock = data.get('stock', 0)
        safety_stock = data.get('safety_stock', 0)
        unit = data.get('unit', '개')
        location = data.get('location', None)
        memo = data.get('memo', '신규 추가')  # 사용자가 제공한 memo 또는 기본값

        if not item_name:
            return jsonify({'error': '품목명은 필수 입력값입니다.'}), 400

        query = '''
            INSERT INTO inventory (item_name, color, stock, safety_stock, unit, location, updated_at) 
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
        '''
        params = (item_name, color, stock, safety_stock, unit, location)

        cursor.execute(query, params)
        conn.commit()

        # 로그 기록
        log_inventory_change(cursor.lastrowid, stock, stock, memo, request.user['name'])

        return jsonify({'message': '품목이 추가되었습니다.', 'id': cursor.lastrowid}), 201
    except Exception as e:
        print(f'품목 추가 오류: {e}')
        return jsonify({'error': '품목 추가 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

# update_inventory API에 로그 기록 추가
@app.route('/api/inventory/<id>', methods=['PUT'])
@token_required
def update_inventory(id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        data = request.json
        item_name = data.get('item_name')
        color = data.get('color')
        stock = data.get('stock')
        safety_stock = data.get('safety_stock')
        unit = data.get('unit')
        location = data.get('location')
        memo = data.get('memo', '수정')  # 사용자가 제공한 memo 또는 기본값

        # 해당 ID의 품목이 존재하는지 확인
        cursor.execute('SELECT * FROM inventory WHERE id = %s', (id,))
        item = cursor.fetchone()

        if not item:
            return jsonify({'error': '해당 품목을 찾을 수 없습니다.'}), 404

        # 기존 stock 값 가져오기
        old_stock = item['stock']

        update_fields = []
        params = []

        if item_name is not None:
            update_fields.append('item_name = %s')
            params.append(item_name)
        if color is not None:
            update_fields.append('color = %s')
            params.append(color)
        if stock is not None:
            update_fields.append('stock = %s')
            params.append(stock)
        if safety_stock is not None:
            update_fields.append('safety_stock = %s')
            params.append(safety_stock)
        if unit is not None:
            update_fields.append('unit = %s')
            params.append(unit)
        if location is not None:
            update_fields.append('location = %s')
            params.append(location)

        if not update_fields:
            return jsonify({'message': '변경할 데이터가 없습니다.'}), 400

        query = f'UPDATE inventory SET {", ".join(update_fields)}, updated_at = NOW() WHERE id = %s'
        params.append(id)

        cursor.execute(query, tuple(params))
        conn.commit()

        # 변경된 수량 계산
        quantity_change = stock - old_stock if stock is not None else 0

        # 로그 기록
        log_inventory_change(id, quantity_change, stock, memo, request.user['name'])

        return jsonify({'message': '품목이 수정되었습니다.'})
    except Exception as e:
        print(f'품목 수정 오류: {e}')
        return jsonify({'error': '품목 수정 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

# 재고 삭제 API
@app.route('/api/inventory/<id>', methods=['DELETE'])
@token_required
def delete_inventory(id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 해당 ID의 품목이 존재하는지 확인
        cursor.execute('SELECT * FROM inventory WHERE id = %s', (id,))
        item = cursor.fetchone()

        if not item:
            return jsonify({'error': '해당 품목을 찾을 수 없습니다.'}), 404

        # visible 컬럼을 0으로 설정 (삭제 처리)
        cursor.execute('UPDATE inventory SET visible = 0 WHERE id = %s', (id,))
        conn.commit()

        # 로그 기록
        log_inventory_change(id, 0, item['stock'], '삭제', request.user['name'])

        return jsonify({'message': '품목이 성공적으로 삭제되었습니다.'})
    except Exception as e:
        print(f'품목 삭제 오류: {e}')
        return jsonify({'error': '품목 삭제 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

# 재고 복구 API
@app.route('/api/inventory/<id>/restore', methods=['PUT'])
@token_required
def restore_inventory(id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 해당 ID의 품목이 존재하는지 확인
        cursor.execute('SELECT * FROM inventory WHERE id = %s', (id,))
        item = cursor.fetchone()

        if not item:
            return jsonify({'error': '해당 품목을 찾을 수 없습니다.'}), 404

        # visible 컬럼을 1로 설정 (복구 처리)
        cursor.execute('UPDATE inventory SET visible = 1 WHERE id = %s', (id,))
        conn.commit()

        # 로그 기록
        log_inventory_change(id, 0, item['stock'], '복구', request.user['name'])

        return jsonify({'message': '품목이 성공적으로 복구되었습니다.'})
    except Exception as e:
        print(f'품목 복구 오류: {e}')
        return jsonify({'error': '품목 복구 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/test-password/<password>')
def test_password(password):
    stored_hash = '$2b$10$rXfI/6Pl1K5YhZKQr1aZkeu7ZXmOJinp6bJlBZKm2MfU7eR7UWi8a'
    is_valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    return jsonify({'password': password, 'is_valid': is_valid})

@app.route('/generate-password-hash/<password>')
def generate_password_hash(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return jsonify({
        'password': password,
        'hashed': hashed.decode('utf-8')
    })

# 특정 inventory_id의 로그 조회 API
@app.route('/api/inventory/<inventory_id>/logs', methods=['GET'])
@token_required
def get_inventory_logs(inventory_id):
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # inventory_id에 해당하는 로그 조회
        cursor.execute('SELECT * FROM inventory_logs WHERE inventory_id = %s ORDER BY created_at ASC', (inventory_id,))
        logs = cursor.fetchall()

        if not logs:
            return jsonify({'error': '해당 inventory_id에 대한 로그를 찾을 수 없습니다.'}), 404

        return jsonify(logs)
    except Exception as e:
        print(f'로그 조회 오류: {e}')
        return jsonify({'error': '로그를 조회하는 중 오류가 발생했습니다.'}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(debug=False, port=PORT)