from flask import Blueprint, request, jsonify
from datetime import datetime
from app.database import get_connection
from app.auth import token_required

order_bp = Blueprint('orders', __name__)

# 모든 발주 목록 조회 API
@order_bp.route('/orders', methods=['GET'])
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
@order_bp.route('/orders/<id>', methods=['GET'])
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
@order_bp.route('/orders', methods=['POST'])
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
@order_bp.route('/orders/<id>', methods=['PUT'])
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
@order_bp.route('/orders/<id>', methods=['DELETE'])
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