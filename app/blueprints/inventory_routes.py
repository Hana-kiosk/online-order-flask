from flask import Blueprint, request, jsonify
from app.database import get_connection
from app.auth import token_required
from app.utils import log_inventory_change

inventory_bp = Blueprint('inventory', __name__)

# 재고 전체 조회 API
@inventory_bp.route('/inventory', methods=['GET'])
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
            query += ' WHERE ' + ' AND '.join(conditions)
        
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

# 재고 추가 API
@inventory_bp.route('/inventory', methods=['POST'])
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

# 재고 수정 API
@inventory_bp.route('/inventory/<id>', methods=['PUT'])
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
@inventory_bp.route('/inventory/<id>', methods=['DELETE'])
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
@inventory_bp.route('/inventory/<id>/restore', methods=['PUT'])
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

# 특정 inventory_id의 로그 조회 API
@inventory_bp.route('/inventory/<inventory_id>/logs', methods=['GET'])
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