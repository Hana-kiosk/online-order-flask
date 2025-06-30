from flask import Blueprint, request, jsonify
from datetime import datetime, date
import uuid
from mysql.connector import Error
from app.database import get_connection
from app.auth import token_required
from app.utils import calculate_business_days

leave_bp = Blueprint('leave', __name__)

@leave_bp.route('/leave/apply', methods=['POST'])
@token_required
def apply_leave():
    """연차 신청 API"""
    try:
        data = request.get_json()
        
        # 필수 필드 검증
        required_fields = ['userid', 'name', 'leave_type', 'start_date', 'end_date']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} 필드가 누락되었습니다.'
                }), 400
        
        # 날짜 파싱
        try:
            start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
            end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({
                'success': False,
                'message': '날짜 형식이 올바르지 않습니다. (YYYY-MM-DD 형식 사용)'
            }), 400
        
        # 날짜 유효성 검증
        today = date.today()
        if start_date < today:
            return jsonify({
                'success': False,
                'message': '과거 날짜에는 연차를 신청할 수 없습니다.'
            }), 400
        
        if start_date > end_date:
            return jsonify({
                'success': False,
                'message': '시작일이 종료일보다 늦을 수 없습니다.'
            }), 400
        
        # 근무일 수 계산
        business_days = calculate_business_days(start_date, end_date)
        
        # 데이터베이스 연결
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor()
        
        try:
            # 연차 신청 데이터 삽입
            leave_id = str(uuid.uuid4())
            insert_query = """
                INSERT INTO leave_requests 
                (id, userid, name, leave_type, start_date, end_date, reason, status, applied_at, days_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (
                leave_id,
                data['userid'],
                data['name'],
                data['leave_type'],
                start_date,
                end_date,
                data.get('reason', ''),
                'pending',
                datetime.now(),
                business_days
            ))
            
            connection.commit()
            
            return jsonify({
                'success': True,
                'message': '연차 신청이 완료되었습니다.',
                'data': {
                    'leave_id': leave_id,
                    'days_count': business_days,
                    'status': 'pending'
                }
            }), 200
            
        except Error as e:
            connection.rollback()
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 신청 처리 중 오류가 발생했습니다.'
            }), 500
            
        finally:
            cursor.close()
            connection.close()
            
    except Exception as e:
        print(f"일반 오류: {e}")
        return jsonify({
            'success': False,
            'message': '서버 오류가 발생했습니다.'
        }), 500

@leave_bp.route('/leave/list', methods=['GET'])
@token_required
def get_leave_list():
    """연차 목록 조회 API"""
    try:
        userid = request.args.get('userid')
        
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor(dictionary=True)
        
        try:
            if userid:
                # 특정 사용자의 연차 목록
                query = """
                    SELECT * FROM leave_requests 
                    WHERE userid = %s 
                    ORDER BY applied_at DESC
                """
                cursor.execute(query, (userid,))
            else:
                # 모든 연차 목록 (관리자용)
                query = """
                    SELECT * FROM leave_requests 
                    ORDER BY applied_at DESC
                """
                cursor.execute(query)
            
            leaves = cursor.fetchall()
            
            # 날짜 필드 포맷팅
            for leave in leaves:
                if leave['start_date']:
                    leave['start_date'] = leave['start_date'].strftime('%Y-%m-%d')
                if leave['end_date']:
                    leave['end_date'] = leave['end_date'].strftime('%Y-%m-%d')
                if leave['applied_at']:
                    leave['applied_at'] = leave['applied_at'].strftime('%Y-%m-%d %H:%M:%S')
                if leave['reviewed_at']:
                    leave['reviewed_at'] = leave['reviewed_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify(leaves), 200
            
        except Error as e:
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 목록 조회 중 오류가 발생했습니다.'
            }), 500
            
        finally:
            cursor.close()
            connection.close()
            
    except Exception as e:
        print(f"일반 오류: {e}")
        return jsonify({
            'success': False,
            'message': '서버 오류가 발생했습니다.'
        }), 500

@leave_bp.route('/leave/<leave_id>/status', methods=['PUT'])
@token_required
def update_leave_status(leave_id):
    """연차 상태 업데이트 API (관리자용)"""
    try:
        data = request.get_json()
        status = data.get('status')
        
        if status not in ['approved', 'rejected']:
            return jsonify({
                'success': False,
                'message': '올바르지 않은 상태값입니다.'
            }), 400
        
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor()
        
        try:
            # 연차 상태 업데이트
            update_query = """
                UPDATE leave_requests 
                SET status = %s, reviewed_at = %s, reviewed_by = %s
                WHERE id = %s
            """
            
            cursor.execute(update_query, (
                status,
                datetime.now(),
                data.get('reviewed_by', request.user['name']),  # 로그인한 사용자 정보 사용
                leave_id
            ))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': '해당 연차 신청을 찾을 수 없습니다.'
                }), 404
            
            connection.commit()
            
            return jsonify({
                'success': True,
                'message': f'연차가 {status}되었습니다.'
            }), 200
            
        except Error as e:
            connection.rollback()
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '상태 업데이트 중 오류가 발생했습니다.'
            }), 500
            
        finally:
            cursor.close()
            connection.close()
            
    except Exception as e:
        print(f"일반 오류: {e}")
        return jsonify({
            'success': False,
            'message': '서버 오류가 발생했습니다.'
        }), 500

@leave_bp.route('/leave/<leave_id>', methods=['GET'])
@token_required
def get_leave_detail(leave_id):
    """특정 연차 정보 조회 API"""
    try:
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor(dictionary=True)
        
        try:
            query = "SELECT * FROM leave_requests WHERE id = %s"
            cursor.execute(query, (leave_id,))
            leave = cursor.fetchone()
            
            if not leave:
                return jsonify({
                    'success': False,
                    'message': '해당 연차 신청을 찾을 수 없습니다.'
                }), 404
            
            # 날짜 필드 포맷팅
            if leave['start_date']:
                leave['start_date'] = leave['start_date'].strftime('%Y-%m-%d')
            if leave['end_date']:
                leave['end_date'] = leave['end_date'].strftime('%Y-%m-%d')
            if leave['applied_at']:
                leave['applied_at'] = leave['applied_at'].strftime('%Y-%m-%d %H:%M:%S')
            if leave['reviewed_at']:
                leave['reviewed_at'] = leave['reviewed_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify(leave), 200
            
        except Error as e:
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 정보 조회 중 오류가 발생했습니다.'
            }), 500
            
        finally:
            cursor.close()
            connection.close()
            
    except Exception as e:
        print(f"일반 오류: {e}")
        return jsonify({
            'success': False,
            'message': '서버 오류가 발생했습니다.'
        }), 500 