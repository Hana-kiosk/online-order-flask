from flask import Blueprint, request, jsonify
from datetime import datetime, date
import uuid
from mysql.connector import Error
from app.database import get_connection
from app.auth import token_required
from app.utils import calculate_business_days, load_holidays, clear_holidays_cache, load_holidays_with_details
import csv
import os

leave_bp = Blueprint('leave', __name__)

@leave_bp.route('/leave/apply', methods=['POST'])
@token_required
def apply_leave():
    """연차 신청 API"""
    try:
        data = request.get_json()
        
        # 필수 필드 검증
        required_fields = ['userid', 'employee_name', 'leave_type', 'start_date', 'end_date']
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
        
        # 연차 유형이 '연차'인 경우에만 잔여량 검증
        if data['leave_type'] == '연차':
            # 연차 잔여량 검증을 위한 cursor 생성
            cursor_check = connection.cursor(dictionary=True)
            try:
                # 해당 연도의 연차 부여량 조회
                year = start_date.year
                balance_query = "SELECT total_granted FROM leaves WHERE user_id = %s AND year = %s"
                cursor_check.execute(balance_query, (data['userid'], year))
                balance_result = cursor_check.fetchone()
                
                if not balance_result:
                    return jsonify({
                        'success': False,
                        'message': f'{year}년도 연차 부여량이 설정되지 않았습니다. 관리자에게 문의하세요.'
                    }), 400
                
                total_granted = float(balance_result['total_granted'])
                
                # 사용된 연차 계산 (승인된 것만)
                used_query = """
                    SELECT COALESCE(SUM(days_count), 0) as used_days
                    FROM leave_requests 
                    WHERE userid = %s AND YEAR(start_date) = %s AND status = 'approved'
                """
                cursor_check.execute(used_query, (data['userid'], year))
                used_result = cursor_check.fetchone()
                used_days = float(used_result['used_days'] or 0)
                
                # 대기중인 연차 계산
                pending_query = """
                    SELECT COALESCE(SUM(days_count), 0) as pending_days
                    FROM leave_requests 
                    WHERE userid = %s AND YEAR(start_date) = %s AND status = 'pending'
                """
                cursor_check.execute(pending_query, (data['userid'], year))
                pending_result = cursor_check.fetchone()
                pending_days = float(pending_result['pending_days'] or 0)
                
                # 신청 가능한 연차량 계산
                available_days = total_granted - used_days - pending_days
                
                # 신청 일수가 사용 가능한 연차를 초과하는지 확인
                if business_days > available_days:
                    return jsonify({
                        'success': False,
                        'message': f'신청 가능한 연차가 부족합니다. (신청: {business_days}일, 사용가능: {available_days}일)',
                        'data': {
                            'total_granted': total_granted,
                            'used_days': used_days,
                            'pending_days': pending_days,
                            'available_days': available_days,
                            'requested_days': business_days
                        }
                    }), 400
                    
            finally:
                cursor_check.close()
        
        cursor = connection.cursor()
        
        try:
            # 연차 신청 데이터 삽입 (AUTO_INCREMENT이므로 id 제외)
            insert_query = """
                INSERT INTO leave_requests 
                (userid, employee_name, leave_type, start_date, end_date, reason, status, days_count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (
                data['userid'],
                data['employee_name'],
                data['leave_type'],
                start_date,
                end_date,
                data.get('reason', ''),
                'pending',
                business_days
            ))
            
            # 생성된 ID 가져오기
            leave_id = cursor.lastrowid
            
            connection.commit()
            
            # 응답에 포함할 추가 정보 계산 (연차인 경우)
            response_data = {
                'leave_id': leave_id,
                'days_count': business_days,
                'status': 'pending'
            }
            
            # 연차인 경우 잔여량 정보 추가
            if data['leave_type'] == '연차':
                cursor_info = connection.cursor(dictionary=True)
                try:
                    year = start_date.year
                    
                    # 최신 연차 정보 다시 조회
                    balance_query = "SELECT total_granted FROM leaves WHERE user_id = %s AND year = %s"
                    cursor_info.execute(balance_query, (data['userid'], year))
                    balance_result = cursor_info.fetchone()
                    total_granted = float(balance_result['total_granted'])
                    
                    used_query = """
                        SELECT COALESCE(SUM(days_count), 0) as used_days
                        FROM leave_requests 
                        WHERE userid = %s AND YEAR(start_date) = %s AND status = 'approved'
                    """
                    cursor_info.execute(used_query, (data['userid'], year))
                    used_result = cursor_info.fetchone()
                    used_days = float(used_result['used_days'] or 0)
                    
                    pending_query = """
                        SELECT COALESCE(SUM(days_count), 0) as pending_days
                        FROM leave_requests 
                        WHERE userid = %s AND YEAR(start_date) = %s AND status = 'pending'
                    """
                    cursor_info.execute(pending_query, (data['userid'], year))
                    pending_result = cursor_info.fetchone()
                    pending_days = float(pending_result['pending_days'] or 0)
                    
                    # 잔여량 정보 추가
                    response_data['leave_balance'] = {
                        'total_granted': total_granted,
                        'used_days': used_days,
                        'pending_days': pending_days,
                        'available_days': total_granted - used_days - pending_days
                    }
                    
                finally:
                    cursor_info.close()
            
            return jsonify({
                'success': True,
                'message': '연차 신청이 완료되었습니다.',
                'data': response_data
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
                    ORDER BY created_at DESC
                """
                cursor.execute(query, (userid,))
            else:
                # 모든 연차 목록 (관리자용)
                query = """
                    SELECT * FROM leave_requests 
                    ORDER BY created_at DESC
                """
                cursor.execute(query)
            
            leaves = cursor.fetchall()
            
            # 날짜 필드 포맷팅
            for leave in leaves:
                if leave['start_date']:
                    leave['start_date'] = leave['start_date'].strftime('%Y-%m-%d')
                if leave['end_date']:
                    leave['end_date'] = leave['end_date'].strftime('%Y-%m-%d')
                if leave['created_at']:
                    leave['created_at'] = leave['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                if leave['updated_at']:
                    leave['updated_at'] = leave['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
                if leave['approved_at']:
                    leave['approved_at'] = leave['approved_at'].strftime('%Y-%m-%d %H:%M:%S')
            
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

@leave_bp.route('/leave/<int:leave_id>/status', methods=['PUT'])
@token_required
def update_leave_status(leave_id):
    """연차 상태 업데이트 API (관리자용)"""
    try:
        data = request.get_json()
        status = data.get('status')
        
        if status not in ['approved', 'rejected', 'canceled']:
            return jsonify({
                'success': False,
                'message': '올바르지 않은 상태값입니다. (approved, rejected, canceled만 허용)'
            }), 400
        
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor()
        
        try:
            if status == 'approved':
                # 승인 처리
                update_query = """
                    UPDATE leave_requests 
                    SET status = %s, approver_userid = %s, approver_name = %s, approved_at = %s
                    WHERE id = %s
                """
                cursor.execute(update_query, (
                    status,
                    data.get('approver_userid', request.user.get('id')),
                    data.get('approver_name', request.user.get('name')),
                    datetime.now(),
                    leave_id
                ))
            elif status == 'rejected':
                # 반려 처리
                update_query = """
                    UPDATE leave_requests 
                    SET status = %s, approver_userid = %s, approver_name = %s, 
                        approved_at = %s, rejection_reason = %s
                    WHERE id = %s
                """
                cursor.execute(update_query, (
                    status,
                    data.get('approver_userid', request.user.get('id')),
                    data.get('approver_name', request.user.get('name')),
                    datetime.now(),
                    data.get('rejection_reason', ''),
                    leave_id
                ))
            else:  # status == 'canceled'
                # 취소 처리 (승인자 정보 없이 처리)
                update_query = """
                    UPDATE leave_requests 
                    SET status = %s, approved_at = %s, rejection_reason = %s
                    WHERE id = %s
                """
                cursor.execute(update_query, (
                    status,
                    datetime.now(),
                    data.get('rejection_reason', '사용자 취소'),
                    leave_id
                ))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': '해당 연차 신청을 찾을 수 없습니다.'
                }), 404
            
            connection.commit()
            
            status_messages = {
                'approved': '승인',
                'rejected': '반려', 
                'canceled': '취소'
            }
            status_msg = status_messages.get(status, status)
            
            return jsonify({
                'success': True,
                'message': f'연차가 {status_msg}되었습니다.'
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

@leave_bp.route('/leave/<int:leave_id>', methods=['GET'])
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
            if leave['created_at']:
                leave['created_at'] = leave['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            if leave['updated_at']:
                leave['updated_at'] = leave['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
            if leave['approved_at']:
                leave['approved_at'] = leave['approved_at'].strftime('%Y-%m-%d %H:%M:%S')
            
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

@leave_bp.route('/leaves', methods=['POST'])
@token_required
def create_leave_balance():
    """연차 부여량 생성 API"""
    try:
        data = request.get_json()
        
        # 필수 필드 검증
        required_fields = ['user_id', 'year', 'total_granted']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'{field} 필드가 누락되었습니다.'
                }), 400
        
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor()
        
        try:
            insert_query = """
                INSERT INTO leaves (user_id, year, total_granted)
                VALUES (%s, %s, %s)
            """
            
            cursor.execute(insert_query, (
                data['user_id'],
                data['year'],
                data['total_granted']
            ))
            
            leave_balance_id = cursor.lastrowid
            connection.commit()
            
            return jsonify({
                'success': True,
                'message': '연차 부여량이 생성되었습니다.',
                'data': {
                    'id': leave_balance_id,
                    'user_id': data['user_id'],
                    'year': data['year'],
                    'total_granted': data['total_granted']
                }
            }), 201
            
        except Error as e:
            connection.rollback()
            print(f"데이터베이스 오류: {e}")
            
            # 중복 키 오류 처리
            if e.errno == 1062:  # Duplicate entry
                return jsonify({
                    'success': False,
                    'message': '해당 사용자의 해당 연도 연차 부여량이 이미 존재합니다.'
                }), 409
            
            return jsonify({
                'success': False,
                'message': '연차 부여량 생성 중 오류가 발생했습니다.'
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

@leave_bp.route('/leaves', methods=['GET'])
@token_required
def get_leave_balances():
    """연차 부여량 목록 조회 API"""
    try:
        user_id = request.args.get('user_id')
        year = request.args.get('year')
        
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor(dictionary=True)
        
        try:
            # 쿼리 조건 구성
            where_conditions = []
            params = []
            
            if user_id:
                where_conditions.append("user_id = %s")
                params.append(user_id)
            
            if year:
                where_conditions.append("year = %s")
                params.append(year)
            
            # 기본 쿼리
            query = "SELECT * FROM leaves"
            
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
            
            query += " ORDER BY year DESC, user_id"
            
            cursor.execute(query, params)
            leave_balances = cursor.fetchall()
            
            return jsonify(leave_balances), 200
            
        except Error as e:
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 부여량 조회 중 오류가 발생했습니다.'
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

@leave_bp.route('/leaves/<int:leave_balance_id>', methods=['PUT'])
@token_required
def update_leave_balance(leave_balance_id):
    """연차 부여량 수정 API"""
    try:
        data = request.get_json()
        
        # 수정 가능한 필드들
        allowed_fields = ['total_granted']
        update_fields = {}
        
        for field in allowed_fields:
            if field in data:
                update_fields[field] = data[field]
        
        if not update_fields:
            return jsonify({
                'success': False,
                'message': '수정할 필드가 없습니다.'
            }), 400
        
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor()
        
        try:
            # 동적 UPDATE 쿼리 구성
            set_clause = ", ".join([f"{field} = %s" for field in update_fields.keys()])
            update_query = f"UPDATE leaves SET {set_clause} WHERE id = %s"
            
            values = list(update_fields.values()) + [leave_balance_id]
            cursor.execute(update_query, values)
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': '해당 연차 부여량을 찾을 수 없습니다.'
                }), 404
            
            connection.commit()
            
            return jsonify({
                'success': True,
                'message': '연차 부여량이 수정되었습니다.'
            }), 200
            
        except Error as e:
            connection.rollback()
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 부여량 수정 중 오류가 발생했습니다.'
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

@leave_bp.route('/leaves/<int:leave_balance_id>', methods=['DELETE'])
@token_required
def delete_leave_balance(leave_balance_id):
    """연차 부여량 삭제 API"""
    try:
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor()
        
        try:
            delete_query = "DELETE FROM leaves WHERE id = %s"
            cursor.execute(delete_query, (leave_balance_id,))
            
            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'message': '해당 연차 부여량을 찾을 수 없습니다.'
                }), 404
            
            connection.commit()
            
            return jsonify({
                'success': True,
                'message': '연차 부여량이 삭제되었습니다.'
            }), 200
            
        except Error as e:
            connection.rollback()
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 부여량 삭제 중 오류가 발생했습니다.'
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

@leave_bp.route('/leaves/<int:leave_balance_id>', methods=['GET'])
@token_required
def get_leave_balance(leave_balance_id):
    """특정 연차 부여량 조회 API"""
    try:
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor(dictionary=True)
        
        try:
            query = "SELECT * FROM leaves WHERE id = %s"
            cursor.execute(query, (leave_balance_id,))
            leave_balance = cursor.fetchone()
            
            if not leave_balance:
                return jsonify({
                    'success': False,
                    'message': '해당 연차 부여량을 찾을 수 없습니다.'
                }), 404
            
            return jsonify(leave_balance), 200
            
        except Error as e:
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 부여량 조회 중 오류가 발생했습니다.'
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

@leave_bp.route('/leaves/summary/<user_id>/<int:year>', methods=['GET'])
@token_required
def get_leave_summary(user_id, year):
    """사용자별 연차 요약 정보 조회 API"""
    try:
        connection = get_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': '데이터베이스 연결에 실패했습니다.'
            }), 500
        
        cursor = connection.cursor(dictionary=True)
        
        try:
            # 연차 부여량 조회
            balance_query = "SELECT total_granted FROM leaves WHERE user_id = %s AND year = %s"
            cursor.execute(balance_query, (user_id, year))
            balance_result = cursor.fetchone()
            
            if not balance_result:
                return jsonify({
                    'success': False,
                    'message': '해당 사용자의 해당 연도 연차 부여량이 없습니다.'
                }), 404
            
            total_granted = float(balance_result['total_granted'])
            
            # 사용한 연차 계산 (승인된 연차만)
            used_query = """
                SELECT COALESCE(SUM(days_count), 0) as used_days
                FROM leave_requests 
                WHERE userid = %s 
                AND YEAR(start_date) = %s 
                AND status = 'approved'
            """
            cursor.execute(used_query, (user_id, year))
            used_result = cursor.fetchone()
            used_days = float(used_result['used_days'] or 0)
            
            # 대기중인 연차 계산
            pending_query = """
                SELECT COALESCE(SUM(days_count), 0) as pending_days
                FROM leave_requests 
                WHERE userid = %s 
                AND YEAR(start_date) = %s 
                AND status = 'pending'
            """
            cursor.execute(pending_query, (user_id, year))
            pending_result = cursor.fetchone()
            pending_days = float(pending_result['pending_days'] or 0)
            
            # 잔여 연차 계산
            remaining_days = total_granted - used_days
            
            # 실질적 잔여 연차 계산 (대기중 연차 고려)
            effective_remaining_days = total_granted - used_days - pending_days
            
            # 신청 가능 연차량 (음수가 되지 않도록 보정)
            available_for_request = max(0, effective_remaining_days)
            
            summary = {
                'user_id': user_id,
                'year': year,
                'total_granted': total_granted,
                'used_days': used_days,
                'pending_days': pending_days,
                'remaining_days': remaining_days,                    # 공식 잔여량 (승인된 것만 차감)
                'effective_remaining_days': effective_remaining_days, # 실질 잔여량 (대기중 포함)
                'available_for_request': available_for_request,      # 실제 신청 가능량
                'utilization_rate': round((used_days / total_granted) * 100, 1) if total_granted > 0 else 0  # 사용률
            }
            
            return jsonify(summary), 200
            
        except Error as e:
            print(f"데이터베이스 오류: {e}")
            return jsonify({
                'success': False,
                'message': '연차 요약 정보 조회 중 오류가 발생했습니다.'
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

@leave_bp.route('/api/leave/cancel/<int:leave_id>', methods=['PUT'])
def cancel_leave(leave_id):
    """
    연차 신청 취소 API
    - 사용자가 자신의 pending 상태 연차 신청을 취소할 수 있습니다.
    - 취소된 연차는 잔여량에 즉시 반영됩니다.
    """
    try:
        data = request.json
        userid = data.get('userid')
        
        if not userid:
            return jsonify({'success': False, 'message': 'userid가 필요합니다.'}), 400
        
        # 데이터베이스 연결
        connection = get_connection()
        if not connection:
            return jsonify({'success': False, 'message': '데이터베이스 연결 실패'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        try:
            # 취소할 연차 정보 조회 (본인의 것이고 pending 상태인지 확인)
            select_query = """
                SELECT * FROM leave_requests 
                WHERE ID = %s AND userid = %s AND status = 'pending'
            """
            cursor.execute(select_query, (leave_id, userid))
            leave_request = cursor.fetchone()
            
            if not leave_request:
                return jsonify({
                    'success': False, 
                    'message': '취소할 수 있는 연차 신청을 찾을 수 없습니다. (본인의 대기중인 신청만 취소 가능)'
                }), 404
            
            # 연차 신청 취소 (상태를 'canceled'로 변경)
            update_query = """
                UPDATE leave_requests 
                SET status = 'canceled', updated_at = NOW()
                WHERE ID = %s
            """
            cursor.execute(update_query, (leave_id,))
            connection.commit()
            
            # 응답 데이터 준비
            response_data = {
                'leave_id': leave_id,
                'status': 'canceled',
                'canceled_days': leave_request['days_count']
            }
            
            # 연차인 경우 최신 잔여량 정보 제공
            if leave_request['leave_type'] == '연차':
                cursor_info = connection.cursor(dictionary=True)
                try:
                    year = leave_request['start_date'].year
                    
                    # 연차 잔여량 정보 조회
                    balance_query = "SELECT total_granted FROM leaves WHERE user_id = %s AND year = %s"
                    cursor_info.execute(balance_query, (userid, year))
                    balance_result = cursor_info.fetchone()
                    total_granted = float(balance_result['total_granted'])
                    
                    used_query = """
                        SELECT COALESCE(SUM(days_count), 0) as used_days
                        FROM leave_requests 
                        WHERE userid = %s AND YEAR(start_date) = %s AND status = 'approved'
                    """
                    cursor_info.execute(used_query, (userid, year))
                    used_result = cursor_info.fetchone()
                    used_days = float(used_result['used_days'] or 0)
                    
                    pending_query = """
                        SELECT COALESCE(SUM(days_count), 0) as pending_days
                        FROM leave_requests 
                        WHERE userid = %s AND YEAR(start_date) = %s AND status = 'pending'
                    """
                    cursor_info.execute(pending_query, (userid, year))
                    pending_result = cursor_info.fetchone()
                    pending_days = float(pending_result['pending_days'] or 0)
                    
                    # 잔여량 정보 추가
                    response_data['leave_balance'] = {
                        'total_granted': total_granted,
                        'used_days': used_days,
                        'pending_days': pending_days,
                        'available_days': total_granted - used_days - pending_days
                    }
                    
                finally:
                    cursor_info.close()
            
            return jsonify({
                'success': True,
                'message': '연차 신청이 취소되었습니다.',
                'data': response_data
            }), 200
            
        finally:
            cursor.close()
            connection.close()
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'연차 취소 중 오류가 발생했습니다: {str(e)}'
        }), 500

@leave_bp.route('/holidays', methods=['GET'])
@token_required
def get_holidays():
    """공휴일 목록 조회 API"""
    try:
        holidays_details = load_holidays_with_details()
        
        # 날짜를 문자열로 변환하여 정렬된 목록 반환
        holiday_list = sorted([{
            'date': holiday['date'].strftime('%Y-%m-%d'),
            'name': holiday['name'],
            'type': holiday['type']
        } for holiday in holidays_details], key=lambda x: x['date'])
        
        return jsonify({
            'success': True,
            'data': holiday_list,
            'count': len(holiday_list)
        }), 200
        
    except Exception as e:
        print(f"공휴일 조회 오류: {e}")
        return jsonify({
            'success': False,
            'message': '공휴일 목록 조회 중 오류가 발생했습니다.'
        }), 500

@leave_bp.route('/holidays/reload', methods=['POST'])
@token_required
def reload_holidays():
    """공휴일 데이터 다시 로드 API (관리자용)"""
    try:
        # 캐시 초기화
        clear_holidays_cache()
        
        # 새로 로드
        holidays = load_holidays()
        
        return jsonify({
            'success': True,
            'message': f'공휴일 데이터가 다시 로드되었습니다. ({len(holidays)}개)',
            'count': len(holidays)
        }), 200
        
    except Exception as e:
        print(f"공휴일 리로드 오류: {e}")
        return jsonify({
            'success': False,
            'message': '공휴일 데이터 리로드 중 오류가 발생했습니다.'
        }), 500 