from flask import request, jsonify
import jwt
from functools import wraps
from app.config import JWT_SECRET_KEY
from app.database import get_connection

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