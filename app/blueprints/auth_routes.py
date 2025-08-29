from flask import Blueprint, request, jsonify
from datetime import datetime
import jwt
import bcrypt
from app.config import JWT_SECRET_KEY, JWT_EXPIRATION_DELTA
from app.database import get_connection
from app.auth import token_required

auth_bp = Blueprint('auth', __name__)

# 로그인 API
@auth_bp.route('/login', methods=['POST'])
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
@auth_bp.route('/me', methods=['GET'])
@token_required
def get_current_user():
    return jsonify(request.user)

# 테스트용 라우트들
@auth_bp.route('/test-password/<password>', methods=['GET'])
def test_password(password):
    stored_hash = '$2b$10$rXfI/6Pl1K5YhZKQr1aZkeu7ZXmOJinp6bJlBZKm2MfU7eR7UWi8a'
    is_valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    return jsonify({'password': password, 'is_valid': is_valid})

@auth_bp.route('/generate-password-hash/<password>', methods=['GET'])
def generate_password_hash(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return jsonify({
        'password': password,
        'hashed': hashed.decode('utf-8')
    }) 