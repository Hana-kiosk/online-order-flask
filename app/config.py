import os
from datetime import timedelta

# JWT 비밀 키 설정
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
JWT_EXPIRATION_DELTA = timedelta(days=1)  # 토큰 유효 기간 (1일)

# 서버 설정
PORT = 5000 