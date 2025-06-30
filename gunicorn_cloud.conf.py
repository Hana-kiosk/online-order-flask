import os

# 서버 소켓 - 클라우드 환경에서는 반드시 0.0.0.0으로 바인딩
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"
backlog = 2048

# 워커 프로세스 (클라우드 환경에 맞게 조정)
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 5

# 요청 처리
max_requests = 1000
max_requests_jitter = 100

# 로깅 (클라우드 환경에서는 stdout/stderr로)
accesslog = "-"
errorlog = "-"
loglevel = "info"

# 프로세스 이름
proc_name = "online_order_flask"

# 클라우드 환경에서는 리로드 비활성화
reload = False

# 보안 설정
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190 