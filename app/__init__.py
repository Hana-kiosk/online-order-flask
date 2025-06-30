from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

def create_app():
    load_dotenv()
    
    app = Flask(__name__)
    
    # CORS 설정 강화 - 개발환경과 운영환경 모두 지원
    CORS(app, 
         origins=[
             "http://localhost:3000",
             "http://localhost:5173", 
             "http://localhost:8080",
             "https://www.hanadesk.co.kr"  # 여기에 실제 프론트엔드 도메인을 넣어주세요
         ],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         allow_headers=["Content-Type", "Authorization"],
         supports_credentials=True
    )
    
    # preflight 요청 처리
    @app.before_request
    def handle_preflight():
        from flask import request
        if request.method == "OPTIONS":
            from flask import make_response
            res = make_response()
            res.headers['Access-Control-Allow-Origin'] = '*'
            res.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
            res.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
            return res
    
    # 헬스체크 엔드포인트
    @app.route('/health')
    def health_check():
        from flask import jsonify
        return jsonify({'status': 'healthy', 'message': 'Server is running'})
    
    @app.route('/api/health')
    def api_health_check():
        from flask import jsonify
        return jsonify({'status': 'healthy', 'message': 'API is running'})
    
    # Blueprint 등록
    from app.blueprints.auth_routes import auth_bp
    from app.blueprints.order_routes import order_bp
    from app.blueprints.inventory_routes import inventory_bp
    from app.blueprints.leave_routes import leave_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(order_bp, url_prefix='/api')
    app.register_blueprint(inventory_bp, url_prefix='/api')
    app.register_blueprint(leave_bp, url_prefix='/api')
    
    return app 