from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

def create_app():
    load_dotenv()
    
    app = Flask(__name__)
    CORS(app)  # CORS 미들웨어 설정
    
    # Blueprint 등록
    from app.blueprints.auth_routes import auth_bp
    from app.blueprints.order_routes import order_bp
    from app.blueprints.inventory_routes import inventory_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(order_bp, url_prefix='/api')
    app.register_blueprint(inventory_bp, url_prefix='/api')
    
    return app 