from app import create_app
from app.config import PORT

if __name__ == '__main__':
    app = create_app()
    app.run(debug=False, port=PORT) 