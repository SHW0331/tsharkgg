from flask import Flask

def create_app():
    app = Flask(__name__)

    # secret_key 설정
    app.secret_key = 'shw98'

    # BluePrint 등록
    from .routes.index import index_bp
    from .routes.report import report_bp

    app.register_blueprint(index_bp)
    app.register_blueprint(report_bp)

    return app
    