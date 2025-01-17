from flask import Blueprint, render_template

# BluePrint 정의
index_bp = Blueprint('index', __name__, template_folder='../templates/index')

# route 정의
@index_bp.route('/')
def index():
    return render_template('index.html')