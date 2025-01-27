from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.utils.analysis import *
from datetime import datetime
import os

# BluePrint 정의
report_bp = Blueprint('report', __name__, template_folder='../templates/report')

# upload dir 설정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, '../upload/')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# route 정의
@report_bp.route('/report', methods=['POST'])
def report():
    if 'file' not in request.files:  # 'file'이 폼 데이터에 포함되어 있는지 확인
        flash('No file part in the request', 'error')
        return render_template('error.html')  # 업로드 후 다시 렌더링

    file = request.files['file']
    if file.filename == '':  # 파일명이 비어 있는지 확인
        flash('No file selected', 'error')
        return render_template('error.html')  # 업로드 후 다시 렌더링

    if file and allowed_file(file.filename):  # 유효한 파일인지 
        # file name 
        current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{current_time}.{file_extension}"

        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)  # 파일 저장

        # 패킷 분석
        pcap_data = tshark_subporcess(filepath)
        pcap_json = tshark_json(pcap_data)
        pcap_counts = tshark_counts(pcap_json)
        
        return render_template('report.html', data=pcap_counts)  # 업로드 후 다시 렌더링

    flash('Invalid file type. Only .pcap or .pcapng files are allowed.', 'error')
    return render_template('error.html')  # 업로드 후 다시 렌더링