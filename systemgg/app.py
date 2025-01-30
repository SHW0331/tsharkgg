from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# 로그 저장을 위한 리스트
logs = []

@app.route('/send', methods=['POST'])
def receive_log():
    data = request.get_json()
    log_message = data.get("log", "No log message received")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 로그 저장
    logs.append(f"[{timestamp}] {log_message}")
    print(f"Received log: {log_message}")  # 콘솔 출력

    return jsonify({"status": "success", "message": log_message}), 200

# 로그를 웹 페이지에서 확인
@app.route('/')
def show_logs():
    return "<h2>Received Logs</h2>" + "<br>".join(logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)