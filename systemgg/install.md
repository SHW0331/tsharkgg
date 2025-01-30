# apk cmd
apk update
apk add rsyslog
apk add rsyslog-tls rsyslog-omhttp
apk add build-base autoconf automake libtool curl-dev

python3 --version
pip3 --version

pip install flask
pip install request
pip install jsonify


apk add openrc 
rc-service rsyslog start

vi /etc/rsyslog.conf

# send syslog Http
# 로컬 로그를 HTTP로 전송
*.* action(
    type="omhttp"
    server="localhost"
    serverport="5000"
    url="/logs"
    template="RSYSLOG_TraditionalFileFormat"
)

# send log
logger "Test"
