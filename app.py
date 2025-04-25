import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
import bcrypt  # 상단 import 부분에 추가해줘야 함
from flask_socketio import SocketIO, join_room  # `join_room` 임포트 추가
from markupsafe import escape  # `escape` 임포트 추가
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField
import time
import datetime
from flask_talisman import Talisman

csrf = CSRFProtect()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf.init_app(app)

# 상품 검색 폼
class SearchForm(FlaskForm):
    product_name = StringField('상품 이름')

# 사용자 검색 폼
class UserSearchForm(FlaskForm):
    username = StringField('사용자 이름')



class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS 환경에서만 전송

socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*")

talisman = Talisman(app)

# 보안 헤더 설정
CSP = {
    'default-src': "'self'",
    'script-src': ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.socket.io", "'unsafe-inline'"],  # 외부 스크립트 및 인라인 스크립트 허용
    'style-src': ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],  # 인라인 스타일 허용
    'img-src': ["'self'", "https://images.example.com"],
    'font-src': ["'self'", "https://fonts.gstatic.com"],
}



talisman.content_security_policy = CSP
talisman.headers = {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
}

# HSTS 적용 (HTTPS 강제)
talisman.force_https = True

 #세션 보안 설정 추가
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # HTTPS 배포 시 True로 바꿔야 함
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


from datetime import timedelta

app.permanent_session_lifetime = timedelta(minutes=30)  # 30분 후 세션 만료

login_attempts = 0

user_last_sent = {}  # 스팸 방지용 사용자 타임스탬프

def rate_limit_check(user_id):
    current_time = time.time()
    if user_id in user_last_sent:
        if current_time - user_last_sent[user_id] < 1:  # 1초 이내에 메시지 전송 방지
            return False
    user_last_sent[user_id] = current_time
    return True


def check_login():
    global login_attempts
    if login_attempts >= 5:
        time.sleep(2)  # 2초 지연
        login_attempts = 0  # 초기화
    else:
        login_attempts += 1



# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                 is_active BOOLEAN DEFAULT 1,  -- is_active 컬럼을 추가
                balance REAL DEFAULT 0  -- 잔액 컬럼 추가
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
                       
        """)
        # 메시지 테이블 생성 (1:1 채팅을 위한 테이블)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_log (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1")
        except sqlite3.OperationalError:
            pass  # 이미 컬럼이 존재하면 넘어갑니다
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN balance REAL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # 이미 컬럼이 존재하면 오류를 무시합니다.
        db.commit()


import re
from markupsafe import escape


def validate_product_data(title, price, description):
    if not title or not description:
        return False
    if len(title) < 3 or price < 0:
        return False
    return True

def validate_product_data(title, price, description):
    if not title or not description:
        return False
    if len(title) < 3 or price < 0:
        return False
    return True


def validate_username(username):
    # 사용자명 길이 3~30자 사이
    if len(username) < 3 or len(username) > 30:
        return False
    # 영문, 숫자, 밑줄(_)만 허용
    if not re.match("^[a-zA-Z0-9_]*$", username):
        return False
    return True

def validate_password(password):
    # 비밀번호 길이 8자 이상
    if len(password) < 8:
        return False
    # 비밀번호는 영문, 숫자, 특수문자 포함 등 원하는 조건을 추가할 수 있습니다
    if not re.match("^(?=.*[a-zA-Z])(?=.*[0-9]).*$", password):
        return False
    return True

def validate_message(message):
    if len(message) > 200:  # 메시지 길이 제한
        return False
    if not re.match("^[a-zA-Z0-9\s]*$", message):  # 허용된 문자만
        return False
    return True


def sanitize_input(input_data):
    return escape(input_data)  # HTML 태그를 이스케이프 처리

def validate_report_data(target_id, reason):
    # 신고 사유는 최소 10자 이상, 최대 500자 이하
    if len(reason) < 10 or len(reason) > 500:
        return False
    
    # XSS 방어: 사용자가 입력한 내용에 HTML 태그가 포함되지 않도록 이스케이프 처리
    escaped_reason = escape(reason)

    return True

def log_report_activity(reporter_id, target_id, reason):
    db = get_db()
    cursor = db.cursor()
    log_id = str(uuid.uuid4())
    cursor.execute(
        "INSERT INTO report_log (id, reporter_id, target_id, reason, timestamp) VALUES (?, ?, ?, ?, ?)",
        (log_id, reporter_id, target_id, reason, datetime.now())
    )
    db.commit()


def check_report_abuse(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM report WHERE reporter_id = ?", (user_id,))
    report_count = cursor.fetchone()[0]
    
    if report_count > 10:  # 예시: 10건 이상 신고 시 차단
        flash('신고 남용이 감지되었습니다. 관리자에게 문의하세요.')
        return False
    return True



app.config['SECRET_KEY'] = 'your_secret_key'
#csrf = CSRFProtect(app)

class RegistrationForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')


# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')

        # bio 업데이트
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        
        # 비밀번호 변경 요청이 있을 경우
        if current_pw and new_pw:
            # 현재 비밀번호 검증
            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            if user and bcrypt.checkpw(current_pw.encode('utf-8'), user['password']):
                new_hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_hashed_pw, session['user_id']))
                flash('비밀번호가 변경되었습니다.')
            else:
                flash('현재 비밀번호가 일치하지 않습니다.')

        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    # 현재 사용자 정보 불러오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)


# 내가 등록한 상품 목록 보기
@app.route('/my-products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 사용자가 등록한 상품만 조회
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    my_items = cursor.fetchall()

    return render_template('my_products.html', products=my_items)


@app.route('/my-products/delete/<product_id>', methods=['POST'])
def delete_product_from_my_products(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품이 해당 유저의 상품인지 확인
    cursor.execute("SELECT * FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    product = cursor.fetchone()

    if product:
        # 상품 삭제
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        db.commit()
        flash('상품이 삭제되었습니다.')
    else:
        flash('해당 상품을 삭제할 권한이 없습니다.')

    return redirect(url_for('my_products'))


@app.route('/send_money', methods=['GET', 'POST'])
def send_money():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        receiver_username = request.form['receiver_username']  # 받는 사람의 username
        amount = float(request.form['amount'])  # 송금액

        # 받는 사람의 username을 기준으로 user_id 조회
        cursor.execute("SELECT id FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()

        if receiver is None:
            flash('받는 사람을 찾을 수 없습니다.')
            return redirect(url_for('send_money'))

        receiver_id = receiver['id']  # 받는 사람의 user_id

        # 송금 내역 기록
        transaction_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO transactions (id, sender_id, receiver_id, amount)
            VALUES (?, ?, ?, ?)
        """, (transaction_id, session['user_id'], receiver_id, amount))

        # 송금 처리: sender의 잔액 차감, receiver의 잔액 증가
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, session['user_id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver_id))

        db.commit()
        flash('송금이 완료되었습니다.')

        # 송금 후 잔액을 DB에서 새로 조회하여 반영
        cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
        balance = current_user['balance']

        return redirect(url_for('dashboard', balance=balance))  # 대시보드로 리디렉션

    return render_template('send_money.html')




@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.args.get('query', '')
    db = get_db()
    cursor = db.cursor()

    # 상품 제목과 설명에서 검색
    cursor.execute("""
        SELECT * FROM product WHERE title LIKE ? OR description LIKE ?
    """, ('%' + query + '%', '%' + query + '%'))
    products = cursor.fetchall()

    return render_template('search_results.html', products=products)


# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 비밀번호 해싱
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')


# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        # 비밀번호는 해시값만 가져와서 비교해야 함
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and user['is_active'] == 0:
            flash('이 계정은 휴면 상태입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')
# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 폼 객체 생성
    product_form = SearchForm()
    user_form = UserSearchForm()

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 유저 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 현재 유저의 잔액 가져오기
    balance = current_user['balance']

    # 상품 목록 검색 (상품명 기준으로)
    search_query_product = ''
    if product_form.validate_on_submit():  # 폼이 제출되었을 때만
        search_query_product = product_form.product_name.data
    if search_query_product:
        cursor.execute("SELECT * FROM product WHERE title LIKE ?", ('%' + search_query_product + '%',))
    else:
        cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()

    # 사용자 목록 검색 (username을 기준으로)
    search_query = ''
    if user_form.validate_on_submit():  # 폼이 제출되었을 때만
        search_query = user_form.username.data
    if search_query:
        cursor.execute("SELECT * FROM user WHERE username LIKE ?", ('%' + search_query + '%',))
    else:
        cursor.execute("SELECT * FROM user WHERE id != ?", (session['user_id'],))  # 현재 유저 제외
    users = cursor.fetchall()

    return render_template('dashboard.html', form=product_form, user_form=user_form, products=all_products, user=current_user, balance=balance, users=users)



# 프로필 페이지: bio 업데이트 가능

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        price = request.form['price']

        # 입력 검증 (description 포함)
        if not validate_product_data(title, price, description):
            flash("상품 제목, 가격, 설명을 정확히 입력해주세요.")
            return redirect(url_for('new_product'))
        
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        escaped_description = escape(description)  # HTML 태그 및 스크립트 코드 이스케이프
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
     if not validate_message(data['message']):
        return 
     data['message_id'] = str(uuid.uuid4())
     send(data, broadcast=True)



# 1:1 채팅방 라우트
@app.route('/chat/<receiver_id>', methods=['GET', 'POST'])
def private_chat(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상대방 유저 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()
    if not receiver:
        flash('대상을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 기존 채팅 내역 불러오기
    cursor.execute("""
        SELECT * FROM message
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], receiver_id, receiver_id, session['user_id']))
    chat_history = cursor.fetchall()

    return render_template('private_chat.html', receiver=receiver, chat_history=chat_history)



def make_private_room(user1, user2):
    return '_'.join(sorted([user1, user2]))  # 두 사용자 ID로 고유한 방 ID 생성

# 소켓에서 채팅방 참여
@socketio.on('join_private', namespace='/')
def join_private(data):
    if 'user_id' not in session:
        return
    room = make_private_room(session['user_id'], data['room'])
    join_room(room)

# 1:1 채팅 메시지 전송 처리
@socketio.on('send_private_message', namespace='/')
def send_private_message(data):
    if 'user_id' not in session:
        return

    sender_id = session['user_id']
    receiver_id = data.get('to')
    message = escape(data.get('message', '').strip())

    if not message or len(message) > 200:
        return

    db = get_db()
    cursor = db.cursor()
    msg_id = str(uuid.uuid4())

    # 메시지 DB에 저장
    cursor.execute("INSERT INTO message (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)",
                   (msg_id, sender_id, receiver_id, message))
    db.commit()

    # 해당 채팅방으로 메시지 전송
    room = make_private_room(sender_id, receiver_id)
    socketio.emit('private_message', {
        'from': sender_id,
        'message': message
    }, room=room, namespace='/')



@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or not is_admin(session['user_id']):
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 모든 유저와 상품 조회
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    return render_template('admin_dashboard.html', users=users, products=products)

@app.route('/admin/update_balance/<user_id>', methods=['POST'])
def update_balance(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        return redirect(url_for('login'))  # 관리자 인증

    new_balance = request.form['new_balance']  # 입력된 새로운 잔액

    db = get_db()
    cursor = db.cursor()

    # 유저의 잔액 수정
    cursor.execute("UPDATE user SET balance = ? WHERE id = ?", (new_balance, user_id))
    db.commit()

    flash('유저의 잔액이 수정되었습니다.')

    return redirect(url_for('admin_dashboard'))  # 대시보드로 리디렉션


def is_admin(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return user['username'] == 'admin'  # 예시: 관리자 계정만 처리


@app.route('/admin/activate_user/<user_id>', methods=['POST'])
def activate_user(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_active = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash('유저가 활성화 상태로 전환되었습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/deactivate_user/<user_id>', methods=['POST'])
def deactivate_user(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash('유저가 휴면 상태로 전환되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_product/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

def make_private_room(user1, user2):
    return '_'.join(sorted([user1, user2]))  # 두 사용자 ID로 고유한 방 ID 생성


@socketio.on('join_private', namespace='/')
def join_private(data):
    if 'user_id' not in session:
        return
    room = make_private_room(session['user_id'], data['room'])
    join_room(room)  # 해당 채팅방에 참여


@socketio.on('send_private_message', namespace='/')
def send_private_message(data):
    if 'user_id' not in session:
        return

    sender_id = session['user_id']
    receiver_id = data.get('to')
    message = escape(data.get('message', '').strip())

    if not message or len(message) > 200:
        return

    db = get_db()
    cursor = db.cursor()
    msg_id = str(uuid.uuid4())

    # 메시지 DB에 저장
    cursor.execute("INSERT INTO message (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)",
                   (msg_id, sender_id, receiver_id, message))
    db.commit()

    room = make_private_room(sender_id, receiver_id)
    socketio.emit('private_message', {
        'from': sender_id,
        'message': message
    }, room=room, namespace='/')  # 채팅방에 메시지 전송




@app.errorhandler(500)
def internal_error(error):
    return "Internal Server Error. Please try again later.", 500





if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
    # ssl_context='adhoc'