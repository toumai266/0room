from flask import Flask, render_template, request, jsonify
from zxcvbn import zxcvbn
import requests
import socket
from urllib.parse import urlparse
import os

app = Flask(__name__)

# 피싱 데이터베이스 로드
phishing_db = set()
try:
    db_path = os.path.join(os.path.dirname(__file__), 'data', 'phishing_db.txt')
    if os.path.exists(db_path):
        with open(db_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    phishing_db.add(line.lower())
        print(f"Loaded {len(phishing_db)} phishing domains.")
    else:
        print("Warning: Phishing database file not found.")
except Exception as e:
    print(f"Warning: Could not load phishing database: {e}")

def check_password_strength(password):
    result = zxcvbn(password)
    score = result['score'] # 0-4
    
    # 점수를 등급으로 매핑
    if score < 2:
        rating = "약함(Weak)"
        css_class = "weak"
    elif score < 4:
        rating = "보통(Medium)"
        css_class = "medium"
    else:
        rating = "매우 강함(Strong)"
        css_class = "strong"
        
    # 피드백을 한국어로 번역
    feedback_trans = {
        "warning": "",
        "suggestions": []
    }
    
    # 경고 메시지 번역 맵
    warning_map = {
        "Straight rows of keys are easy to guess": "키보드에서 연속된 키 배열(예: qwerty)은 추측하기 쉽습니다.",
        "Short keyboard patterns are easy to guess": "짧은 키보드 패턴은 추측하기 쉽습니다.",
        "Repeats like \"aaa\" are easy to guess": "'aaa'와 같은 반복 문자는 추측하기 쉽습니다.",
        "Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\"": "반복되는 패턴은 보안에 취약합니다.",
        "Sequences like abc or 6543 are easy to guess": "abc나 6543 같은 연속된 문자/숫자는 피해야 합니다.",
        "Recent years are easy to guess": "최근 연도(2020, 2021 등)는 추측하기 쉽습니다.",
        "Dates are often easy to guess": "생일이나 기념일 같은 날짜는 피하는 것이 좋습니다.",
        "Top 10 common passwords": "세계에서 가장 많이 쓰이는 10대 비밀번호 중 하나입니다.",
        "Top 100 common passwords": "매우 자주 사용되는 비밀번호입니다. 즉시 변경하세요.",
        "Very common passwords": "매우 흔한 비밀번호입니다.",
        "Similar to a common password": "흔한 비밀번호입니다.",
        "A word by itself is easy to guess": "단어 하나만 사용하는 것은 위험합니다.",
        "Names and surnames by themselves are easy to guess": "이름이나 성만 사용하는 것은 위험합니다.",
        "Common names and surnames are easy to guess": "흔한 이름은 쉽게 추측할 수 있습니다.",
        
        # 전체 문장 변형 (마침표 유무 포함)
        "This is a top-10 common password": "세계에서 가장 많이 쓰이는 10대 비밀번호 중 하나입니다.",
        "This is a top-100 common password": "매우 자주 사용되는 비밀번호입니다. 즉시 변경하세요.",
        "This is a very common password": "매우 흔한 비밀번호입니다.",
        "This is similar to a commonly used password": "흔한 비밀번호입니다."
    }
    
    original_warning = result['feedback']['warning']
    
    # 견고한 번역 조회
    translated_warning = None
    if original_warning:
        # 1. 정확한 일치 시도
        translated_warning = warning_map.get(original_warning)
        
        # 2. 찾을 수 없는 경우, 끝의 마침표 제거 시도
        if not translated_warning and original_warning.endswith('.'):
            translated_warning = warning_map.get(original_warning[:-1])
            
        # 3. 찾을 수 없는 경우, 끝에 마침표 추가 시도
        if not translated_warning and not original_warning.endswith('.'):
            translated_warning = warning_map.get(original_warning + '.')
            
        feedback_trans['warning'] = translated_warning if translated_warning else original_warning
    
    # 제안 메시지 번역 맵
    suggestion_map = {
        "Add another word or two. Uncommon words are better.": "단어를 한두 개 더 추가하세요. 흔하지 않은 단어가 좋습니다.",
        "Use a longer keyboard pattern with more turns.": "더 길고 복잡한 키보드 패턴을 사용하세요.",
        "Avoid repeated words and characters.": "반복되는 단어나 문자를 피하세요.",
        "Avoid sequences.": "연속된 문자나 숫자를 피하세요.",
        "Avoid recent years.": "최근 연도를 포함하지 마세요.",
        "Avoid years that are associated with you.": "본인과 관련된 연도를 피하세요.",
        "Avoid dates and years that are associated with you.": "본인과 관련된 날짜나 연도를 피하세요.",
        "Capitalization doesn't help very much.": "대문자만으로는 충분하지 않습니다.",
        "All-uppercase is almost as easy to guess as all-lowercase.": "모두 대문자로 쓰는 것은 소문자만큼이나 추측하기 쉽습니다.",
        "Reversed words are not much harder to guess.": "단어를 거꾸로 쓰는 것도 추측하기 어렵지 않습니다.",
        "Predictable substitutions like '@' instead of 'a' don't help very much.": "'a' 대신 '@'를 쓰는 것 같은 뻔한 치환은 도움이 되지 않습니다."
    }
    
    for suggestion in result['feedback']['suggestions']:
        feedback_trans['suggestions'].append(suggestion_map.get(suggestion, suggestion))

    # 점수가 낮은 경우 일반적인 OWASP 가이드라인 추가
    if score < 3:
        feedback_trans['suggestions'].append("[OWASP 권장] 최소 12자 이상의 길이를 사용하세요.")
        feedback_trans['suggestions'].append("[OWASP 권장] 특수문자, 숫자, 대소문자를 섞어서 사용하세요.")
        
    # 해킹 소요 시간 표시
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    
    # 해킹 소요 시간 번역
    time_translations = {
        "less than a second": "1초 미만",
        "seconds": "초",
        "minutes": "분",
        "hours": "시간",
        "days": "일",
        "months": "개월",
        "years": "년",
        "centuries": "1세기 이상"
    }
    
    for en, ko in time_translations.items():
        crack_time = crack_time.replace(en, ko)
    
    return rating, css_class, feedback_trans, crack_time

def expand_url(short_url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(short_url, headers=headers, timeout=5, allow_redirects=True)
        return response.url, response.status_code, None
    except requests.exceptions.Timeout:
        return None, None, "사이트 응답 시간이 초과되었습니다. (Timeout)"
    except requests.exceptions.ConnectionError:
        return None, None, "사이트에 접속할 수 없습니다. 도메인이 존재하지 않거나 서버가 다운되었습니다."
    except requests.exceptions.TooManyRedirects:
        return None, None, "리다이렉트 횟수가 너무 많습니다. (순환 참조 가능성)"
    except Exception as e:
        return None, None, f"오류가 발생했습니다: {str(e)}"

def check_malicious(url):
    # 실제 악성 여부 확인을 위한 자리 표시자
    # 실제 시나리오에서는 Google Safe Browsing API 또는 VirusTotal API를 호출합니다.
    suspicious_keywords = ['login', 'signin', 'bank', 'account', 'update', 'verify', 'secure', 'bonus', 'free', 'crypto', 'wallet', 'phishing', 'phish']
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # 포트가 있는 경우 제거
        if ':' in domain:
            domain = domain.split(':')[0]
            
        full_url_lower = url.lower()
        
        # 1. 피싱 데이터베이스와 대조 확인
        if domain in phishing_db:
            return "위험 (피싱 데이터베이스에 등록됨)"
        
        # IP 주소 사용 여부 확인
        try:
            socket.inet_aton(domain)
            return "의심됨 (IP 주소 직접 사용)"
        except socket.error:
            pass
            
        # 전체 URL에서 의심스러운 키워드 확인 (도메인뿐만 아니라)
        for keyword in suspicious_keywords:
            if keyword in full_url_lower:
                return f"의심됨 ('{keyword}' 키워드 발견)"
                
        return "안전함"
    except:
        return "알 수 없음"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/password-check', methods=['GET', 'POST'])
def password_check():
    strength = None
    css_class = None
    feedback = None
    crack_time = None
    password = None
    
    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            strength, css_class, feedback, crack_time = check_password_strength(password)
            
    return render_template('password_check.html', strength=strength, css_class=css_class, feedback=feedback, crack_time=crack_time, password=password)

@app.route('/api/password-check', methods=['POST'])
def api_password_check():
    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({'error': '비밀번호를 입력해주세요.'}), 400
    
    if len(password) > 30:
        return jsonify({'error': '비밀번호는 30자를 초과할 수 없습니다.'}), 400
    
    try:
        strength, css_class, feedback, crack_time = check_password_strength(password)
    except ValueError as e:
        return jsonify({'error': '비밀번호 검사 중 오류가 발생했습니다: ' + str(e)}), 400
    
    return jsonify({
        'strength': strength,
        'css_class': css_class,
        'feedback': feedback,
        'crack_time': crack_time,
        'password': password
    })

@app.route('/api/url-expander', methods=['POST'])
def api_url_expander():
    data = request.get_json()
    input_url = data.get('url')
    
    if not input_url:
        return jsonify({'error': 'URL을 입력해주세요.'}), 400
        
    if not input_url.startswith(('http://', 'https://')):
        input_url = 'http://' + input_url
    
    # 입력된 URL의 안전성 먼저 확인
    safety_status = check_malicious(input_url)
    
    final_url, status_code, error = expand_url(input_url)
    
    # 확장이 성공하면 최종 URL도 확인 (다를 수 있음)
    if not error and final_url and final_url != input_url:
        final_safety = check_malicious(final_url)
        # 최종 URL이 입력 URL보다 위험하면 최종 URL 결과 사용.
        # 간단한 로직: 둘 중 하나라도 안전하지 않으면 안전하지 않은 것을 표시.
        if final_safety != "안전함":
            safety_status = final_safety

    # 연결 오류가 있어도 200 OK 반환,
    # 프론트엔드에서 안전 상태와 오류 메시지를 함께 표시할 수 있도록 함.
    return jsonify({
        'final_url': final_url if final_url else input_url,
        'status_code': status_code,
        'error': error,
        'safety_status': safety_status,
        'input_url': input_url
    })

@app.route('/url-expander', methods=['GET', 'POST'])
def url_expander():
    final_url = None
    status_code = None
    error = None
    input_url = None
    
    if request.method == 'POST':
        input_url = request.form.get('url')
        if input_url:
            if not input_url.startswith(('http://', 'https://')):
                input_url = 'http://' + input_url
            final_url, status_code, error = expand_url(input_url)
            
    return render_template('url_expander.html', final_url=final_url, status_code=status_code, error=error, input_url=input_url)

if __name__ == '__main__':
    app.run(debug=True)