from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')

def index():
    return render_template('index.html')

# app.run(debug=True) / flask run으로 실행할거면 필요하지 않다고 하는 것 같다.