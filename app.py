
from flask import Flask, render_template, request
from analyzer import analyze_log
app = Flask(__name__)
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['logfile']
        # Call the analysis function
        results = analyze_log(file)
        return render_template('dashboard.html', data=results)
    return render_template('index.html')

