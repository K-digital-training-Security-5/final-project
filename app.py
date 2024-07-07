from flask import Flask, render_template, request, redirect, url_for
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            return redirect(url_for('file_result', filename=file.filename))
    return redirect(url_for('home'))

@app.route('/submit_url', methods=['POST'])
def submit_url():
    if 'url' in request.form:
        url = request.form['url']
        if url != '':
            return redirect(url_for('url_result', url=url))
    return redirect(url_for('home'))

@app.route('/file_result')
def file_result():
    filename = request.args.get('filename')
    return render_template('file_result.html', filename=filename)

@app.route('/url_result')
def url_result():
    url = request.args.get('url')
    return render_template('url_result.html', url=url)

if __name__ == '__main__':
    app.run(debug=True)
