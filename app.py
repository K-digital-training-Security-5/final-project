from flask import Flask, render_template, request, redirect, url_for
import os
import yara
import magic
import hashlib
import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.template_filter('datetime')
def datetime_filter(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

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
    if filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        yara_results, file_info = apply_yara_rules(file_path)
        return render_template('file_result.html', filename=filename, results=yara_results, file_info=file_info)
    else:
        return "파일이 업로드되지 않았습니다."

@app.route('/url_result')
def url_result():
    url = request.args.get('url')
    return render_template('url_result.html', url=url)

def apply_yara_rules(filepath):
    rule_source = '''
    rule HiddenTear {
        meta:
            description = "Detects HiddenTear ransomware"
            author = "YourName"
            date = "2024-07-09"
            reference = "https://github.com/goliate/hidden-tear"
        strings:
            $a = "hidden tear"
            $b = "SEND ME BITCOIN"
            $c = "Files has been encrypted with hidden tear"
            $d = "Send me some bitcoins or kebab"
            $e = { 48 69 64 64 65 6E 20 54 65 61 72 } // Hidden Tear in hex
            $f = "System.Security.Cryptography.RijndaelManaged"
            $g = "System.Security.Cryptography.SHA256"
            $h = "System.Windows.Forms"
        condition:
            any of them
    }
    '''
    rule = yara.compile(source=rule_source)
    matches = rule.match(filepath=filepath)

    # 파일 형식 및 크기 정보
    file_type = magic.from_file(filepath, mime=True)
    file_size = os.path.getsize(filepath)
    file_name = os.path.basename(filepath)
    file_creation_time = os.path.getctime(filepath)
    file_modification_time = os.path.getmtime(filepath)
    file_access_time = os.path.getatime(filepath)
    file_permissions = oct(os.stat(filepath).st_mode)[-3:]
    
    # 파일 해시 값 계산
    def calculate_hash(file_path, hash_type):
        hash_func = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    file_hashes = {
        'md5': calculate_hash(filepath, 'md5'),
        'sha1': calculate_hash(filepath, 'sha1'),
        'sha256': calculate_hash(filepath, 'sha256')
    }

    file_info = {
        'name': file_name,
        'type': file_type,
        'size': file_size,
        'creation_time': file_creation_time,
        'modification_time': file_modification_time,
        'access_time': file_access_time,
        'permissions': file_permissions,
        'hashes': file_hashes
    }

    return matches, file_info

if __name__ == '__main__':
    app.run(debug=True)
