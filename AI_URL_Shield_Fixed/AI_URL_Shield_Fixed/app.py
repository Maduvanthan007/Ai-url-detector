from flask import Flask, render_template, request, jsonify
from features import analyze_url

app = Flask(__name__)

@app.get('/')
def home():
    return render_template('index.html')

@app.post('/api/scan')
def scan_url():
    data = request.get_json(silent=True) or request.form
    url = str(data.get('url', '')).strip()
    if not url:
        return jsonify({'error': 'Please enter a URL to scan.'}), 400
    if len(url) > 2048:
        return jsonify({'error': 'URL is too long to analyze.'}), 400
    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception:
        app.logger.exception('URL analysis failed')
        return jsonify({'error': 'The scanner could not analyze this URL. Please try again.'}), 500

if __name__ == '__main__':
    print('\nAI URL Shield is starting...')
    print('Open http://127.0.0.1:5000 in your browser.\n')
    app.run(host='127.0.0.1', port=5000, debug=False)
