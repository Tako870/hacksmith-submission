from flask import Flask, render_template
app = Flask(__name__)

@app.route('/')
def index():
    return 'Future Black Hat Arsenal Exhibitors.'

@app.route('/uploadmap')
def upload_asset_map():
    return render_template('uploadMap.html')

@app.route('/rendermap')
def render_map():
    return "placeholder"

if __name__ == '__main__':
    app.run(debug=True)