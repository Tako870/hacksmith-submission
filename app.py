from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return 'Future Black Hat Arsenal Exhibitors.'

if __name__ == '__main__':
    app.run(debug=True)