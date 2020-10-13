from bug_tracker import app
from livereload import Server

if __name__ == '__main__':
    app.debug=1
    server = Server(app.wsgi_app)
    server.serve()
