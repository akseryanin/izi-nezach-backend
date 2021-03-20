import os
import time
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'izi-nezach'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost:5432/hse_corpus'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), unique=True, nullable=False)  # how about uniqueness !!!!!!!!!!
    user_department = db.Column(db.String(30), nullable=False)
    user_email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(80))
    user_rights = db.Column(db.Integer)

    def __repr__(self):
        return f"User('{self.user_name}', '{self.user_department}')"

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])


class Student(db.Model):
    student_id = db.Column(db.Integer, primary_key=True)  # ver 8
    student_moniker = db.Column(db.String(80), nullable=False)  # ver 9 hashed_name
    student_name = db.Column(db.String(30), nullable=False)
    student_name_latin = db.Column(db.String(30), nullable=False)
    student_sex = db.Column(db.Boolean, nullable=False)
    student_department = db.Column(db.String(30), nullable=False)
    texts = db.relationship('Text', backref='author', lazy=True)

    def __repr__(self):
        return f"Student('{self.student_name}', '{self.student_department}')"


class DB_Service_Table(db.Model):
    dict_name = db.Column(db.String(30), primary_key=True)
    dict = db.Column(db.JSON)
    misc = db.Column(db.String(500))

    def __repr__(self):
        return f"DB_Service_Table('{self.dict_name}', '{self.dict})"


class Text(db.Model):
    text_id = db.Column(db.Integer, primary_key=True)
    text_year = db.Column(db.Integer, nullable=False)
    text_name = db.Column(db.String(30), unique=True, nullable=False)
    # text_original_name = db.Column(db.String(60), unique=True, nullable=False)  # ver 9
    text_original_name = db.Column(db.String(60))  # ver 9
    text_mark = db.Column(db.String(50))
    text_date = db.Column(db.String(12))
    text_student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'))
    text_student_moniker = db.Column(db.String(80))  # ver 9
    text_student_sex = db.Column(db.String(1))  # 'f' or 'm'
    text_student_department = db.Column(db.String(120))  # make it 120
    text_ielts = db.Column(db.Boolean, nullable=False)
    text_student_study_year = db.Column(db.Integer)
    text_student_proficiency = db.Column(db.String(2))  # ver 9 A1, A2, B1, B2, C1, C2
    text_work_type = db.Column(db.Integer)  # 'exam', for example
    text_task_id = db.Column(db.String(3))  # ver 7 work type (see task_)
    text_graph_desc = db.Column(db.Boolean)
    text_words = db.Column(db.Integer)
    text_sentences = db.Column(db.Integer)  # ver 9
    text_ann_err_tags = db.Column(db.Integer)  # ver 7 re-name the field - err tags num
    text_annotated = db.Column(db.Boolean)  # ver 8 text was annotated (errors other than Spelling
    text_ann_checked = db.Column(
        db.Boolean)  # ver 9 annotations approved by editor    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'))     # ver 8 field was renamed to student_id
    sentences = db.relationship('Sentence_text', backref='in_text', cascade="save-update, delete")
    tokens = db.relationship('Tokenized_text', backref='in_text')
    mistakes = db.relationship('Mistake', backref='text_in_error',
                               cascade="save-update, delete")  # ver 7 to speed up reference to text

    # tokens = db.relationship('Tokenized_text', backref='in_text', lazy=True)

    def __repr__(self):
        return f"Text('{self.text_name}')"


class Tokenized_text(db.Model):
    text_id = db.Column(db.Integer,
                        db.ForeignKey('text.text_id'))  # need to modify the table value when adding new texts !!!!!
    paragraph_id = db.Column(db.Integer)
    sentence_id = db.Column(db.Integer, db.ForeignKey('sentence_text.sentence_id'))
    token_id = db.Column(db.Integer, primary_key=True)
    token_inx = db.Column(db.Integer, nullable=False)  # ver 5 index of a token within sentence token list
    token = db.Column(db.String(35), nullable=False)
    token_pos = db.Column(db.String(4), nullable=False)
    lemma = db.Column(db.String(35), nullable=False)
    token_dep = db.Column(db.String(10), nullable=False)  # ver 5 index see spacy 'dep'
    token_head = db.Column(db.Integer, nullable=False)  # ver 5 index see spacy 'head'
    mistakes = db.relationship('Mistake', backref='token_in_error', cascade="save-update, delete")

    def __repr__(self):
        return f"Tokenized_text('{self.text_id}', '{self.sentence_id}', '{self.token_id}', '{self.token}', '{self.token_pos}', '{self.lemma}')"


class Sentence_text(db.Model):
    text_id = db.Column(db.Integer, db.ForeignKey('text.text_id'))
    paragraph_id = db.Column(db.Integer)
    sentence_id = db.Column(db.Integer, primary_key=True)
    sentence_no = db.Column(db.Integer)  # ver 9 sentence number in the text
    sentence_tokens = db.Column(db.String(900), nullable=False)
    sentence_poses = db.Column(db.String(700), nullable=False)
    sentence_lemmas = db.Column(db.String(900), nullable=False)
    sentence_token_space_map = db.Column(db.String(145), nullable=False)  # ver 5 if token is followed by space
    sentence_token_deps = db.Column(db.String(750), nullable=False)  # ver 5 token dependencies
    sentence_token_heads = db.Column(db.String(450), nullable=False)  # ver 5 token heads
    tokens = db.relationship('Tokenized_text', backref='in_sentence', cascade="save-update, delete")
    mistakes = db.relationship('Mistake', backref='sentence_in_error',
                               cascade="save-update, delete")  # ver 8 to speed up reference to text

    def __repr__(self):
        return f"Sentence_text('{self.text_id}', '{self.sentence_id}', '{self.sentence_tokens}')"


class Mistake(db.Model):
    mistake_id = db.Column(db.Integer, primary_key=True)
    text_id = db.Column(db.Integer, db.ForeignKey('text.text_id'))  # ver 7 to speed up reference to text
    sentence_id = db.Column(db.Integer,
                            db.ForeignKey('sentence_text.sentence_id'))  # ver 8 to speed up reference to sentence
    mistake_type = db.Column(db.String(25), nullable=False)
    mistake_qualifier = db.Column(db.Integer)  # ver 10 if we decide to specify Tense
    mistake_dependent = db.Column(db.Boolean)  # ver 5 if mistake is related to other mistake
    mistake_parallel = db.Column(db.Boolean)  # ver 5 if mistake is related to other mistake
    error_span = db.Column(db.String(300))  # ver 7 mistake tokens
    error_span_poses = db.Column(db.String(240))  # ver 7 poses of the corrected mistake
    mistake_corrected = db.Column(db.Boolean)  # ver 7 if mistake was corrected
    cause = db.Column(db.String(25))
    correction_delete = db.Column(db.Boolean)  # ver 5 if correction was simple delete
    correction_tokens = db.Column(db.String(260))  # ver 6 to speed up processing
    correction_poses = db.Column(db.String(240))  # ver 6 to speed up processing
    correction_lemmas = db.Column(db.String(260))  # ver 6 to speed up processing
    correction_token_space_map = db.Column(db.String(60))  # ver 6 to speed up processing
    first_token_id = db.Column(db.Integer, db.ForeignKey('tokenized_text.token_id'))
    last_token_id = db.Column(db.Integer, nullable=False)
    corrections = db.relationship('Corrections', backref='for_mistake', cascade="save-update, delete")  # ver 6

    def __repr__(self):
        return f"Mistake('{self.sentence_id}', '{self.mistake_type}')"


class Corrections(db.Model):
    correction_id = db.Column(db.Integer, primary_key=True)
    text_id = db.Column(db.Integer)
    sentence_id = db.Column(db.Integer)
    mistake_id = db.Column(db.Integer, db.ForeignKey('mistake.mistake_id'))
    correction_token = db.Column(db.String(35), nullable=False)
    correction_pos = db.Column(db.String(4), nullable=False)
    correction_lemma = db.Column(db.String(35), nullable=False)
    correction_token_inx = db.Column(db.Integer, nullable=False)  # to restore full correction

    def __repr__(self):
        return f"Corrections('{self.mistake_id}', '{self.correction_token}', '{self.correction_pos}', " \
               f"'{self.correction_token_inx}')"


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)