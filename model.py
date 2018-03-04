import os as a
import hashlib
from flask import Flask, current_app, render_template, request
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, AnonymousUserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Ven
from flask_mail import Mail, Message
from threading import Thread
from datetime import datetime
from flask_moment import Moment
from flask_pagedown import PageDown
from markdown import markdown
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import bleach
from flask_basicauth import BasicAuth
import flask_gravatar

#defining database path
basedir = a.path.abspath(a.path.dirname(__file__))

app = Flask(__name__)
mail = Mail(app)
moment = Moment(app)
admin = Admin(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+a.path.join(basedir, 'sociall.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['FLASKY_ADMIN'] = 'uzakari2@gmail.com'
app.config['TESTING'] = True
app.config['SECRET_KEY'] = 'You not suppose to know'
app.config['FLASKY_POSTS_PER_PAGE'] = 20
app.config['FLASKY_FOLLOWERS_PER_PAGE'] = 50
app.config['FLASKY_COMMENTS_PER_PAGE'] = 23
app.config['RECAPTCHA_PUBLIC_KEY']='6LebczEUAAAAAH2cgnbUVFK-Cwv2DrLID4xHEkC2'
app.config['RECAPTCHA_PRIVATE_KEY']='6LebczEUAAAAAGlXAFCBtN5TYv-X4cRvJkhKhuJd'

#mail server configuration
app.config.update(
    DEBUG=True,
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='uzakari2@gmail.com',
    MAIL_PASSWORD='Goodboy2'
)


boot = Bootstrap(app)

pagedown = PageDown(app)

app.config['BASIC_AUTH_USERNAME'] = 'umar'
app.config['BASIC_AUTH_PASSWORD'] = 'Goodboy2'

basic_auth = BasicAuth(app)

#initiating sqlalchemy
db = SQLAlchemy(app)

mail = Mail(app)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.init_app(app)
login_manager.login_view = 'login'


class follow(db.Model):
    __tablename__ = 'follow'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow())


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    is_confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default= datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    post = db.relationship('Post',backref='author', lazy='dynamic')
    followed = db.relationship('follow', foreign_keys=[follow.follower_id], backref=db.backref('follower', lazy='joined'),
                              lazy='dynamic',  cascade='all,delete-orphan')

    followers = db.relationship('follow', foreign_keys=[follow.followed_id],
                               backref=db.backref('followed', lazy='joined'), lazy='dynamic',
                               cascade='all,delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')
    #generating confirmation token with its dengerous meaning storing the value in self.id

    def generate_confirmation_token(self, expiration=3600):
        s = Ven(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Ven(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.is_confirmed = True
        db.session.add(self)
        return True

    @property
    def password(self):
        raise AttributeError('password is not a reasable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default2=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
            
    def change_email(self, token):
        new_email = User.query.filter_by(email=self.email).first()
        self.email = new_email
        self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True
    
    #role verification
    def can(self, permissions):
        return self.role is not None and \
               (self.role.permissions & permissions) == permissions
    
    def is_administrator(self):
        return False
    


    #dealing with last seen
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
    
    def gravatar(self, size=100, default='retro', rating='g',force_default=False,force_lower=False,use_ssl=False,base_url='http://www.gravatar.com/avatar'):
        hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{base_url}/{hash}?s={size}&d={default}&r={rating}'.format(base_url=base_url,hash=hash,size=size,default=default,rating=rating,force_default=force_default,force_lower=force_lower,use_ssl=use_ssl)

    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def follow(self, user):
        if not self.is_following(user):
            f = follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(follower_id=user.id).first() is not None


    @property
    def followed_posts(self):
        return Post.query.join(follow,follow.followed_id == Post.author_id).filter(follow.follower_id == self.id)


    def generate_auth_token(self,expiration):
        s = Ven(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dump({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Ven(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def __repr__(self):
        return '<User %r>' % self.username


#callback function given identifier
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def send_async_email(app, data):
    with app.app_context():
        mail.send(data)

#sendding data through mail function
def send_email(to, subject, template, **kwargs):
    data = Message(subject, sender='uzakari2@gmail.com', recipients=[to])
    data.body = render_template(template + '.txt', **kwargs)
    data.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, data])
    thr.start()
    return thr


class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x88
    ADMINISTER = 0x80


#class role
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default2 = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')
    
    @staticmethod
    def insert_roles():
        roles = {'User': (Permission.FOLLOW |
                         Permission.COMMENT |
                         Permission.WRITE_ARTICLES, True),
                'Moderator': (Permission.FOLLOW | Permission.COMMENT | 
                              Permission.WRITE_ARTICLES | 
                              Permission.MODERATE_COMMENTS, False),
                'Administrator':(0xff, False)
                }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]  #it get the permision in the tuple
            role.default2 = roles[r][1]
            db.session.add(role)
        db.session.commit()  
      
    def __repr__(self):
        return '<User %r> ' % (self.name)

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


class Post(db.Model):
    __tablename__='posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow())
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    body_html = db.Column(db.Text)
    
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    def __repr__(self):
        return '<Post %r> ' % (self.body)
    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentence(randint(1,3)), timestamp=forgery_py.date.date(True),author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target,value, oldvalue, initiator):
        allowed_tags = ['a','abbr','acronym','b','blockquote','code','em','i'
                        'i','li','ol','pre','strong','ul','h1','h2','h3','p','div'
                        ]
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),tags=

                                                       allowed_tags, strip=True))
db.event.listen(Post.body, 'set', Post.on_changed_body)


class Comment(db.Model):
    __tablename__='comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    
    def __repr__(self):
        return '<Comment %r> ' % (self.name)
   
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr','acronym','b','code','em','i','strong']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),tags=allowed_tags,strip=True))
db.event.listen(Comment.body,'set',Comment.on_changed_body)       
#permission class to templates


@app.context_processor
def inject_permission():
    return dict(Permission=Permission)


def create_app(config_name):
    pagedown.init_app(app)


#admin things
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Post, db.session))
admin.add_view(ModelView(Role, db.session))
admin.add_view(ModelView(follow, db.session))
admin.add_view(ModelView(Comment, db.session))


if __name__ == '__main__':
    app.run(debug=True)
