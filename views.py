from flask import render_template, redirect, request, url_for, flash, session, abort, current_app,make_response
from flask_login import login_user
from decorators import admin_required, permission_required
from model import User, db, send_email, Role, Post, Comment
from forms import LoginForm, RegistrationForm, EditProfileForm, EditProfileAdminForm, PostForm,CommentForm
from model import app, Permission
from flask_login import logout_user, login_required, current_user


#protection against csrf
app.config['SECRET_KEY'] = 'Ultimate Goodboy'  # protection crsf


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('home'))
        flash('Invalid Username or password.')
    return render_template('login.html', form=form)


@app.route('/index', methods=['GET', 'POST'])
def home():
        form = PostForm()
        if current_user.can(Permission.WRITE_ARTICLES) and form.validate_on_submit():
            post = Post(body=form.body.data, author=current_user._get_current_object())
            db.session.add(post)
            return redirect(url_for('home'))
        page = request.args.get('page', 1, type=int)
        show_followed = False
        if current_user.is_authenticated:
            show_followed = bool(request.cookies.get('show_followed',''))
        if show_followed:
            query = current_user.followed_posts
        else:
            query = Post.query
        #rendering data on page
        pagination = query.order_by(Post.timestamp.desc()).paginate(page,per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],error_out=False)
        posts = pagination.items
        return render_template('index.html', form=form, posts=posts, show_followed=show_followed, pagination=pagination)


@app.route('/register/', methods=['GET', 'POST'])
def register():

        form = RegistrationForm()
        if form.validate_on_submit():
          user = User(email=form.email.data,
                    username=form.userName.data,
                    password=form.password.data
                        )
          db.session.add(user)
          db.session.commit()#had to added for none delay
          token = user.generate_confirmation_token()
          send_email(user.email, 'Confirmed Your Account', 'confirm', user=user, token=token)
          flash('A confirmation has been sent to you by email.')
          return redirect(url_for('home'))
        return render_template('register.html', form=form)


@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.is_confirmed:
        return redirect(url_for('home'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('home'))


@app.before_first_request
def before_request():
    catch = ['login', 'unconfirmed', 'index.html', 'resend_confirmation', 'logout', 'register', 'user', 'editProfile']
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.is_confirmed and request.endpoint not in catch:
            return redirect(url_for('unconfirmed'))


@app.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.is_confirmed:
        return redirect(url_for('home'))
    else:
      return render_template('unconfirmed.html')


#route to profile for each user
@app.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts = user.post.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)

#route to edit profile
@app.route('/editProfile', methods=['GET','POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your Profile has been updated')
        return redirect(url_for('user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('editProfile.html', form=form)


@app.route('/editProfile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confimed = form.confimed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('Your profile has been updated')
        return redirect(url_for('user',username=user.username))
    form.email.data = user.email
    form.name.data = user.name
    form.confimed.data = user.is_confirmed
    form.role.data = user.role
    form.username.data = user.username
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('editProfile.html', form=form, user=user)

@app.route('/post/<int:id>', methods=['GET','POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,post=post,author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published')
        return redirect(url_for('post',id = post.id, page=-1))
    page = request.args.get('page',1,type=int)
    if page == -1:
        page = (post.comments.count()-1)/current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(page,per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],error_out=False)
    comments = pagination.items
    return  render_template('post2.html', posts=[post], form=form, comments=comments,pagination=pagination)


#edit the existing post or update it
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author_id and not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated.')
        return redirect(url_for('post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)

@app.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User.')
        return redirect(url_for('home'))
    if current_user.is_following(user):
        flash('You are already following this user')
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    flash('You are now following %s. '% username)
    return redirect(url_for('user',username=username))

@app.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User')
        return redirect(url_for('home'))
    if not current_user.is_following(user):
        flash('You are not following this user')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    flash('You are not following this %s anymore '% username)
    return redirect(url_for('user', username=username))

@app.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User. ')
        return redirect(url_for('home'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'], error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('followers.html', user=user, title='followers of ', endpoint='followers', pagination=pagination, follows=follows)


@app.route('/following/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User')
        return redirect(url_for('home'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp} for item in pagination.items]
    return render_template('followers.html', user=user, title='People You follow ', endpoint='followed_by', pagination=pagination, follows=follows)



@app.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp


@app.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('show_followed','1', max_age=30*24*60*60)
    return resp

@app.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account','confirm', user=user, token=token)
    flash('A new confirmation email has been sent to you by email')
    return redirect(url_for('home'))


@app.route("/")
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for("login"))


if __name__ == '__main__':
    app.run(debug=True,port=5559)
