from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
blog_db = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship ("Comment", back_populates="parent_post")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250),unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)

if not os.path.isfile(blog_db):
    db.create_all()

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)



def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods= ['GET','POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        user_data = User.query.filter_by(email=register_form.email.data).first()
        if not user_data:
            if register_form.password.data == register_form.password_check.data:
                email = register_form.email.data
                password = register_form.password.data
                name = register_form.name.data
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
                new_user = User(email=email, password=hashed_password, name=name)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                # return redirect (url_for('get_all_posts'))
                return redirect(url_for('get_all_posts', current_user=current_user ))
            else:
                error= "Your password in both fields must be same!"
                return render_template("register.html", error=error, register_form=register_form)
        else:
            # flash("You've already signed up with that email, log in instead!")
            error= "Your email already registered! Please login."
            return render_template("register.html", register_form=register_form, error=error)
            # return redirect(url_for('register',error=error))
    return render_template("register.html", register_form=register_form, current_user=current_user)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET','POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user_data = User.query.filter_by(email=email).first()
        if user_data:
            if check_password_hash(user_data.password, password):
                login_user(user_data)
                return redirect(url_for('get_all_posts'))
            else:
                error = 'Wrong user email or password!'
                return render_template("login.html", login_form=login_form, error=error)
        else:
            error= 'No user registered with this email'
            return render_template("login.html", login_form=login_form, error=error)
    return render_template("login.html", login_form=login_form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    all_comments = db.session.query(Comment).all()
    if comment_form.validate_on_submit():
        # if login_user(current_user):
        if current_user.is_authenticated:
            new_comment = Comment(author_id= current_user.id, post_id= requested_post.id, text= comment_form.comment.data)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id, post=requested_post, comment_form=comment_form, all_comments=all_comments))
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, comment_form=comment_form, all_comments=all_comments)


@app.route("/edit_comment/<int:comment_id>", methods=['GET','POST'])
@login_required
def edit_comment(comment_id):
    comment_picked = Comment.query.get(comment_id)
    requested_post = BlogPost.query.get(comment_picked.parent_post.id)
    all_comments = db.session.query(Comment).all()
    if current_user.id == comment_picked.author_id:
        post_id_req = comment_picked.post_id
        edit_comment = CommentForm(
            author_id = current_user.id,
            post_id = comment_picked.post_id,
            text=comment_picked.text
        )
        if edit_comment.validate_on_submit():
            comment_picked.author_id = current_user.id
            comment_picked.post_id = requested_post.id
            comment_picked.text = edit_comment.comment.data
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id_req))
            # return redirect(url_for('get_all_posts', current_user=current_user ))
        return render_template("edit_comment.html", comment_form=edit_comment, post_id=post_id_req, post=requested_post)
    else:
        return redirect(url_for('get_all_posts', current_user=current_user ))

@app.route("/delete_comment/<int:comment_id><int:post_id>", methods=['GET','POST'])
@login_required
def delete_comment(comment_id,post_id):
    comment_picked = Comment.query.get(comment_id)
    post_id_load = post_id
    print(post_id_load)
    if current_user.id == comment_picked.author_id or current_user.id == 1:
        db.session.delete(comment_picked)
        db.session.commit()
        return redirect(url_for('show_post',post_id=post_id_load))
    else:
        return redirect(url_for('get_all_posts', current_user=current_user ))



@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET','POST'])
@login_required
@admin_only
def add_new_post():
    if current_user.id == 1:
        form = CreatePostForm()
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                # author=current_user.name,
                author_id = current_user.id,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        return render_template("make-post.html", form=form)
    else:
        return redirect(url_for('get_all_posts'))


@app.route("/edit-post/<int:post_id>", methods=['GET','POST'])
@login_required
@admin_only
def edit_post(post_id):
    if current_user.id == 1:
        post = BlogPost.query.get(post_id)
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            # author=post.author,
            author_id=current_user.id,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            # post.author_id = edit_form.author.data
            post.author_id = current_user.id
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))
        return render_template("make-post.html", form=edit_form, is_edit=True)
    else:
        return redirect(url_for('get_all_posts'))

@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    if current_user.id == 1:
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))



if __name__ == "__main__":
    app.run(debug=True)
