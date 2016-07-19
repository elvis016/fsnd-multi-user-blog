import webapp2
import jinja2
import os
import time
import re
import random
from string import letters
import hashlib
import hmac

from google.appengine.ext import ndb

HTML_DIR = os.path.join(os.path.dirname(__file__), 'html')
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(HTML_DIR),
    autoescape=True)

# Regular expression to verify the format of username, password, and email
# \S Matches any non-whitespace character;
# ^ Matches at the beginning of lines.
# $ Matches at the end of a line, which is defined as either the end of the
# string, or any location followed by a newline character.
SECRET = 'imsosecret'  # secret code used for generating cookie
USER_RE = re.compile(r'^[\w-]{3,20}$')
PASS_RE = re.compile(r'^.{3,20}$')
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def users_key(group='default'):
    '''
    Constructs a Datastore key for a User entity.
    Use group as the key.
    '''
    return ndb.Key('users', group)


def make_salt(length=5):
    return ''.join(random.sample(letters, 5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()  # h is hashed password
    return '%s,%s' % (salt, h)


def valid_pw(name, password, pw_hash):
    salt = pw_hash.split(',')[0]   # h is hashed password
    return pw_hash == make_pw_hash(name, password, salt)


def make_secure_val(val):  # val is user_id
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]  # val is user_id
    if secure_val == make_secure_val(val):
        return val


class User(ndb.Model):
    '''
    A model for representing an user.
    '''
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        name_query = User.query(User.name == name).get()
        return name_query

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(
            parent=users_key(), name=name,
            pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name, pw, user.pw_hash):
            return user


class Handler(webapp2.RequestHandler):
    '''
    Main Handler
    '''
    def write(self, *arg, **params):
        self.response.out.write(*arg, **params)

    def render_str(self, template, **params):
        t = JINJA_ENVIRONMENT.get_template(template)
        return t.render(params)

    def render(self, tempalte, **params):
        self.write(self.render_str(tempalte, **params))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        userID = self.read_secure_cookie('user_id')
        self.user = userID and User.by_id(int(userID))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class MainPage(Handler):
    def get(self):
        self.render('index.html')


class SignUp(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # define a dictionary of paramaters fetched back to signup.html
        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = 'This is not a vaild username'
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = 'This is not a vaild password'
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = 'Password did not match'
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = 'This is not a vaild email'
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *arg, **kw):
        raise NotImplementedError


class Register(SignUp):
    """docstring for Register"""
    def done(self):
        # make sure the user doesn't already exist
        user = User.by_name(self.username)
        if user:
            msg = 'Username already exists'
            self.render(
                'signup.html', username=self.username, error_username=msg)
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            self.redirect('/welcome')


class Welcome(Handler):
    """docstring for We"""
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class SignIn(Handler):
    """docstring for We"""
    def get(self):
        self.render('signin.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('signin.html', error=msg)


class SignOut(Handler):
    """docstring for SignOut"""
    def get(self):
        self.logout()
        self.redirect('/welcome')


def blog_key(topic='default'):
    '''
    Constructs a Datastore key for a BlogPost entity.
    Use topic as the key.
    '''
    return ndb.Key('blogs', topic)


class BlogPost(ndb.Model):
    '''
    A model for representing individual blog post.
    '''
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    like = ndb.IntegerProperty(required=True)
    dislike = ndb.IntegerProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self._render_text


class PostComment(ndb.Model):
    '''
    A model for representing a comment.
    '''
    blog = ndb.KeyProperty(kind=BlogPost)
    comment = ndb.TextProperty(required=True)
    author = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    like = ndb.IntegerProperty(required=True)
    dislike = ndb.IntegerProperty(required=True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return self._render_text


class NewPost(Handler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/signin')

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            post = BlogPost(
                        parent=blog_key(),
                        subject=subject,
                        content=content,
                        author=author,
                        like=0,
                        dislike=0)
            post.put()

            self.redirect('/blog/%s' % str(post.key.id()))
        else:
            error = "subject and content, please!"
            self.render(
                'newpost.html', subject=subject, content=content, error=error)


class PostPage(Handler):
    def get(self, post_id):
        post_key = ndb.Key('BlogPost', int(post_id), parent=blog_key())
        post = post_key.get()

        if not post:
            self.error(404)
            return

        self.render("post.html", post=post)


class EditPost(Handler):
    def get(self, post_id):
        post = BlogPost.get_by_id(int(post_id), parent=blog_key())
        if self.user and self.user.name == post.author:
            self.render('editpost.html', post=post)
        else:
            self.redirect('/signin')

    def post(self, post_id):
        content = self.request.get('content')
        post = BlogPost.get_by_id(int(post_id), parent=blog_key())
        post.content = content
        post.put()
        time.sleep(.1)
        self.redirect('/blog')


class DeletePost(Handler):
    def get(self, post_id):
        post = BlogPost.get_by_id(int(post_id), parent=blog_key())
        if self.user and self.user.name == post.author:
            self.render('deletepost.html', post=post)
        else:
            self.redirect('/blog')

    def post(self, post_id):
        post = BlogPost.get_by_id(int(post_id), parent=blog_key())
        post.key.delete()
        time.sleep(.1)
        self.redirect('/blog')


class CommentPost(Handler):
    def get(self, post_id):
        post_entity = BlogPost.get_by_id(int(post_id), parent=blog_key())
        comment_entity_all = PostComment.query(
            PostComment.blog == post_entity.key).fetch()
        print comment_entity_all

        if self.user:
            self.render('comment.html',
                        post_entity=post_entity,
                        comments=comment_entity_all)
        else:
            self.redirect('/signin')

    def post(self, post_id):

        if not self.user:
            self.redirect('/blog')

        post_entity = BlogPost.get_by_id(int(post_id), parent=blog_key())
        comment = self.request.get('comment')
        author = self.user.name

        if comment:
            comment = PostComment(
                        blog=post_entity.key,
                        comment=comment,
                        author=author,
                        like=0,
                        dislike=0)
            comment.put()
            time.sleep(.1)

            comment_entity_all = PostComment.query(
                                PostComment.blog == post_entity.key).fetch()

            self.render(
                'comment.html',
                post_entity=post_entity,
                comments=comment_entity_all)
        else:
            error = "Your comment, please!"
            comment_entity_all = PostComment.query(
                                PostComment.blog == post_entity.key).fetch()
            self.render(
                'comment.html',
                post_entity=post_entity,
                comment=comment,
                comments=comment_entity_all,
                error=error)


class BlogFront(Handler):
    def get(self):
        posts = BlogPost.query().order(-BlogPost.last_modified).fetch(10)
        if self.user:
            author = self.user.name
        else:
            author = 'anoaymous'

        self.render('front.html', posts=posts, author=author)

    def post(self):

        if self.user:
            author = self.user.name
        else:
            author = 'anoaymous'
            self.redirect('/signin')

        editPost_id = ""
        trashPost_id = ""
        editPost_id = self.request.get('edit')
        trashPost_id = self.request.get('trash')
        like_id = self.request.get('like')
        dislike_id = self.request.get('dislike')
        comment_id = self.request.get('comment')

        if editPost_id:
            # post_A = BlogPost.get_by_id(int(editPost_id), parent=blog_key())
            # post_B = ndb.Key('BlogPost', int(editPost_id), parent=blog_key())
            # print post_A.key, post_B
            # post_A.key get same answer as post_B
            # print post_A, post_B.get()
            # post_A get same answer as post_B.get()
            self.redirect('/editpost/%s' % str(editPost_id))

        if trashPost_id:
            # print trashPost_id
            self.redirect('/deletepost/%s' % str(trashPost_id))

        if comment_id:
            # print trashPost_id
            self.redirect('/comment/%s' % str(comment_id))

        if like_id and author != 'anoaymous':
            post_entity = BlogPost.get_by_id(
                int(like_id), parent=blog_key())
            if author != post_entity.author:
                post_entity.like += 1
                post_entity.put()
                time.sleep(.1)

        if dislike_id and author != 'anoaymous':
            post_entity = BlogPost.get_by_id(
                int(dislike_id), parent=blog_key())
            if author != post_entity.author:
                post_entity.dislike += 1
                post_entity.put()
                time.sleep(.1)

        posts = BlogPost.query().order(-BlogPost.last_modified).fetch(10)

        self.render('front.html', posts=posts, author=author)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/welcome', Welcome),
    ('/signup', Register),
    ('/signin', SignIn),
    ('/signout', SignOut),
    ('/newpost', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/editpost/([0-9]+)', EditPost),
    ('/deletepost/([0-9]+)', DeletePost),
    ('/comment/([0-9]+)', CommentPost),
    (r'/blog/?', BlogFront)
], debug=True)
