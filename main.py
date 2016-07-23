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
    """Welcome new user"""
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class SignIn(Handler):
    """Register new user"""
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
    """User to signOut"""
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
    like = ndb.IntegerProperty(repeated=True)
    dislike = ndb.IntegerProperty(repeated=True)

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
    like = ndb.IntegerProperty(repeated=True)
    dislike = ndb.IntegerProperty(repeated=True)

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
                        like=[],
                        dislike=[])
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

        ok_id = self.request.get('ok')
        cancel_id = self.request.get('remove')

        if self.user and ok_id:
            content = self.request.get('content')
            post = BlogPost.get_by_id(int(post_id), parent=blog_key())
            post.content = content
            post.put()
            time.sleep(.1)
            self.redirect('/blog')

        elif self.user and cancel_id:
            self.redirect('/blog')

        else:
            self.redirect('/signin')


class DeletePost(Handler):
    def get(self, post_id):
        post = BlogPost.get_by_id(int(post_id), parent=blog_key())

        if self.user and self.user.name == post.author:
            self.render('deletepost.html', post=post)
        else:
            self.redirect('/blog')

    def post(self, post_id):
        post = BlogPost.get_by_id(int(post_id), parent=blog_key())
        ok_id = self.request.get('ok')
        cancel_id = self.request.get('remove')

        if self.user and ok_id:
            post.key.delete()
            time.sleep(.1)
            self.redirect('/blog')

        elif self.user and cancel_id:
            self.redirect('/blog')

        else:
            self.redirect('/signin')


class CommentPost(Handler):
    def get(self, post_id):
        post_entity = BlogPost.get_by_id(int(post_id), parent=blog_key())
        comment_entity_all = PostComment.query(
            PostComment.blog == post_entity.key).fetch()
        author = self.user.name

        if self.user:
            self.render('comment.html',
                        post_entity=post_entity,
                        comments=comment_entity_all,
                        author=author)
        else:
            self.redirect('/signin')

    def post(self, post_id):

        post_entity = BlogPost.get_by_id(int(post_id), parent=blog_key())
        post_id = post_entity.key.id()
        comment = self.request.get('comment')
        edit_comment = self.request.get('edit')
        delete_comment = self.request.get('trash')
        author = self.user.name

        print edit_comment
        print delete_comment

        if not self.user:
            self.redirect('/blog')

        elif self.user and comment:
            comment = PostComment(
                        blog=post_entity.key,
                        comment=comment,
                        author=author,
                        like=[],
                        dislike=[])
            comment.put()
            time.sleep(.1)

            comment_entity_all = PostComment.query(
                                PostComment.blog == post_entity.key).fetch()

            self.render(
                'comment.html',
                post_entity=post_entity,
                comments=comment_entity_all,
                author=author)

        elif self.user and edit_comment:
            comment_post_id = str(edit_comment) + '|' + str(post_id)
            self.redirect('/editcomment/%s' % comment_post_id)

        elif self.user and delete_comment:
            comment_post_id = str(delete_comment) + '|' + str(post_id)
            self.redirect('/deletecomment/%s' % comment_post_id)

        else:
            error = "Your comment, please!"
            comment_entity_all = PostComment.query(
                                PostComment.blog == post_entity.key).fetch()
            self.render(
                'comment.html',
                post_entity=post_entity,
                comment=comment,
                comments=comment_entity_all,
                author=author,
                error=error)


class EditComment(Handler):
    def get(self, comment_post_id):
        comment_id = comment_post_id.split('|')[0]
        comment = PostComment.get_by_id(int(comment_id))

        if self.user and self.user.name == comment.author:
            self.render('editcomment.html', comment=comment)

        else:
            self.redirect('/signin')

    def post(self, comment_post_id):
        comment_id = comment_post_id.split('|')[0]
        post_id = comment_post_id.split('|')[1]

        ok_id = self.request.get('ok')
        cancel_id = self.request.get('remove')

        if self.user and ok_id:
            content = self.request.get('content')
            comment = PostComment.get_by_id(int(comment_id))
            comment.comment = content
            comment.put()
            time.sleep(.1)
            self.redirect('/comment/%s' % str(post_id))

        elif self.user and cancel_id:
            self.redirect('/comment/%s' % str(post_id))

        else:
            self.redirect('/signin')


class DeleteComment(Handler):
    def get(self, comment_post_id):
        comment_id = comment_post_id.split('|')[0]
        comment = PostComment.get_by_id(int(comment_id))

        if self.user and self.user.name == comment.author:
            self.render('deletecomment.html', comment=comment)

        else:
            self.redirect('/signin')

    def post(self, comment_post_id):
        comment_id = comment_post_id.split('|')[0]
        post_id = comment_post_id.split('|')[1]

        ok_id = self.request.get('ok')
        cancel_id = self.request.get('remove')

        if self.user and ok_id:
            comment = PostComment.get_by_id(int(comment_id))
            comment.key.delete()
            time.sleep(.1)
            self.redirect('/comment/%s' % str(post_id))

        elif self.user and cancel_id:
            self.redirect('/comment/%s' % str(post_id))

        else:
            self.redirect('/signin')


class BlogFront(Handler):
    def get(self):
        posts = BlogPost.query().order(-BlogPost.last_modified).fetch(10)

        if self.user:
            author = self.user.name
        else:
            author = 'anonymous'

        self.render('front.html', posts=posts, author=author)

    def post(self):

        if self.user:
            author = self.user.name
            user_id = self.user.key.id()

            editPost_id = ""
            trashPost_id = ""
            editPost_id = self.request.get('edit')
            trashPost_id = self.request.get('trash')
            like_id = self.request.get('like')
            dislike_id = self.request.get('dislike')
            comment_id = self.request.get('comment')

            if editPost_id:

                self.redirect('/editpost/%s' % str(editPost_id))

            if trashPost_id:
                # print trashPost_id
                self.redirect('/deletepost/%s' % str(trashPost_id))

            if comment_id:
                # print trashPost_id
                self.redirect('/comment/%s' % str(comment_id))

            if like_id:
                post_entity = BlogPost.get_by_id(
                    int(like_id), parent=blog_key())

                if (author != post_entity.author and
                        user_id not in post_entity.like):
                    post_entity.like.append(user_id)
                    post_entity.put()
                    time.sleep(.1)

            if dislike_id:
                post_entity = BlogPost.get_by_id(
                    int(dislike_id), parent=blog_key())

                if (author != post_entity.author and
                        user_id not in post_entity.dislike):
                    post_entity.dislike.append(user_id)
                    post_entity.put()
                    time.sleep(.1)

            posts = BlogPost.query().order(-BlogPost.last_modified).fetch(10)

            self.render('front.html', posts=posts, author=author)

        else:
            author = 'anonymous'
            self.redirect('/signin')

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
    ('/editcomment/([0-9]+[|][0-9]+)', EditComment),
    ('/deletecomment/([0-9]+[|][0-9]+)', DeleteComment),
    (r'/blog/?', BlogFront)
], debug=True)
