import os
import webapp2
import jinja2
import codecs
import re
import hashlib
import random
import string
from string import letters
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=True)

# handler class to utilize template easily
# also includes cookie handling


class Handler(webapp2.RequestHandler):
    # write in webpage
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # render str
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    # render webpage with given template file and any parameters
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # read "name" user cookie and return username if valid
    def readusercookie(self):
        uid = self.request.cookies.get('name')
        return uid and check_secure_val(uid)

    # initialize handler classes with logged variable
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user = self.readusercookie()
        loginuser = ""
        if user:
            loginuser = User.all().filter('username = ', user).get()
        self.logged = user and loginuser
# secret hash keyword
SECRET = 'myblog'

# hash a given string


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

# make a secure cookie value


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

# validate cookie


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# make salt with length 5 for password hashing


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# make password hash with make_salt function


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# validate password hash


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# class to create Blog database
# includes edit, delete, like, and dislike functions


class Blog(db.Model):
    author = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    number_comments = db.TextProperty()
    like_users = db.TextProperty()

    # check Blog db for key and return specific Blog entity

    @classmethod
    def editpost(cls, blog):
        b = Blog.all().filter('__key__ = ', blog.key().id())
        return b

    # delete post by using blog key

    @classmethod
    def deletepost(cls, blog):
        blog.key().delete()

    # like post by adding logged in user to Blog db field "like_user"

    @classmethod
    def likepost(cls, username, blogid):
        b = Blog.get_by_id(int(blogid))
        blu = b.like_users
        b.like_users = blu + username + '|'
        b.put()

    # dislike post by erasing logged in user from Blog db field "like_user"

    @classmethod
    def dislikepost(cls, username, blogid):
        b = Blog.get_by_id(int(blogid))
        b.like_users = b.like_users.replace(username + '|', "")
        b.put()

# Comment database


class Comments(db.Model):
    commenter = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    blogid = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    # check if given user has commented in given blog

    @classmethod
    def ifcommented(cls, blogid, user):
        blogs = db.GqlQuery(
                "SELECT * FROM Comments WHERE blogid = :1", blogid)
        for blog in blogs:
            if user == blogs.commenter:
                return 1
        return 0

# User database


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    blogs_commented = db.TextProperty()
    email = db.StringProperty()

    # login function: checks if password is valid for given username

    @classmethod
    def login(cls, username, password):
        loginuser = User.all().filter('username = ', username).get()
        if loginuser and valid_pw(username, password, loginuser.password):
            return loginuser

    # register function: creates password hash and returns User entity

    @classmethod
    def register(cls, username, password, email=None):
        hpassword = make_pw_hash(username, password)
        return User(username=username, password=hpassword, email=email)

    # function puts blog key id into User field blogs_commented

    @classmethod
    def commentedpost(cls, username, blogid):
        u = User.all().filter('username = ', username).get()
        bcs = u.blogs_commented + str(blogid) + '|'
        u.blogs_commented = bcs
        u.put()

# MainPage gives login/signup links or redirects to user home page


class MainPage(Handler):
    def get(self):
        if self.logged:
            user = self.readusercookie()
            self.redirect('/frontpage/%s' % user)
        else:
            self.render('home.html')

# FrontPage renders user's blog pages and logout and newpost links


class FrontPage(Handler):
    def get(self, user):
        if self.logged:
            loginuser = User.all().filter('username = ', user).get()
            if loginuser:
                blogs = db.GqlQuery(
                 "SELECT * FROM Blog WHERE author = :1 ORDER BY created DESC",
                 user)
                if self.readusercookie() == user:
                    own = 1
                else:
                    own = 0
                self.render('front.html', blogs=blogs, flag=own,
                            user=self.readusercookie())
            else:
                self.response.out.write("Error: User not found!")
        else:
            self.redirect('/')

# LikePostPage adds username to Blog database field like_users then redirects
# to homepage


class LikePostPage(Handler):
    def get(self, blogid):
        if self.logged:
            blog = Blog.get_by_id(int(blogid))
            author = blog.author
            likes = blog.like_users
            if self.readusercookie() == author:
                self.response.out.write("You cannot like your own posts!")
            else:
                if '|' + self.readusercookie() + '|' in blog.like_users:
                    Blog.dislikepost(self.readusercookie(), blogid)
                    self.redirect("/frontpage/" + author)
                else:
                    Blog.likepost(self.readusercookie(), blogid)
                    self.redirect("/frontpage/" + author)
        else:
            self.redirect('/')

# NewCommentPage renders textarea for logged in user to create a comment
# for specified blogpost


class NewCommentPage(Handler):
    def render_comment(self, comment="", error="", blogid=""):
        self.render('newcomment.html', comment=comment, error=error,
                    blogid=blogid)

    def get(self, blogid):
        if self.logged:
            self.render_comment(blogid=blogid)
        else:
            self.redirect('/')

    def post(self, blogid):
        if self.logged:
            comment = self.request.get("comment")
            username = self.readusercookie()
            u = User.all().filter('username = ', username).get()
            bcs = u.blogs_commented
            if '|' + str(blogid) + '|' in bcs:
                error = "You have already commented on this post!"
                self.render_comment(comment=comment, error=error)
            else:
                if comment:
                    c = Comments(commenter=username, comment=comment,
                                 blogid=blogid)
                    if c and c.commenter == username:
                        c.put()
                        User.commentedpost(username, blogid)
                        b = Blog.get_by_id(int(blogid))
                        b.number_comments = str(int(b.number_comments) + 1)
                        b.put()
                        self.redirect("/blog/%s" % blogid)
                    else:
                        self.redirect('/')
                else:
                    error = "Please enter a comment!"
                    self.render_comment(comment=comment, error=error)
        else:
            self.redirect('/')

# EditCommentPage loads logged in user's comment for that blogpost
# and allows user to edit comment


class EditCommentPage(Handler):
    def render_comment(self, comment="", error=""):
        self.render('newcomment.html', comment=comment, error=error)

    def get(self, b_id):
        if self.logged:
            content = ""
            error = ""
            user = self.readusercookie()
            comments = db.GqlQuery(
                        "SELECT * FROM Comments WHERE commenter = :1",
                        user)
            for comment in comments:
                if comment.blogid == b_id:
                    content = comment.comment
            if content == "":
                error = "You can't edit this comment!"
            self.render_comment(comment=comment.comment, error=error)
        else:
            self.redirect('/')

    def post(self, blogid):
        user = self.readusercookie()
        content = self.request.get("comment")
        comments = Comments.all()
        comments.filter("commenter = ", user)
        comments.filter("blogid = ", blogid)
        c = comments.get()

        if self.logged:
            if c and c.commenter == user:
                c.comment = content
                c.put()
                self.redirect("/blog/%s" % blogid)
            else:
                error = "Please enter a comment!"
                self.render_comment(comment=comment, error=error)
        else:
            self.redirect('/')

# DeleteCommentPage allows user to delete comment off blogpost


class DeleteCommentPage(Handler):
    def get(self, b_id):
        user = self.readusercookie()
        comments = Comments.all()
        comments.filter("commenter = ", user)
        comments.filter("blogid = ", b_id)
        c = comments.get()
        if self.logged:
            if c and c.commenter == user:
                c.delete()
                b = Blog.get_by_id(int(b_id))
                b.number_comments = str(int(b.number_comments) - 1)
                b.put()
                u = User.all()
                u.filter("username = ", user)
                user = u.get()
                user.blogs_commented = user.blogs_commented.replace(
                                        b_id + '|', "")
                user.put()
                self.redirect('/blog/%s' % b_id)
            else:
                self.response.out.write(
                    "Sorry! You can't delete that comment!"
                    )
        else:
            self.redirect('/')

# NewPostPage allows user to create new blogpost


class NewPostPage(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render('newpost.html', subject=subject, content=content,
                    error=error, user=self.readusercookie())

    def get(self):
        if self.logged:
            self.render_newpost()
        else:
            self.redirect('/')

    def post(self):
        if self.logged:
            subject = self.request.get("subject")
            content = self.request.get("content")

            username = self.readusercookie()

            if subject and content:
                b = Blog(author=username, subject=subject,
                         content=content, like_users="|",
                         number_comments="0")
                b.put()
                self.redirect("/blog/%d" % b.key().id())
            else:
                error = "We need both a subject and some content!"
                self.render_newpost(subject, content, error)
        else:
            self.redirect('/')

# EditPostPage allows user to edit one of the blogposts they have created


class EditPostPage(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render('newpost.html', subject=subject, content=content,
                    error=error)

    def get(self, b_id):
        if self.logged:
            user = self.readusercookie()
            blog = Blog.get_by_id(int(b_id))
            if blog and blog.author == user:
                self.render_newpost(blog.subject, blog.content)
            else:
                self.response.out.write("Sorry! You can't edit that post!")
        else:
            self.redirect('/')

    def post(self, b_id):
        if self.logged:
            user = self.readusercookie()
            b = Blog.get_by_id(int(b_id))
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                if b and b.author == user:
                    b.subject = subject
                    b.content = content
                    b.put()
                    self.redirect("/blog/%d" % b.key().id())
            else:
                error = "We need both a subject and some content!"
                self.render_front(subject, content, error)
        else:
            redirect('/')

# DeletePostPage allows user to delete their blogpost


class DeletePostPage(Handler):
    def get(self, b_id):
        if self.logged:
            user = self.readusercookie()
            blog = Blog.get_by_id(int(b_id))
            if blog and blog.author == user:
                blog.delete()
                self.redirect('/')
            else:
                self.response.out.write("Sorry! You can't delete that post!")
        else:
            self.redirect('/')

# BlogPage allows user to render a single blogpost they created


class BlogPage(Handler):
    def render_blogpage(self, b_id, own, c, u, logged, check):
        blog = Blog.get_by_id(int(b_id))
        if blog:
            self.render("blogpost.html", blog=blog, flag=own, comments=c,
                        user=u, logged=logged, check=check)
        else:
            self.response.out.write("No blog found")

    def get(self, b_id):
        blog = Blog.get_by_id(int(b_id))
        comments = db.GqlQuery("SELECT * FROM Comments WHERE blogid = :1",
                               b_id)
        user = blog.author
        if self.logged:
            if self.readusercookie() == user:
                own = 1
            else:
                own = 0
            comment = Comments.all()
            comment.filter("blogid = ", b_id)
            comment.filter("commenter = ", self.readusercookie())
            c = comment.get()
            if c:
                check = 1
            else:
                check = 0
            self.render_blogpage(b_id, own, comments, user,
                                 self.readusercookie(), check)
        else:
            self.redirect('/')


# expressions to make sure user enters valid inputs for username,
# password, and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_PA = re.compile(r"^.{3,20}$")
USER_EM = re.compile(r"^[\S]+@[\S]+.[\S]+$")

# vuser validates username input on signup page


def vuser(username):
    return USER_RE.match(username)

# vpass validates username input on signup page


def vpass(pw):
    return USER_PA.match(pw)

# vmail validates email input on signup page


def vmail(email):
    return USER_EM.match(email)

# Signup page allows user to create new account for blog.
# Will check for valid inputs for username, password, and email fields


class SignUpPage(Handler):

    def get(self):
        if self.logged:
            self.redirect('/')
        else:
            self.render('signup.html')

    def post(self):
        if not self.logged:
            eu = ""
            ep = ""
            ep2 = ""
            ee = ""

            user_name = self.request.get('username')
            user_pass1 = self.request.get('password')
            user_pass2 = self.request.get('verify')
            user_email = self.request.get('email')

            if(not vuser(user_name)):
                eu = "That's not a valid username"

            u = User.all().filter('username = ', user_name).get()
            if u:
                eu = "That name is already taken"
                flag = 1
            else:
                flag = 0

            if(not vpass(user_pass1)):
                ep = "That's not a valid password"

            if(user_pass1 != user_pass2):
                ep2 = "Passwords did not match"

            if(not vmail(user_email) or user_email != ""):
                ee = "That's not a valid email"

            if(vuser(user_name) and vpass(user_pass1) and
               user_pass1 == user_pass2 and
               (vmail(user_email) or user_email == "") and flag == 0):
                self.response.headers.add_header(
                    'Set-Cookie',
                    'name=%s; Path=/' % (str(make_secure_val(user_name))))
                u = User.register(user_name, user_pass1, user_email)
                u.blogs_commented = '|'
                u.put()
                self.redirect('/welcome')
            else:
                self.render("signup.html", username=user_name,
                            email=user_email, eu=eu, ep=ep, ep2=ep2, ee=ee)
        else:
            self.redirect('/')

# WelcomePage is landing page after successful login
# Includes link to user's homepage


class WelcomePage(Handler):
    def get(self):
        name_cookie = self.request.cookies.get('name')
        if name_cookie:
            user = check_secure_val(name_cookie)
            if user:
                self.render('welcome.html', username=user)
            else:
                self.redirect('/signup')

# LoginPage allows returning users to log in to the blog


class LoginPage(Handler):
    def get(self):
        if self.logged:
            self.redirect('/')
        else:
            self.render('login.html')

    def post(self):
        if self.logged:
            self.redirect('/')
        else:
            username = self.request.get('username')
            password = self.request.get('password')

            u = User.login(username, password)

            if u:
                self.response.headers.add_header(
                    'Set-Cookie',
                    'name=%s; Path=/' % (str(make_secure_val(username))))
                self.redirect('/welcome')
            else:
                self.render('login.html', error="Invalid login")

# LogOutPage allows user to cleanly log out of the blog


class LogoutPage(Handler):
    def get(self):
        if self.logged:
            self.response.headers.add_header('Set-Cookie', 'name=; Path=/')
            self.redirect('/signup')
        else:
            self.redirect('/')

# collection of pages


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPostPage),
                               ('/editpost/(\d+)', EditPostPage),
                               ('/newcomment/(\d+)', NewCommentPage),
                               ('/editcomment/(\d+)', EditCommentPage),
                               ('/deletecomment/(\d+)', DeleteCommentPage),
                               ('/frontpage/(\S+)', FrontPage),
                               ('/blog/(\d+)', BlogPage),
                               ('/signup', SignUpPage),
                               ('/welcome', WelcomePage),
                               ('/likepost/(\d+)', LikePostPage),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage),
                               ('/delete/(\d+)', DeletePostPage)], debug=True)
