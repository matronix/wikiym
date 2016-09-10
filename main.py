#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import json
import re
import random
import string
import hashlib
import logging
import time
import hmac
from google.appengine.api import memcache
from google.appengine.ext import ndb
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PSWD_RE = re.compile(r"^.{3,20}$")
def valid_pswd(passwd):
    return PSWD_RE.match(passwd)

def pswd_match(passwd, repasswd):
    return passwd==repasswd

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

def hash_str(s):
    return hashlib.sha256(s).hexdigest()

# implement the function make_salt() that returns a string of 5 random
# letters use python's random module.
# Note: The string package might be useful here.
def make_salt():
    randStr = ''

    for i in range(1,6):
        randomNum = random.randrange(0,26)
        randChar = string.ascii_lowercase[randomNum]
        randStr = randStr + randChar

    return randStr
    
        
# implement the function make_pw_hash(name, pw) that returns a hashed password 
# of the format: 
# HASH(name + pw + salt),salt
# use sha256
secret = 'planes'
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#check_secure_val return the userid if it is authentic.
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_pw_hash(name, pw):
    theSalt = make_salt()
    strToHash = name+pw+theSalt
    return "%s|%s" % (theSalt,hash_str(strToHash))

    
def valid_pw(name, pw, h):
    hArray = h.split('|')
    theHash = hArray[1]
    theSalt = hArray[0]
    if hash_str(name+pw+theSalt)==theHash:
        return True
    return False

def is_username_unique(username):
    #get usernames from the database
    usernames = db.GqlQuery("SELECT * FROM User ORDER BY username ASC")
    #run() returns an iterable to loop through the query
    for user in usernames.run():
        if username == user.username:
            return False
    return True

def username_exists(username):
    #get usernames from the database
    usernames = db.GqlQuery("SELECT * FROM User ORDER BY username ASC")
    for user in usernames.run():
        if username == user.username:
            return True
    return False
    
def passwd_exists(pw):
    #get usernames from the database
    passwords = db.GqlQuery("SELECT * FROM User ORDER BY password ASC")
    for p in passwords.run():
        if pw == p.password:
            return True
    return False

def getPost(postid, update=False):
    postid = str(postid)
    postGet = memcache.get(postid)
    post_time = 0
    
    if postGet is None or update:
        print "Post cache is cold......heating it."
        #posts = Post.query().order(-Post.created)
        #post = Post.get_by_id(int(postid))
        gqlstring = "SELECT * FROM Post WHERE pid='%s'" % postid
        post = ndb.gql(gqlstring)
        postcount = post.count()
        if postcount==0:
            return None
        #above return a query object. Need to iterate to get the post object
        for p in post:
          set_time = time.time()
          memcache.set(postid, (p, set_time))
    else:
        print "Post cache is hot"
        #posts = list(posts)
        p = postGet[0]
        post_time = time.time() - postGet[1]
        
    return (p, post_time)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)


class User(db.Model):
	username = db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)

        @classmethod
        def by_id(cls, uid):
                return User.get_by_id(uid, parent = users_key())


class Post(ndb.Model):
	#subject = ndb.StringProperty(required=True)
        pid = ndb.StringProperty(required=True)
	content = ndb.TextProperty(required=True)
	created = ndb.DateTimeProperty(auto_now_add=True)

	elapsed_time = 0
	

	@classmethod
	def getElapsedTime(cls):
            return cls.elapsed_time

        @classmethod
	def getPostTime(cls):
            return cls.post_time
	
        @classmethod
        def getPosts(cls, update=False):
            postsGet = memcache.get("POST")           
            
            if postsGet is None or update:
                print "Cache is cold......heating it."
                posts = Post.query().order(-Post.created)
                posts = list(posts)
                set_time = time.time()
                memcache.set("POST", (posts, set_time))
            else:
                print "Cache is hot"
                #posts = list(posts)
                posts = list(postsGet[0])
                cls.elapsed_time = time.time() - postsGet[1]
                
            return posts

        
        @classmethod
        def flushPosts(cls):
            memcache.flush_all()
            cls.elapsed_time=0

        @classmethod
        def clearPosts(cls):
            print "Cool the cache"
            memcache.delete("POST")
                
	

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


        def set_secure_cookie(self, name, val):
                cookie_val = make_secure_val(val)
                self.response.set_cookie(name, value=cookie_val, path='/')


        def read_secure_cookie(self, name):
                cookie_val = self.request.cookies.get(name)
                return cookie_val and check_secure_val(cookie_val)


        def initialize(self, *a, **kw):
                webapp2.RequestHandler.initialize(self, *a, **kw)
                uid = self.read_secure_cookie('registercookie')
               #self.user = uid and User.by_id(int(uid))
                self.user = uid and User.by_id(int(uid))



class MainHandler(Handler):
    def render_front(self, template,  user=""):
       self.render(template, user=user)

    def get(self):
       u_id = self.read_secure_cookie('registercookie')
       if u_id:
           user = User.get_by_id(int(u_id))
           self.render_front('base.html', user)
       else:
           self.redirect('/signup', SignupHandler)            
        

class EditPageHandler(Handler):

    def render_front(self, template,  postid="", content="", error=""):
	    self.render(template, content=content, error=error)

    def get(self, postid):
        #check if this postid already exists in the db. If it does add the current contents
        #to the textarea.
        #p=getPost(postid)
        gqlstring = "SELECT * FROM Post WHERE pid='%s' ORDER BY created DESC" % postid
        p = ndb.gql(gqlstring)
        postlist = []
        for post in p:
            postlist.append(post)

        lastPost = postlist[0]

        if p:
            post = lastPost
            self.render_front('wikiIn.html', content=post.content, postid=postid) 
        else:
            self.render('wikiIn.html', postid=postid)

        """if p is None:
            self.render('wikiIn.html', postid=postid)
        else:
            post = p[0]
            self.render_front('wikiIn.html', content=post.content, postid=postid)""" 

#the browser has sent a post request.
#This method will respond.
    def post(self, postid):
	    content = self.request.get("content")

	    if  content:
                    #if the postid does not exists in the db, create a new post object and
                    #put it in the db, else update the existing post with entered content
                    #p=getPost(postid)
                    p = Post(pid=postid, content=content)
                    p.put()
                    '''if p is None:
		        p = Post(pid=postid, content=content)
		        #accessing DB
		        logging.error("Putting new post in DB")
		        p.put()
                        time.sleep(0.3)
		        #since we've just updated the datastore with a new entry
		        #we force a refresh of the cache.
                    else:
                        existingPost = p[0]
                        existingPost.content = content
                        existingPost.put()'''
                    
                    #flush cache since new post added in database.
                    Post.flushPosts()
                    time.sleep(0.3)
		    self.redirect('%s' % postid)
	    else:
		    error = 'Need to enter content'
		    self.render_front(error=error)


class WikiPageHandler(Handler):
    def render_front(self, template, postid, post, user=''):
	    self.render(template, postid=postid, post=post, user=user)

    def get(self, postid):
            #p = Post.get_by_id(int(post_id))
            #if postid is not in db, redirect to EditHandler 
            #else if postid is in db display it
            #p = getPost(postid)
            gqlstring = "SELECT * FROM Post WHERE pid='%s' ORDER BY created DESC" % postid
            p = ndb.gql(gqlstring)
            postlist = []
            for post in p:
                postlist.append(post)

            lastPost = postlist[0]

            u_id = self.read_secure_cookie('registercookie')
            if u_id:
                """if p is None:
                    self.redirect('/_edit' + '%s' % postid)
                else:
                    user = User.get_by_id(int(u_id))
                    self.render_front('wikiOut.html', postid, p, user)"""
                if lastPost:
                    #self.response.out.write(lastPost)
                    user = User.get_by_id(int(u_id))
                    self.render_front('wikiOut.html', postid, lastPost, user)
                else:
                    self.redirect('/_edit' + '%s' % postid)
            else:
                self.render_front('wikiOut.html', postid, p)
                #self.redirect('/login')

            """
            #some experimental stuff
            cookie_val = self.request.cookies.get('registercookie')
            self.response.out.write(cookie_val+'<br>')
            h = self.response.headers
            self.response.out.write(h)
            self.response.out.write('<br>')
            #b = self.response.body
            #self.response.out.write(b)
            r = self.request.referer
            self.response.out.write(r)
            self.response.out.write('<br>')
            """

class HistoryPageHandler(MainHandler):

    def render_front(self, template, postid, post, user=''):
	    self.render(template, postid=postid, post=post, user=user)

    def get(self, postid):
            #p = getPost(postid)
            gqlstring = "SELECT * FROM Post WHERE pid='%s' ORDER BY created DESC" % postid
            p = ndb.gql(gqlstring)
            u_id = self.read_secure_cookie('registercookie')
            if u_id:
                if p:
                    user = User.get_by_id(int(u_id))
                    self.render_front("history.html", postid, p, user)
                else:
                    self.redirect('/_edit' + '%s' % postid)


class SignupHandler(MainHandler):
   
    def get(self):
        self.render('signup-form.html', username='')

    def post(self):
        errString = dict()
        name = self.request.get('username')
        pw = self.request.get('password')
        email = self.request.get('email')
        
        if not valid_username(self.request.get('username')):
            errString['error_username'] = 'not a valid username'
            
        #check if username is unique
        if not is_username_unique(name):
            errString['error_username'] = 'username not unique'
            
        if not valid_pswd(self.request.get('password')):
            errString['error_password'] = 'That\'s not a valid pasword'
            
        if not pswd_match(self.request.get('password'), self.request.get('verify')):
            errString['error_verify'] = 'Passwords don\'t match'

        if self.request.get('email'):
            if not valid_email(self.request.get('email')):
                errString['error_email']='Invalid email'                               

        if not errString:
            u = User(username=name, password=pw, email=email)
            u.put()
            u_id = str(u.key().id())
            #value = make_pw_hash(name, pw)
            #self.response.set_cookie('registercookie', value=value, path='/')
            #value = make_secure_val(u_id)
            value = u_id
            self.set_secure_cookie('registercookie', value)
            #self.redirect('/welcome/%s' % u_id)
            self.render('wikiOut.html', postid='', post='', post_time='')
        else:
            self.render('signup-form.html',**errString)

class LoginHandler(MainHandler):
    def get(self):
        self.render('login_form.html', username='')

    def post(self):
        errString = dict()
        nameenterd = self.request.get('username')
        pwenterd = self.request.get('password')
        if not username_exists(nameenterd):
            errString['error_username'] = 'user does not exist'

        if not passwd_exists(pwenterd):
            errString['error_password'] = 'password does not exist'

        if not errString:
            q = db.GqlQuery("SELECT * FROM User WHERE username='%s'" % nameenterd)
            
            for u in q.run():
                u_id = str(u.key().id())
            value = u_id
            self.set_secure_cookie('registercookie', value)
            self.redirect('/')
        else:
            self.render('login_form.html', **errString)

class LogoutHandler(MainHandler):
    def get(self):
        self.response.delete_cookie('registercookie', path='/')
        r = self.request.referer
        self.redirect(r)

#WikiPageHandler should be very similar to PostHandler
#EditPageHandler should be similar to NewPostHandler
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignupHandler),
    ('/login' , LoginHandler),
    ('/logout', LogoutHandler),
    ('/_edit' + PAGE_RE, EditPageHandler),
    ('/_history' + PAGE_RE, HistoryPageHandler),
    (PAGE_RE, WikiPageHandler)
], debug=True)

                              
