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
import logging
import os
import facebook 
import base64
import hmac
import hashlib
import time
import Cookie
import urllib

# dummy config to enable registering django template filters
os.environ[u'DJANGO_SETTINGS_MODULE'] = u'conf'

from google.appengine.dist import use_library
use_library('django', '1.2')

from google.appengine.api import urlfetch, taskqueue
from django.template.defaultfilters import register
from django.utils import simplejson as json

from google.appengine.ext import db, webapp
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template

FB_NONDEV_ID = '210687712331095'
FB_NONDEV_SECRETID = '2d92ebb40913357c449332f172b1366a'

FB_DEV_ID = '262869930403008'
FB_DEV_SECRETID = '9dc16baa1f8dc2aa1710491019a49c6f'

FB_APP_ID = '262869930403008'
FB_SECRET_ID = '9dc16baa1f8dc2aa1710491019a49c6f'
_USER_FIELDS_API = u'name,email,picture,friends,first_name,last_name,statuses'

"""data models"""
class Users(db.Model):
    user_id = db.StringProperty(required = True)
    access_token = db.StringProperty(required = True)
    name = db.StringProperty(required = True)
    first_name = db.StringProperty()
    last_name = db.StringProperty()
    picture = db.StringProperty(required = True)
    email = db.StringProperty()
    friends = db.StringListProperty()
    checkin = db.StringListProperty()
    city = db.StringProperty()
"""end data models"""

class Facebook(object):
    def __init__(self, app_id = FB_APP_ID, 
             app_secret = FB_SECRET_ID):
        logging.debug('Facebook class - init')           
        self.app_id = app_id
        self.app_secret = app_secret
        self.user_id = None
        self.access_token = None
        self.signed_request = {}


    def load_signed_request(self, signed_request):
	    #load the user state; signed_request is used to share info between fb adn the app
        try: 
            logging.debug('Facebook class - load_signed_request - try')
            logging.debug(signed_request)
            sig, load = signed_request.split(u'.', 1)
            logging.debug('sig: ' + sig)
            logging.debug('load: ' +load)
            sig = self.base64_url_decode(sig)
            logging.debug('sig after base: ')
            logging.debug(sig)
            deload = self.base64_url_decode(load)
            logging.debug('deload after base')
            logging.debug(deload)
            data = json.loads(deload)
            #data = json.loads(self.base64_url_decode(load))
            logging.debug('data after json base: ')
            logging.debug(data)
		    
		    #check the signature
      	    expected_sig = hmac.new(
		        self.app_secret, msg = load, digestmod = hashlib.sha256).digest()
            logging.debug('expected_sig: ')
            logging.debug(expected_sig)

		    #allow request to function for 1 day
    	    if sig == expected_sig and data[u'issued_at'] > (time.time() - 86400):
                logging.debug('sig == expected sig')
                self.signed_request = data
                self.user_id = data.get(u'user_id')
                logging.debug(self.user_id)
                self.access_token = data.get(u'oauth_token')
                #logging.debug(self.access_token + 'access token') 
		
        except ValueError, ex:
            logging.debug('except')
            pass  
    
    @staticmethod
    def base64_url_decode(data):
	    data = data.encode(u'ascii')
	    data += '=' * (4 - (len(data) % 4))
	    return base64.urlsafe_b64decode(data)      

    #me = facebook.api(u'/me', {u'fields': _USER_FIELDS})
    def api(self, path, params=None, method=u'GET', domain=u'graph'):
        """Make Graph API calls"""
        logging.debug('in API')
        logging.debug(path)
        if not params:
            params = {}
        params[u'method'] = method
        if u'access_token' not in params and self.access_token:
            logging.debug('API access token not in params')
            params[u'access_token'] = self.access_token
        logging.debug(params)
        url_f = urlfetch.fetch(
            url = u'https://' + domain + u'.facebook.com' + path,
            payload = urllib.urlencode(params),
            method = urlfetch.POST,
            headers = {
                u'Content-Type': u'application/x-www-form-urlencoded'})
        logging.debug('url_f')
        logging.debug(url_f)
        result = json.loads(url_f.content) 
        logging.debug('result')
        logging.debug(result)
        #need to add instance API error
        return result

class BaseHandler(webapp.RequestHandler):
    facebook = None
    user = None
    
    def initialize(self, request, response):
        logging.debug('BaseHandler Initialize')
        super(BaseHandler, self).initialize(request, response)
        logging.debug(request)
        logging.debug(response)

        try: 
            logging.debug('BaseHandler Try - init_facebook()')           
            self.init_facebook()
        except Exception, ex: 
            #self.log_exception(ex)
            raise

    def init_facebook(self):
        logging.debug('BaseHandler - init_facebook()')           
        facebook = Facebook()
        user = None

        # the initial facebook request is POST and not GET
        if u'signed_request' in self.request.POST:
            logging.debug('BaseHandler init_facebook() - if signed request check')           
            """call load_signed_request to check on fb signature"""
            logging.debug('SR in init_fb: ' + self.request.get('signed_request'))
            facebook.load_signed_request(self.request.get('signed_request'))
            logging.debug('after fb load_signed_request: ')
            logging.debug(facebook.user_id)
            """we also want to change the POST request from fb to GET"""
            self.request.method = u'GET'
#            self.set_cookie(
#                'u', facebook.user_cookie, datetime.timedelta(minutes=1440))

        # load a user object
        if facebook.user_id:
            logging.debug('user id exists for signed request')
            logging.debug('call the API method test')
            #me = facebook.api(u'/me', {u'fields': _USER_FIELDS_API})
            user = Users.get_by_key_name(facebook.user_id)
            if user:
                logging.debug('user found in datastore')
                me = facebook.api(u'/me',{u'fields': _USER_FIELDS_API})
                logging.debug(me)
                # update access token
                if facebook.access_token != user.access_token:
                    user.access_token = facebook.access_token
                    user.put()
                # set access_token if doesn't exist
                if not facebook.access_token:
                    facebook.access_token = user.access_token

            if not user and facebook.access_token:
                logging.debug('user does not exist in datastore')
                logging.debug('call the API method')
                logging.debug(str(facebook.user_id))
                me = facebook.api(u'/me',{u'fields': _USER_FIELDS_API})
                try:
                    friends = [user[u'id'] for user in me[u'friends'][u'data']] 
                    logging.debug('try to load new user in datastore')
                    logging.debug(facebook.user_id + ' ' + facebook.access_token)
                    user = Users(key_name = facebook.user_id, 
                        user_id = facebook.user_id,
                        access_token = facebook.access_token, name = me[u'name'], 
                        email = me[u'email'], picture = me[u'picture'],
                        first_name = me[u'first_name'], last_name = me[u'last_name'])
                    user.put()
                    logging.debug('after put')
                except: 
                    pass

        self.facebook = facebook
        self.user = user 

class MainHandler(BaseHandler):    

    def get(self):
        logging.debug('MainHandler Get')
        logging.debug(self.facebook.user_id)
        if self.facebook.user_id:
            data = dict(current_user=self.user.user_id,
                        picture = self.user.picture)
            logging.debug(data)
            uid = self.facebook.user_id 
            self.render(u'index', uid=uid)
        else:
            self.render(u'welcome')

    def render(self, name, **data):
        logging.debug('in render')
        if data:
            logging.debug('data exists')
        path = os.path.join(os.path.dirname(__file__), 'views', name + '.html') 
        self.response.out.write(template.render(path, data))        

def main():
	logging.getLogger().setLevel(logging.DEBUG)
	routes = [('/', MainHandler)]
	application = webapp.WSGIApplication(routes, debug=True)
	util.run_wsgi_app(application)

if __name__ == '__main__':
    main()