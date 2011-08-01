#!/usr/bin/env python

from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
#from google.appengine.ext.webapp.util import run_wsgi_app

#import datetime

#HTTP_DATE_FMT = "%a, %d %b %Y %H:%M:%S GMT"

#class StaticContent(db.Model): 
#    body = db.BlobProperty()
#    content_type = db.StringProperty(required=True)
#    last_modified = db.DateTimeProperty(required=True, auto_now=True)
    
#def get(path):
#    return StaticContent.get_by_key_name(path)
    
#def set(path, body, content_type):
#    content = StaticContent(
#        key_name=path,
#        body=body,
#        content_type=content_type)
#    content.put()
#    return content
    
# handle request for static content
class StaticContentHandler(webapp.RequestHandler):
    def output_content(self):
        self.response.out.write('bitch')
#        self.response.headers['Content-Type'] = content.content_type
#        last_modified = content.last_modified.strftime(HTTP_DATE_FMT)
#        self.response.headers['Last-Modified'] = last_modified
#        if serve: 
#            self.response.out.write(content.body)
#        else: 
#            self.response.set_status(304)
            
#   def get(self, path):
#        content = get(path)
#        self.response.out.write('bitch2')
#        if not content:
#            self.error(404)
#            return
            
#        serve = True
#        if 'If-Modified-Since' in self.request.headers:
#            last_seen = datetime.datetime.strptime(
#                self.request.headers['If-Modified-Since'],
#                HTTP_DATE_FMT)
#            if last_seen >= content.last_modified.replace(microsecond=0):
#                serve = False
#        self.output_content(content, serve)
        

def main():
    application = webapp.WSGIApplication([('(/.*)', StaticContentHandler)])
    util.run_wsgi_app(application)

if __name__ = '__main__':
    main()