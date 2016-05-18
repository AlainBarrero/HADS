# Librerias
import cgi
import webapp2
from google.appengine.api import users
from google.appengine.ext import ndb
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from webapp2_extras import sessions
import session_module
import re
import urllib
import hashlib

# Pagina principal
MAIN_PAGE_HTML = '''<!DOCTYPE html>
                    <html lang="es">
                    <head>
                        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
                        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"/>
                        <title>AlbumFotos</title>
                    </head>
	                <body>
	                    <div align="center">
		                    <h1>Album de Fotos</h1>
		                    <img src="http://www.wix.com/blog/wp-content/uploads/2013/10/baby-album5.jpg"/><br>
		                    <a href="/Login">Login</a>
		                    <a href="/Registro">Registrarse</a>
		                </div>
	                </body>
                    </html>'''

REGISTRO = '''<!DOCTYPE html>
    <html lang="es">
         <head>
              <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
              <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"/>
              <style type="text/css"> .label {text-align: right} .error {color: red} </style>
              <title>AlbumFotos</title>
         </head>
            <body>
                <div align="center">
                  <h1>Registro de Usuarios</h1>
                  <form method="post">
                    <table>
                        <tr>
                            <td class="label"> Nombre de usuario </td>
                            <td> <input type="text" name="username"  value="%(username)s" placeholder="Tu nombre...">
                            <td class="error"> %(username_error)s </td>
                         </tr>
                         <tr>
                            <td class="label"> Password</td>
                            <td> <input type="password" name="password" value="%(password)s" autocomplete="off" placeholder="Tu password..."></td>
                            <td class="error"> %(password_error)s </td>
                        </tr>
                        <tr>
                            <td class="label"> Repetir Password </td>
                            <td> <input type="password" name="verify" value="%(verify)s" placeholder="Repetir password...">
                            <td class="error"> %(verify_error)s </td>
                        </tr>
                        <tr>
                            <td class="label"> Email </td>
                            <td> <input type="text" name="email" value="%(email)s" placeholder="Tu email..."></td>
                            <td class="error"> %(email_error)s </td>
                        </tr>
                        </table> <input type="submit" name="Registrarse"> </form>
                </div>
            </body>
    </html>'''

LOGIN = '''<!DOCTYPE html>
    <html lang="es">
         <head>
              <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
              <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"/>
              <style type="text/css"> .label {text-align: right} .error {color: red} </style>
              <title>AlbumFotos</title>
         </head>
            <body>
                <div align="center">
                  <h1>Iniciar Sesion</h1>
                  <form method="post">
                    <table>
                        <tr>
                            <td class="label"> Email </td>
                            <td> <input type="text" name="email" value="%(email)s" placeholder="Tu email..."></td>
                            <td class="error"> %(email_error)s </td>
                        </tr>
                        <tr>
                            <td class="label"> Password</td>
                            <td> <input type="password" name="password" value="%(password)s" autocomplete="off" placeholder="Tu password..."></td>
                            <td class="error"> %(password_error)s </td>
                        </tr>
                        </table>
                        <input type="submit" value="Iniciar Sesion"> </form>
                </div>
            </body>
    </html>'''

MAIN_USER = '''<!DOCTYPE html>
                    <html lang="es">
                    <head>
                        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
                        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"/>
                        <title>AlbumFotos</title>
                    </head>
	                <body>
	                    <div align="center">
		                    <h1>Album de Fotos</h1>
		                    <img src="http://www.wix.com/blog/wp-content/uploads/2013/10/baby-album5.jpg"/><br>
		                    <a href="/Logout">Log out</a>
		                    <a href="/Album">Album</a>
		                    <a href="/Upload">Subir Foto</a>
		                </div>
	                </body>
                    </html>'''

ALBUM = '''<!DOCTYPE html>
                    <html lang="es">
                    <head>
                        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
                        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"/>
                        <title>AlbumFotos</title>
                    </head>
	                <body>
	                    <div align="center">
		                    <table>
                                <tr>
                                   <td>
                                        <img src="Serve/%s" width="400px"/><br>
                                        ---------------------------------------------------------------------------
                                    </td>
                                </tr>
		                    </table>
		                </div>
	                </body>
                    </html>'''
					
FORM_SUBIR_FOTO="""<!DOCTYPE html>
					<html lang="es">
                    <head>
                        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
                        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0"/>
                        <title>AlbumFotos</title>
                    </head>
					<body>
					    <div align="center">
					        <h1>Subir Fotos</h1>
                            <form action="%(url)s" method="post" enctype="multipart/form-data">
                                <input type="file" name="file"><br>
                                <input type="radio" name="access" value="public" checked="checked" /> Public
                                <input type="radio" name="access" value="private" /> Private<br>
                                <input type="submit" name="submit" value="Subir">
                            </form>
                            </div>
                        </body>
                    </html>
					"""


# Entidades y Clases
class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.write(MAIN_PAGE_HTML)

#####################LOGIN################################################
class Login(session_module.BaseSessionHandler):
    def write_form(self, password="", email="",
                     password_error="", email_error=""):

        self.response.write(LOGIN % {"password": password,
                                    "email": email,
                                    "password_error": password_error,
                                    "email_error": email_error})
    def get(self):
        self.write_form()

    def post(self):
        user_password = self.request.get('password')
        user_email = self.request.get('email')
        sani_password = escape_html(user_password)
        sani_email = escape_html(user_email)
        password_error = ""
        email_error = ""

        error = False
        if not valid_password(user_password):
            password_error = "Password incorrecto!"
            error = True
        if not valid_email(user_email):
            email_error = "Email incorrecto!"
            error = True

        if error:
            self.write_form(sani_password, sani_email, password_error,email_error)
        else:
            decod_pass=hashlib.md5(user_password).hexdigest()
            user = Usuario.query(Usuario.email == user_email, Usuario.password == decod_pass).count()
            if user != 0:
                self.session['email']=user_email
                self.response.write(MAIN_USER)
            else:
                self.response.out.write("Hola: %s <p> no estas registrado" % user_email)
                self.response.write(MAIN_PAGE_HTML)
###########################################################################################

class MainUser(webapp2.RedirectHandler):
    def get(self):
        self.response.write(MAIN_USER)

class LogOut(session_module.BaseSessionHandler):
    def get(self):
        for sesion in self.session.keys():
            del self.session[sesion]
        self.response.write(MAIN_PAGE_HTML)


class Usuario(ndb.Model):
    nombre = ndb.StringProperty()
    email = ndb.StringProperty(indexed=True)
    password = ndb.StringProperty(indexed=True)

class Image(ndb.Model):
    user = ndb.StringProperty(indexed=True)
    public = ndb.BooleanProperty()
    blob_key = ndb.BlobKeyProperty()


############REGISTRO###############
def escape_html(s):
    return cgi.escape(s, quote=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)


class Registro(session_module.BaseSessionHandler):
    def write_form(self, username="", password="", verify="",
                   email="", username_error="", password_error="",
                   verify_error="", email_error=""):
        self.response.write(REGISTRO % {"username":username,
                                        "password": password,
                                        "verify": verify,
                                        "email": email,
                                        "username_error": username_error,
                                        "password_error": password_error,
                                        "verify_error": verify_error,
                                        "email_error": email_error})

    def get(self):
        self.write_form()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')
        sani_username = escape_html(user_username)
        sani_password = escape_html(user_password)
        sani_verify = escape_html(user_verify)
        sani_email = escape_html(user_email)
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        error = False
        if not valid_username(user_username):
            username_error = "Nombre incorrecto!"
            error = True
        if not valid_password(user_password):
            password_error = "Password incorrecto!"
            error = True
        if not user_verify or not user_password == user_verify:
            verify_error = "Password no coincide!"
            error = True
        if not valid_email(user_email):
            email_error = "Email incorrecto!"
            error = True

        if error:
            self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error,
                            verify_error, email_error)
        else:
            user = Usuario.query(Usuario.nombre == user_username,
                                 Usuario.email == user_email).count()
            if user == 0:
                u = Usuario()
                u.nombre = user_username
                u.email = user_email
                u.password = hashlib.md5(user_password).hexdigest()
                u.put()
                self.session['email']=user_email
                self.response.write(MAIN_USER)
            else:
                self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error,
                                verify_error, email_error)
                self.response.out.write("Hola: %s <p> Ya estabas registrado" % user_username)


###################################################################################
class Upload(session_module.BaseSessionHandler, blobstore_handlers.BlobstoreUploadHandler):
        def get(self):
            upload_url = blobstore.create_upload_url('/Upload')
            self.response.out.write(FORM_SUBIR_FOTO % {'url': upload_url})

        def post(self):
            upload_files = self.get_uploads('file')
            blob_info = upload_files[0]
            img = Image(user=self.session.get('email'),
            public=self.request.get("access") == "public", blob_key=blob_info.key())
            img.put()
            self.redirect('/MainUser')


class Album(webapp2.RedirectHandler):
    def get(self):
        fotos = blobstore.BlobInfo.all()
        self.response.out.write('<h1 align="center">Album de Fotos</h1>')
        for foto in fotos:
            self.response.out.write(ALBUM % foto.key())

class Serve(blobstore_handlers.BlobstoreDownloadHandler):
    def get(self, resource):
        resource = str(urllib.unquote(resource))
        blob_info = blobstore.BlobInfo.get(resource)
        self.send_blob(blob_info)

application = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/Registro', Registro),
    ('/Login', Login),
    ('/MainUser', MainUser),
    ('/Album', Album),
    ('/Logout',LogOut),
    ('/Upload', Upload),
    ('/Serve/([^/]+)?', Serve)
    ],
    config=session_module.config,
    debug=True)
