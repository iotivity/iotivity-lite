import secrets

key = secrets.token_urlsafe(16)

f = open("secret","w")
f.write('SECRET_KEY = "{}"'.format(key))
f.close()


