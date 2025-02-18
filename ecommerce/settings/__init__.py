import environ
env = environ.Env()
environ.Env.read_env() 

ENV = env("ENV", default="development")

if ENV == "production":
    from .production import *
elif ENV == "testing":
    from .testing import *
else:
    from .development import *
