import environ

env = environ.Env()
environ.Env.read_env()

DATABASES = {
    "default": env.db(),
}
