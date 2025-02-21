from .base import *

DEBUG = True
ALLOWED_HOSTS = ["*"]

import os

LOGGING_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOGGING_DIR):
    os.makedirs(LOGGING_DIR)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "file": {
            "level": "ERROR",
            "class": "logging.FileHandler",
            "filename": os.path.join(LOGGING_DIR, "errors.log"),
        },
    },
    "root": {
        "handlers": ["file"],
        "level": "ERROR",
    },
}

import environ

env = environ.Env()
environ.Env.read_env()

DATABASES = {"default": env.db(default="sqlite:///db.sqlite3")}  # Fallback to SQLite
