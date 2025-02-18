from .base import *

DEBUG = True
ALLOWED_HOSTS = ["*"]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "file": {
            "level": "ERROR",
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs/errors.log",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "contact_us": {
            "handlers": ["file"],
            "level": "ERROR",
            "propagate": True,
        },
    },
}
