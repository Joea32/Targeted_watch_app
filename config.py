import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret-key')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Mail settings (commented out for now) ---
    # MAIL_SERVER = os.environ.get('MAIL_SERVER', '')
    # MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    # MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 'yes']
    # MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    # MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    # MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', '')

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL', 'sqlite:///dev.db')

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')