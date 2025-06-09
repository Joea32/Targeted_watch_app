# extensions.py
#from flask_sqlalchemy import SQLAlchemy

#db = SQLAlchemy()

# Targeted_victim_watch/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

