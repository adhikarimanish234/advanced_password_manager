from app import app, migrate_database

with app.app_context():
    migrate_database()

application = app