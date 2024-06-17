from main import Role, User
from werkzeug.security import generate_password_hash
from main import app, db

with app.app_context():
    db.create_all()

    # Create roles if they don't exist
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin', description='User is an admin')
        db.session.add(admin_role)

    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user', description='User is a regular user')
        db.session.add(user_role)

    db.session.commit()

    # Create an admin user if it doesn't exist
    admin_user = User.query.filter_by(email='admin@example.com').first()
    if not admin_user:
        admin_user = User(email='admin@email.com', password=generate_password_hash('admin'))
        admin_user.roles.append(admin_role)
        db.session.add(admin_user)
        db.session.commit()
