from model import db, User, Role
db.create_all()
Role.insert_roles()
