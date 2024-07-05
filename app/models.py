from . import db

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=True)