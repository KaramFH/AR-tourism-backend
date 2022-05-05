import datetime
from types import MethodDescriptorType
from flask import Flask,jsonify,request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from sqlalchemy.exc import IntegrityError

import uuid
from werkzeug.security import generate_password_hash, check_password_hash 

import jwt

from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:comp12hs@localhost/flask'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50),unique=True) 
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    admin = db.Column(db.Boolean)

    def __repr__(self):
        return '<User %r>' % self.username

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id','public_id','username','first_name','last_name','email','password','admin')


user_schema = UserSchema()
users_schema = UserSchema(many=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    date = db.Column(db.DateTime, default= datetime.datetime.now(), nullable=False)
    post_body = db.Column(db.Text(), nullable=False)

    def __repr__(self):
        return '<Post %r by %r' % (self.id,self.user_id)

class PostSchema(ma.Schema):
    class Meta:
        fields = ('id','username','date','post_body')

post_schema = PostSchema()
posts_schema = PostSchema(many=True)


class Collection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    collectable = db.Column(db.String(120))


class CollectionSchema(ma.Schema):
    class Meta:
        fields = ('id','username','collectable')

collection_schema = CollectionSchema()
collections_schema = CollectionSchema(many=True)




def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message':'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms="HS256")
            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message':'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


@app.route("/create_post",methods=['POST'])
@token_required
def create_post(current_user):
    try:
        data = request.form

        text = data['text']
        user = current_user.username

        new_post = Post(username=str(user),post_body=str(text))

        db.session.add(new_post)
        db.session.commit()

        return jsonify({'message':'Post created!'})
    except:
        return jsonify({'message':'Something went wrong!'})

@app.route("/get_posts",methods=['GET'])
@token_required
def get_posts(current_user):
    posts = Post.query.all()
    results = posts_schema.dump(posts)

    return jsonify(results)



@app.route("/get",methods=['GET'])
@token_required
def get_users(current_user):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function!'})

    users = User.query.all()
    results = users_schema.dump(users)

    return jsonify(results)

@app.route("/get/<public_id>",methods=['GET'])
@token_required
def user_details(current_user,public_id):
    # user = User.query.get(id)
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':'No user found!'})

    return user_schema.jsonify(user)


#TODO: add exception handling if the username already exists or if the email already exists.
@app.route("/add",methods=['POST'])
def add_user():

    #Use These!!

    #email_exists = User.query.filter_by(email=em).first()
    #if email_exists:

    #username_exists = User.query.filter_by(username=em).first()
    #if username_exists:
    

    try:
        user = request.json['username']
        first = request.json['first_name']
        last = request.json['last_name']
        em = request.json['email']
        passw = request.json['password']

        user = User(username=user,first_name=first,last_name=last,email=em,password=passw)
        db.session.add(user)
        db.session.commit()

        return user_schema.jsonify(user)
    except IntegrityError:
        db.session.rollback()
        return "User already exists."



@app.route("/update/<id>",methods=['PUT'])
def update_user(id):
    user = User.query.get(id)

    #the user wants to update the email

    em = request.json['email']

    user.email = em

    db.session.commit()
    return user_schema.jsonify(user)

@app.route("/delete/<public_id>",methods=['DELETE'])
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':'No user found!'}) 

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message':'User deleted!'})


#If auth doent work hardcode the login and decorator function
# @app.route("/login")
# def login():
#     auth =  request.authorization

#     if not auth or not auth.username or not auth.password:
#         return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login Required"'})
    
#     user = User.query.filter_by(username=auth.username).first()

#     if not user:
#         return jsonify({'message':'User does not exist!'})
#         # return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login Required"'})
    
#     if check_password_hash(user.password,auth.password):
#         token = jwt.encode({'public_id':user.public_id},app.config['SECRET_KEY'])
#         return jsonify({'token': token})
    
#     return jsonify({'message':'Wrong password!'})

@app.route("/login",methods=['POST'])
def login():

    username = request.form['username']
    passw = request.form['password']


    if not username or not passw:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login Required"'})
    
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message':'User does not exist!'})
        # return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login Required"'})
    
    if check_password_hash(user.password,passw):
        token = jwt.encode({'public_id':user.public_id},app.config['SECRET_KEY'])
        return jsonify({'token': token})
    
    return jsonify({'message':'Wrong password!'})

    


#Create a new User, Signup
@app.route("/signup", methods=['POST'])
def signup():
    data = request.form

    username_exists = User.query.filter_by(username=data['username']).first()
    if username_exists:
        return jsonify({'message':'Username already exists!'})


    email_exists = User.query.filter_by(email=data['email']).first()
    if email_exists:
        return jsonify({'message':'Email already exists!'})

    
    #Get the password as a hashed password
    passw = generate_password_hash(data['password'],method='sha256')

    new_user = User(public_id=str(uuid.uuid4()),username = data['username'],first_name=data['first_name'],
               last_name=data['last_name'],email = data['email'],password=passw,admin=False )
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':'New User Created!'})




@app.route("/promote/<public_id>",methods=['PUT'])
def promote_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':'User does not exist!'})

    user.admin = True

    db.session.commit()

    return jsonify({'message':'The user has been promoted!'})    


@app.route("/")
def home():
    return "hello there!"


if __name__ == "__main__":
    app.run(port = 8000,host = '0.0.0.0', debug = True)