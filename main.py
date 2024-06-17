from io import BytesIO
import flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, desc
from config import DevelopmentConfig
from werkzeug.security import check_password_hash, generate_password_hash
import flask_login
from datetime import datetime, timedelta
from flask_login import UserMixin
import os
from flask import current_app as app, jsonify, request, render_template, send_file, Blueprint
from reportlab.pdfgen import canvas

app = flask.Flask(__name__)
app.config.from_object(DevelopmentConfig)
db = SQLAlchemy(app)

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

book_author_association = db.Table(
    'book_author_association',
    db.Column('book_id', db.Integer, db.ForeignKey('book.id')),
    db.Column('author_id', db.Integer, db.ForeignKey('author.id'))
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=False)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String(255))
    amount = db.Column(db.Float, default=0 )
    last_visit = db.Column(db.DateTime, default=datetime.utcnow)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def get_user_roles(self):
        return [role.name for role in self.roles]

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    content = db.Column(db.String, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())
    section_id = db.Column(db.Integer, db.ForeignKey('book_section.id'), nullable=False)
    lang_id = db.Column(db.Integer, db.ForeignKey('language.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('author.id'), nullable=False)
    author = db.relationship('Author', backref='books')
    price = db.Column(db.Float, nullable=True)
class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Float, default=0.0)

class WalletRechargeRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String, default='pending') 
    user = db.relationship('User', backref='recharge_requests')


class Language(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

class Section(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"Section('{self.name}', '{self.date_created}')"

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<Rating {self.id}>"

class BookSection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    books = db.relationship('Book', backref='book_section', lazy=True)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())

class Author(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Borrowing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    borrow_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    return_date = db.Column(db.DateTime, nullable=True, default=datetime.utcnow() + timedelta(days=7))
    approved = db.Column(db.Boolean, default=False)
    returned = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='borrowings')
    book = db.relationship('Book', backref='borrowings') 

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        return render_template("login.html")
    email = flask.request.form.get('email')
    password =flask.request.form.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        error = 'Please check your login details and try again.'
        return render_template('login.html', error=error)# if the user doesn't exist or password is wrong, reload the page

    flask_login.login_user(user, remember=True)
    if 'admin' in flask_login.current_user.get_user_roles() :
        return flask.redirect(flask.url_for('admin_dashboard'))
    return flask.redirect(flask.url_for('home'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if flask.request.method == 'GET':
        return render_template("admin_login.html")
    email = flask.request.form.get('email')
    password =flask.request.form.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        error = 'Please check your login details and try again.'
        return render_template('admin_login.html', error=error)# if the user doesn't exist or password is wrong, reload the page

    flask_login.login_user(user, remember=True)
    if 'admin' in flask_login.current_user.get_user_roles() :
        return flask.redirect(flask.url_for('admin_dashboard'))
    return flask.redirect(flask.url_for('home'))

@app.route('/protected')
@flask_login.login_required
def protected():
    return 'Logged in as: ' + flask_login.current_user.email

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized', 401

@app.route('/home')
@flask_login.login_required
def home():
    recentlyAdded = Book.query.order_by(Book.created_at.desc()).limit(5).all()
    recentlyUpdatedAlbums = BookSection.query.order_by(BookSection.updated_at.desc()).limit(5).all()
    allLanguages = Language.query.all()
    # topRated = db.session.query(Book, func.avg(Rating.rating).label('average_rating')).join(Rating).filter(Book.is_approved == True).group_by(Book.id).order_by(func.avg(Rating.rating).desc()).limit(5).all()
    Books = db.session.query(Book, func.avg(Rating.rating).label('average_rating'))\
            .join(Rating, Book.id == Rating.book_id)\
            .group_by(Book.id)\
            .order_by(desc('average_rating'))\
            .limit(5)\
            .all()
    topRated=[{'id': Book[0].id, 'name': Book[0].name, 'average_rating': Book[1]} for Book in Books]

    return render_template('home.html', recentlyAdded=recentlyAdded, recentlyUpdatedAlbums=recentlyUpdatedAlbums,
                           allLanguages=allLanguages, topRated=topRated)

@app.route('/')
def index():
    return flask.redirect(flask.url_for('login'))
@app.route('/my_albums')
@flask_login.login_required
def my_albums():
    return 'This is my_albums'
@app.route('/search')
@flask_login.login_required
def search():
    return 'This is admin search'
@app.route('/crud')
@flask_login.login_required
def crud():
    Authors = Author.query.all()
    languages = Language.query.all()
    return render_template('crud.html', authors=Authors, languages=languages)
@app.route('/book_management')
@flask_login.login_required
def book_management():
    return 'This is admin book_management'
@app.route('/logout', methods=['GET', 'POST'])
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return flask.redirect(flask.url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return 'User already exists! Please log in.'
        # Create a new user
        role = Role.query.filter_by(name='user').first()
        new_user = User(username=username, email=email, password=generate_password_hash(password) )
        new_user.roles.append(role)
        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()
        return flask.redirect(flask.url_for('login'))
    # For GET request, render the registration form
    return render_template('register.html')

@app.route('/upgrade_creator', methods=['GET', 'POST'])
@flask_login.login_required
def upgrade_creator():
    if request.method == 'POST':
        user = User.query.get(flask_login.current_user.id)
        creator_role = Role.query.filter_by(name='creator').first()
        user.roles.clear()
        user.roles.append(creator_role)
        db.session.commit()
        return flask.redirect(flask.url_for('login'))
    return render_template('upgrade_creator.html')

@app.route('/add_new_Book', methods=['GET', 'POST'])
@flask_login.login_required
def add_new_Book():
    if request.method == 'POST' and 'admin' in flask_login.current_user.get_user_roles() :
        name = request.form['name']
        content = request.form['content']
        selected_section_id = request.form['selectedSectionId']
        selected_Author_id = request.form['selectedAuthorId']
        selected_language_id = request.form['selectedLanguageId']
        price = request.form['price']
        book = Book(name=name, content=content,
                    creator_id=flask_login.current_user.id, section_id=selected_section_id,
                 author_id=selected_Author_id, lang_id=selected_language_id, price = price)
        db.session.add(book)
        db.session.commit()
        message = 'Book uploaded successfully.'
        return render_template('add_Book.html', albums=BookSection.query.all(), authors=Author.query.all(),
                               languages=Language.query.all(), message=message)

    return render_template('add_Book.html', albums=BookSection.query.all(), authors=Author.query.all(),
                            languages=Language.query.all())


@app.route('/create_Author', methods=['POST'])
@flask_login.login_required
def create_Author():
    data = request.json
    new_Author = Author(name=data['name'])
    db.session.add(new_Author)
    db.session.commit()
    return jsonify(message='Author created successfully'), 200

@app.route('/create_language', methods=['POST'])
@flask_login.login_required
def create_language():
    data = request.json
    new_language = Language(name=data['name'])
    db.session.add(new_language)
    db.session.commit()
    return jsonify(message='Language created successfully'), 200

@app.route('/delete_genre/<int:genre_id>', methods=['GET'])
@flask_login.login_required
def delete_genre(genre_id):
    db.session.delete(genre)
    db.session.commit()
    return flask.redirect('/crud')

@app.route('/delete_Author/<int:Author_id>', methods=['GET'])
@flask_login.login_required
def delete_Author(Author_id):
    Author = Author.query.get_or_404(Author_id)
    db.session.delete(Author)
    db.session.commit()
    return flask.redirect('/crud')

@app.route('/delete_language/<int:language_id>', methods=['GET'])
@flask_login.login_required
def delete_language(language_id):
    language = Language.query.get_or_404(language_id)
    db.session.delete(language)
    db.session.commit()
    return flask.redirect('/crud')
@app.route('/latest_albums')
def latest_albums():
    latest_albums = BookSection.query.all()
    return render_template('latest_albums.html', latest_albums=latest_albums)

@app.route('/create_album', methods=['POST'])
def create_album():
    name = request.form.get('name')
    
    new_album = BookSection(name=name)
    db.session.add(new_album)
    db.session.commit()
    Books = Book.query.all()
    albums = BookSection.query.all()
    Authors = Author.query.all()
    languages = Language.query.all()
    return render_template('your_songs.html', Books=Books, albums=albums, Authors=Authors, languages=languages)

@app.route('/your_books')
def your_books():
    if flask_login.current_user.roles[0].name=='admin':
        songs = Book.query.all()
    albums = BookSection.query.all()
    artists = Author.query.all()
    languages = Language.query.all()
    return render_template('your_songs.html', songs=songs, albums=albums, artists=artists, languages=languages)



@app.route('/edit_book/<int:book_id>', methods=['POST', 'GET'])
def edit_book(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify(message='Book not found'), 404

    if request.method == 'POST':
        book.name = request.form.get('name')
        book.content = request.form.get('content')
        book.section_id  = request.form.get('album')
        book.author_id  = request.form.get('author')
        book.lang_id = request.form.get('lang')
        db.session.commit()
        return flask.redirect(flask.url_for('home')), 200

    albums = BookSection.query.all()
    authors = Author.query.all()
    languages = Language.query.all()

    return render_template('edit_book.html', book_id=book_id, song=book, albums=albums, authors=authors, languages=languages)


@app.route('/play_Book/<int:Book_id>')
def play_Book(Book_id):
    Book = Book.query.get(Book_id)
    if not Book:
        return 'Book not found', 404
    music_file_path = f'uploads/{Book.music_file}'
    data = {
        'title': Book.name,
        'lyrics': Book.lyrics,
        'language': Book.lang,
        'Author': Book.Author,
        # 'average_rating': average_rating
    }
    return send_file(music_file_path, as_attachment=False), 200, data
@app.route('/get_book_metadata/<int:book_id>')
def get_book_metadata(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify(message='Book not found'), 404

    existing_rating = Rating.query.filter_by(book_id=book_id, user_id=flask_login.current_user.id).first()
    ratings = Rating.query.filter_by(book_id=book_id).all()
    total_ratings = len(ratings)
    total_rating_value = sum(rating.rating for rating in ratings)

    average_rating = total_rating_value / total_ratings if total_ratings > 0 else 0

    metadata = {
        'title': book.name,
        'content': book.content,
        'language': Language.query.get(book.lang_id).name,
        'artist': Author.query.get(book.author_id).name,
        'album_id': BookSection.query.get(book.section_id ).name,
        'existing_rating': existing_rating.rating if existing_rating else None,
        'average_rating': average_rating
    }
    return jsonify(metadata), 200
@app.route('/rate_book/<int:book_id>', methods=['POST'])
def rate_book(book_id):
    rating_value = int(request.form.get('rating'))
    if rating_value < 1 or rating_value > 5:
        return jsonify(message='Invalid rating value'), 400

    # Assuming you have a way to identify the current user, e.g., through session
    user_id = flask_login.current_user.id

    # Check if the user has already rated this Book
    existing_rating = Rating.query.filter_by(book_id=book_id, user_id=user_id).first()
    if existing_rating:
        existing_rating.rating = rating_value
    else:
        new_rating = Rating(book_id=book_id, user_id=user_id, rating=rating_value)
        db.session.add(new_rating)

    db.session.commit()
    return flask.redirect(flask.url_for('home'))
@app.route('/albums')
def albums():    
    albums = BookSection.query.all()
    return render_template('albums.html', albums=albums)
@app.route('/album_books/<int:section_id>')
def album_books(section_id):
    section = BookSection.query.get(section_id)
    books = Book.query.filter_by(section_id=section_id).all()
    return render_template('album_books.html', section_name=section.name, songs=books)

@app.route('/all_books')
def all_books():
    books = Book.query.all()
    return render_template('all_books.html', songs=books)
@app.route('/delete_book/<int:book_id>', methods=['GET'])
def delete_book(book_id):
    book = Book.query.get(book_id)
    if not book:
        return 'Book not found', 404
    db.session.delete(book)
    db.session.commit()
    return flask.redirect(flask.url_for('your_books'))

@app.route('/search_books')
def search_books():
    search_query = request.args.get('q', '')
    search_results = Book.query.join(BookSection).join(Author).filter(
        (Book.name.ilike(f'%{search_query}%')) |
        (BookSection.name.ilike(f'%{search_query}%')) |
        (Author.name.ilike(f'%{search_query}%'))
    ).all()
    albums = BookSection.query.all()
    return render_template('search_books.html', search_query=search_query, search_results=search_results, albums=albums)

@app.route('/languages/<int:langId>')
def all_languages(langId):
    language = Language.query.get(langId)
    if not language:
        return 'Language not found', 404

    books = Book.query.filter_by(lang_id=langId).all()
    return render_template('language_books.html', language=language, songs=books)
@app.route('/delete_creator_album/<int:album_id>', methods=['GET'])
def delete_creator_album(album_id):
    Book = BookSection.query.get(album_id)
    if not Book:
        return 'Book not found', 404
    db.session.delete(Book)
    db.session.commit()
    return flask.redirect(flask.url_for('your_books'))

@app.route('/admin/dashboard')
@flask_login.login_required
def admin_dashboard():
    # Get key statistics
    total_users = User.query.count()
    total_books = Book.query.count()
    total_albums = BookSection.query.count()
    total_ratings = Rating.query.count()

    return render_template('admin_dashboard.html', total_users=total_users, total_books=total_books, total_albums=total_albums, total_ratings=total_ratings)

@app.route('/admin/users')
@flask_login.login_required
def admin_users():
    # Get all users
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/request_book/<int:book_id>')
def request_book(book_id):
    user_id = flask_login.current_user.id
    t_borrow = Borrowing.query.filter_by(user_id=user_id).filter(
    (Borrowing.returned == False) and (Borrowing.return_date > datetime.utcnow())
).all()
    if len(t_borrow)>=5:
        flask.flash('You have 5 active book requests', 'failure')
        return flask.redirect(flask.url_for('home'))

    book_request = Borrowing(user_id=user_id, book_id=book_id)
    db.session.add(book_request)
    db.session.commit()
    flask.flash('Book request sent successfully', 'success')
    return flask.redirect(flask.url_for('home'))

@app.route('/user_collection')
def user_collection():
    user_id = flask_login.current_user.id
    approved_books = Book.query.join(Borrowing).filter(
        Borrowing.user_id == user_id,
        Borrowing.approved == True,
        Borrowing.returned == False,
        Borrowing.return_date > datetime.utcnow()
    ).all()
    requested_books = Book.query.join(Borrowing).filter(
        Borrowing.user_id == user_id,
        Borrowing.approved == False,
        Borrowing.returned == False, 
    ).all()
    expired_books = Book.query.join(Borrowing).filter(
        Borrowing.user_id == user_id,
        Borrowing.approved == True,
        (Borrowing.returned == True) | (Borrowing.return_date < datetime.utcnow())
    ).all()
    return render_template('collection.html', songs=approved_books, asongs=requested_books, bsongs = expired_books)
@app.route('/book_approval')
def book_approval():
    unapproved_borrowings = Borrowing.query.filter_by(approved=False).all()
    return render_template('book_request.html', unapproved_borrowings=unapproved_borrowings)

@app.route('/approve_borrowing/<int:borrowing_id>')
def approve_borrowing(borrowing_id):
    borrowing = Borrowing.query.get(borrowing_id)
    if not borrowing:
        return 'Borrowing not found', 404

    borrowing.approved = True
    db.session.commit()
    return flask.redirect(flask.url_for('book_approval'))

@app.route('/delete_borrowing/<int:borrowing_id>')
def delete_borrowing(borrowing_id):
    borrowing = Borrowing.query.get(borrowing_id)
    if not borrowing:
        return 'Borrowing not found', 404
    db.session.delete(borrowing)
    db.session.commit()
    return flask.redirect(flask.url_for('book_approval'))

@app.route('/return_borrowing/<int:borrowing_id>')
def return_borrowing(borrowing_id):
    borrowings = Borrowing.query.filter_by(book_id=borrowing_id,user_id = flask_login.current_user.id).all()
    if not borrowings:
        return 'Borrowing not found', 404
    for borrowing in borrowings:
        borrowing.returned = True
        db.session.commit()
    return flask.redirect(flask.url_for('user_collection'))

@app.route('/download/<int:borrowing_id>')
def download(borrowing_id):
    book = Book.query.get(borrowing_id)
    user = User.query.get(flask_login.current_user.id)
    if user.amount>=book.price:
        user.amount = user.amount-book.price
        db.session.commit()
        response = flask.make_response(generate_pdf(book))
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={book.name}.pdf'
        return response

    return flask.redirect(flask.url_for('user_collection'))
def generate_pdf(book):
    pdf_buffer = BytesIO()
    pdf = canvas.Canvas(pdf_buffer)
    pdf.setTitle(book.name)

    pdf.drawString(100, 800, f"Book Name: {book.name}")
    pdf.drawString(100, 780, f"Author: {book.author.name}")
    pdf.drawString(100, 760, f"Price: ${book.price}")
    pdf.drawString(100, 740, "Content:")
    
    y_position = 720
    lines = book.content.split('\n')
    for line in lines:
        pdf.drawString(120, y_position, line)
        y_position -= 20

    pdf.save()

    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()

@app.route('/all_issues')
def all_issues():
    borrowings = Borrowing.query.filter_by(approved=True, returned=False).join(User).all()
    return render_template('all_issues.html', borrowings=borrowings)

@app.route('/revoke_access/<int:borrowing_id>')
def revoke_access(borrowing_id):
    borrowing = Borrowing.query.get(borrowing_id)
    if borrowing:
        borrowing.returned = True
        db.session.commit()
        flask.flash('Access revoked successfully', 'success')
    else:
        flask.flash('Borrowing not found', 'error')
    return flask.redirect(flask.url_for('all_issues'))

@app.route('/request_recharge', methods=['POST', 'GET'])
def request_recharge():
    if request.method == 'POST':
        user_id = flask_login.current_user.id  
        amount = float(request.form['amount'])
        recharge_request = WalletRechargeRequest(user_id=user_id, amount=amount)
        db.session.add(recharge_request)
        db.session.commit()
        return flask.redirect(flask.url_for('home'))  
    money = User.query.filter_by(id=flask_login.current_user.id).first().amount
    return render_template('request_recharge.html', money=money)

@app.route('/admin/recharge_requests')
def recharge_requests():
    recharge_requests = WalletRechargeRequest.query.filter_by(status='pending').all()
    return render_template('admin_recharge_requests.html', recharge_requests=recharge_requests)

@app.route('/admin/approve_recharge/<int:request_id>')
def approve_recharge(request_id):
    recharge_request = WalletRechargeRequest.query.get(request_id)
    user = User.query.get(recharge_request.user_id)
    if user:
        user.amount = float(user.amount)+ recharge_request.amount
        db.session.commit()
        flask.flash('Amount added successfully', 'success')
    else:
        flask.flash('User not found', 'error')
    recharge_request.status = 'approved'
    db.session.commit()
    return flask.redirect(flask.url_for('recharge_requests'))

@app.route('/admin/reject_recharge/<int:request_id>')
def reject_recharge(request_id):
    recharge_request = WalletRechargeRequest.query.get(request_id)
    recharge_request.status = 'rejected'
    db.session.commit()
    return flask.redirect(flask.url_for('recharge_requests'))

if __name__ == '__main__':
    app.run(debug=True)


