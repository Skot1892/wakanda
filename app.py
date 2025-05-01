from flask import Flask, render_template, redirect, url_for, request, session, jsonify, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename
from datetime import timedelta


app = Flask(__name__)

UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.permanent_session_lifetime = timedelta(minutes=15)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(300))
    category = db.Column(db.String(50), nullable=False) 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and bcrypt.check_password_hash(user.password, request.form["password"]):
            login_user(user)
            session.permanent = True
            return redirect(url_for("dashboard"))
    return render_template("login.html")

from flask_login import login_required

@app.route('/dashboard')
@login_required
def dashboard():
    orders = session.get('orders', [])
    recent_orders = orders[-5:]
    experiences = [item for item in recent_orders if 'experience' in item.get('name', '').lower()]
    return render_template('dashboard.html', orders=recent_orders, experiences=experiences)

@app.route("/products")
def products():
    souvenirs = Product.query.filter_by(category="souvenir").all()
    tours = Product.query.filter_by(category="tour").all()
    experiences = Product.query.filter_by(category="experience").all()
    return render_template("products.html", souvenirs=souvenirs, tours=tours, experiences=experiences)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

@app.route("/orders")
@login_required
def orders():
    return render_template("orders.html")

@app.route('/basket')
def basket():
    basket = session.get('basket', [])
    total = sum(item['price'] for item in basket)
    return render_template('basket.html', basket=basket, total=total)

@app.route('/add_to_basket/<int:product_id>', methods=['POST'])
def add_to_basket(product_id):
    product = Product.query.get_or_404(product_id)

    if 'basket' not in session:
        session['basket'] = []

    basket = session['basket']
    basket.append({
        'id': product.id,
        'name': product.name,
        'price': product.price
    })
    session['basket'] = basket

    return jsonify({
        'success': True,
        'basket_count': len(basket)
    })

@app.route('/remove_from_basket/<int:product_id>', methods=['POST'])
def remove_from_basket(product_id):
    basket = session.get('basket', [])

    for i, item in enumerate(basket):
        if item['id'] == product_id:
            basket.pop(i)
            break

    session['basket'] = basket

    return redirect(url_for('basket'))

@app.route('/checkout', methods=['POST'])
def checkout():
    basket = session.get('basket', [])

    if not basket:
        return redirect(url_for('basket'))

    orders = session.get('orders', [])
    orders.extend(basket)
    session['orders'] = orders

    session['basket'] = []

    session['order_complete'] = True

    return redirect(url_for('basket'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)  # Forbidden

    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/admin/add', methods=['POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        abort(403)

    name = request.form['name']
    price = request.form['price']
    category = request.form['category']
    description = request.form['description']

    image_file = request.files.get('image')
    image_url = None

    if image_file:
        filename = secure_filename(image_file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(upload_path)
        image_url = 'static/images/' + filename

    new_product = Product(
        name=name,
        price=price,
        category=category,
        description=description,
        image_url=image_url
    )
    db.session.add(new_product)
    db.session.commit()

    flash('Product added successfully!', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/delete/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()

    flash('Product deleted successfully!', 'success')
    return redirect(url_for('admin'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)