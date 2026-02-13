from flask import Flask, render_template,request,redirect,url_for,flash,session
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config  # import settings from config.py
import os
from werkzeug.utils import secure_filename
import razorpay
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib import colors
from flask import send_file
import io
from datetime import datetime






app = Flask(__name__)
app.secret_key=config.SECRET_KEY
app.config['SESSION_PERMANENT'] = True
app.permanent_session_lifetime = 86400  # 1 day


# upload folders (MUST come first)
app.config['UPLOAD_FOLDER'] = 'static/uploads/product_images'
app.config['ADMIN_UPLOAD_FOLDER'] = 'static/uploads/admin_profiles'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

os.makedirs(os.path.join(BASE_DIR, app.config['UPLOAD_FOLDER']), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, app.config['ADMIN_UPLOAD_FOLDER']), exist_ok=True)



# RAZORPAY................................................
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)
# SQLite Database Connection Setup

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_db_connection():
    conn = sqlite3.connect(os.path.join(BASE_DIR, "smartcart.db"), timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn




# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_USERNAME


mail = Mail(app)
# -----------------------------------------------------------------

@app.route('/')
def index():
    return redirect('/user-login')

@app.context_processor
def inject_admin():
    if 'admin_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (session['admin_id'],))
        admin = cursor.fetchone()

        cursor.close()
        conn.close()

        return dict(current_admin=admin)

    return dict(current_admin=None)


# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    # POST → Process signup
    name = request.form['name']
    email = request.form['email']

    #  Check if admin email already exists
    conn = get_db_connection()
    cursor = conn.cursor()   
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "admin_danger")
        return redirect('/admin-login')

    #  Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    #  Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = str(otp)

    #  Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "admin_success")
    return redirect('/verify-otp')



# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")



# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
    
    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "admin_danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "admin_success")
    return redirect('/admin-login')

# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if admin email exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "admin_danger")
        return redirect('/admin-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = admin['password']

    if isinstance(stored_hashed_password, str):
        stored_hashed_password = stored_hashed_password.encode('utf-8')
    else:
        stored_hashed_password = bytes(stored_hashed_password)

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):

        flash("Incorrect password! Try again.", "admin_danger")
        return redirect('/admin-login')

    # Step 5: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "admin_success")
    return redirect('/admin-dashboard')



# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "admin_danger")
        return redirect('/admin-login')
    admin_id=session['admin_id']
    conn = get_db_connection()
    cursor = conn.cursor()    # 1️⃣ Total products count
    cursor.execute("SELECT COUNT(*) AS total_products FROM products WHERE admin_id=?",(admin_id,))
    total_products = cursor.fetchone()['total_products']

    # 2️⃣ Total inventory value
    cursor.execute("SELECT SUM(price) AS total_value FROM products WHERE admin_id=?",(admin_id,))
    result = cursor.fetchone()

    # If table empty, SUM returns None
    total_value = result['total_value'] if result['total_value'] else 0

    # Admin name
    admin_name = session.get('admin_name')

    cursor.close()
    conn.close()
    


    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", total_products=total_products, total_value=total_value, admin_name=admin_name)



# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "admin_success")
    return redirect('/admin-login')

# ------------------- IMAGE UPLOAD PATH -------------------


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "admin_danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")



# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "admin_danger")
        return redirect('/admin-login')

    # 1️⃣ Get form data
    admin_id = session['admin_id']

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if image_file.filename == "":
        flash("Please upload a product image!", "admin_danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure the file name
    filename = secure_filename(image_file.filename)

    # 4️⃣ Create full path
    image_path = os.path.join(BASE_DIR, app.config['UPLOAD_FOLDER'], filename)


    # 5️⃣ Save image into folder
    image_file.save(image_path)

    # 6️⃣ Insert product into database
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO products (name, description, category, price, image, admin_id) VALUES (?,?,?,?,?,?)",
        (name, description, category, price, filename,admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "admin_success")
    return redirect('/admin/add-item')

# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "admin_danger")
        return redirect('/admin-login')
    
    admin_id = session['admin_id']

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()
    # 1️⃣ Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products WHERE admin_id=?",(admin_id,))
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE admin_id=?"
    params = [admin_id]

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )



#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "admin_danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    admin_id = session['admin_id']

    cursor.execute("SELECT * FROM products WHERE product_id=? AND admin_id=?",(item_id, admin_id))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "admin_danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "admin_danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=? AND admin_id=?", (item_id,session['admin_id']))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "admin_danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "admin_danger")
        return redirect('/admin-login')
    
    admin_id = session['admin_id']

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor()    
    cursor.execute("SELECT * FROM products WHERE product_id = ? and admin_id=?", (item_id, admin_id))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "admin_danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(BASE_DIR,app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(BASE_DIR,app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
        UPDATE products
        SET name=?, description=?, category=?, price=?, image=?
        WHERE product_id=? AND admin_id=?
    """, (name, description, category, price, final_image_name, item_id,admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "admin_success")
    return redirect('/admin/item-list')

# =================================================================
# ROUTE 13: DELETE PRODUCT
# =================================================================
@app.route('/admin/delete-item/<int:item_id>', methods=['POST'])
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "admin_danger")
        return redirect('/admin-login')

    # Fetch product to get image name
    conn = get_db_connection()
    cursor = conn.cursor()    
    cursor.execute("SELECT * FROM products WHERE product_id = ? AND admin_id=?", (item_id,session['admin_id']))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "admin_danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete product from database
    cursor.execute("DELETE FROM products WHERE product_id = ? AND admin_id=?", (item_id,session['admin_id']))
    conn.commit()
    cursor.close()
    conn.close()

    # Delete image file
    image_path = os.path.join(BASE_DIR, app.config['UPLOAD_FOLDER'], image_name)

    if os.path.exists(image_path):
        os.remove(image_path)

    flash("Product deleted successfully!", "admin_success")
    return redirect('/admin/item-list')

# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "admin_danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "admin_danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()
    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(BASE_DIR,app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(BASE_DIR,app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "admin_success")
    return redirect('/admin/profile')

#----------------------------------------USER---------------------------------------------------------------
# REGISTER

@app.route('/register', methods=['GET','POST'])
def user_register():

    if request.method == 'GET':
        return render_template('user/register.html')

    name = request.form['name']
    email = request.form['email']
    password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO users (name,email,password) VALUES (?,?,?)",
                   (name,email,password))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Registration successful. Please login.","user_success")
    return redirect('/user-login')

#---------------------------------------------
# LOG IN

@app.route('/user-login', methods=['GET','POST'])
def user_login():

    if request.method == 'GET':
        return render_template('user/login.html')

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?",(email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Invalid email","user_danger")
        return redirect('/user-login')

    stored_password = user['password']

    # convert to bytes if string
    if isinstance(stored_password, str):
        stored_password = stored_password.encode('utf-8')
    else:
        stored_password = bytes(stored_password)
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        flash("Wrong password","user_danger")
        return redirect('/user-login')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']

    return redirect('/dashboard')

#-----------------------------------------------------
# LOG OUT

@app.route('/logout-user')
def logout_user():
    session.pop('user_id',None)
    session.pop('user_name',None)
    return redirect('/user-login')

#========================================================
# DASHBOARD

@app.route('/dashboard')
def dashboard():

    if 'user_id' not in session:
        return redirect('/user-login')

    search = request.args.get('search','')
    category = request.args.get('category','')

    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%"+search+"%")

    if category:
        query += " AND category=?"
        params.append(category)

    cursor.execute(query,params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user/dashboard.html',
                           products=products,
                           search=search,
                           selected_category=category)

#-----------------------------------------------------------
# PRODUCT DETAILS

@app.route('/product/<int:product_id>')
def product_detail(product_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=?",(product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('user/product_details.html',product=product)
#--------------------------------------------
# Send OTP Mail
import time

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():

    if request.method == 'GET':
        return render_template('user/forgot_password.html')

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?",(email,))
    user = cursor.fetchone()

    if not user:
        flash("Email not registered","user_danger")
        return redirect('/forgot-password')

    # generate otp
    otp = str(random.randint(100000,999999))
    expiry = int(time.time()) + 300   # 5 minutes

    cursor.execute(
        "UPDATE users SET reset_otp=?, otp_expiry=? WHERE email=?",
        (otp,expiry,email)
    )
    conn.commit()

    # send mail
    msg = Message("SmartCart Password Reset",
                  sender=config.MAIL_USERNAME,
                  recipients=[email])
    msg.body = f"Your SmartCart password reset OTP is: {otp} (valid 5 minutes)"
    mail.send(msg)

    cursor.close()
    conn.close()

    flash("OTP sent to your email","user_success")
    return redirect('/reset-password')

#---------------------------------------------------------------
# Re-Set Password

@app.route('/reset-password', methods=['GET','POST'])
def reset_password():

    if request.method == 'GET':
        return render_template('user/reset_password.html')

    email = request.form['email']
    otp = request.form['otp']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?",(email,))
    user = cursor.fetchone()

    if not user:
        flash("Invalid email","user_danger")
        return redirect('/reset-password')

    import time
    current_time = int(time.time())

    if user['reset_otp'] != otp or current_time > user['otp_expiry']:
        flash("OTP invalid or expired","user_danger")
        return redirect('/reset-password')

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute(
        "UPDATE users SET password=?, reset_otp=NULL, otp_expiry=NULL WHERE email=?",
        (hashed,email)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Password updated. Please login.","user_success")
    return redirect('/user-login')
#-------------------------------------------------------
# About
@app.route('/about')
def about():
    return render_template('user/about.html')
#------------------------------------------------------------
# Contact
@app.route('/contact', methods=['GET','POST'])
def contact():

    # When user submits form
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # (For now we just show success message)
        flash("Message sent successfully! We will contact you soon.", "user_success")
        return redirect('/contact')

    # When page opens normally
    return render_template('user/contact.html')



#----------------------------------------------------
# Add To Cart
@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    # check if product already in cart
    cursor.execute(
        "SELECT * FROM cart WHERE user_id=? AND product_id=?",
        (user_id, product_id)
    )
    item = cursor.fetchone()

    if item:
        # increase quantity
        cursor.execute(
            "UPDATE cart SET quantity=quantity+1 WHERE user_id=? AND product_id=?",
            (user_id, product_id)
        )
    else:
        # insert new item
        cursor.execute(
            "INSERT INTO cart (user_id,product_id,quantity) VALUES (?,?,1)",
            (user_id, product_id)
        )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Item added to cart","user_success")
    return redirect('/dashboard')
#----------------------------------------------
#cart
@app.route('/cart')
def cart():

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.*, c.quantity, (p.price*c.quantity) AS subtotal
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id=?
    """, (user_id,))

    items = cursor.fetchall()

    total = sum(float(item['subtotal']) for item in items)

    cursor.close()
    conn.close()

    return render_template('user/cart.html', items=items, total=total)
# Increase Quantity
@app.route('/increase/<int:product_id>')
def increase(product_id):

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE cart SET quantity=quantity+1 WHERE user_id=? AND product_id=?",
        (user_id, product_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/cart')
#Decrease Quantity

@app.route('/decrease/<int:product_id>')
def decrease(product_id):

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT quantity FROM cart WHERE user_id=? AND product_id=?",
        (user_id, product_id)
    )
    item = cursor.fetchone()

    if item['quantity'] <= 1:
        cursor.execute(
            "DELETE FROM cart WHERE user_id=? AND product_id=?",
            (user_id, product_id)
        )
    else:
        cursor.execute(
            "UPDATE cart SET quantity=quantity-1 WHERE user_id=? AND product_id=?",
            (user_id, product_id)
        )

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/cart')

# Remove item
@app.route('/remove/<int:product_id>')
def remove(product_id):

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM cart WHERE user_id=? AND product_id=?",
        (user_id, product_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return redirect('/cart')

# Cart badge
@app.context_processor
def cart_count():

    if 'user_id' not in session:
        return dict(cart_count=0)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT SUM(quantity) FROM cart WHERE user_id=?",(session['user_id'],))
    count = cursor.fetchone()[0] or 0

    cursor.close()
    conn.close()

    return dict(cart_count=count)



@app.route('/profile')
def user_profile():

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id=?",(session['user_id'],))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('user/profile.html', user=user)

@app.context_processor
def global_categories():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    cursor.close()
    conn.close()

    return dict(categories=categories)

#------------------- CHECK OUT ----------------------------
@app.route('/checkout')
def checkout():

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id=session['user_id']

    conn=get_db_connection()
    cursor = conn.cursor()
    # addresses
    cursor.execute("SELECT * FROM addresses WHERE user_id=?",(user_id,))
    addresses=cursor.fetchall()

    # cart items
    cursor.execute("""
        SELECT c.product_id,c.quantity,p.name,p.price,p.image
        FROM cart c
        JOIN products p ON c.product_id=p.product_id
        WHERE c.user_id=?
    """,(user_id,))
    cart_items=cursor.fetchall()

    total=sum(float(item['price'])*item['quantity'] for item in cart_items)


    cursor.close()
    conn.close()

    return render_template('user/checkout.html',
                           addresses=addresses,
                           cart_items=cart_items,
                           total=total)

#-------------ADD ADDRESS----------------------------------
@app.route('/add-address', methods=['GET','POST'])
def add_address():

    if 'user_id' not in session:
        return redirect('/user-login')

    if request.method=='POST':

        data=(session['user_id'],
              request.form['full_name'],
              request.form['phone'],
              request.form['house'],
              request.form['area'],
              request.form['city'],
              request.form['state'],
              request.form['pincode'])

        conn=get_db_connection()
        cursor=conn.cursor()

        cursor.execute("""
        INSERT INTO addresses(user_id,full_name,phone,house,area,city,state,pincode)
        VALUES(?,?,?,?,?,?,?,?)
        """,data)

        conn.commit()
        cursor.close()
        conn.close()

        return redirect('/checkout')

    return render_template('user/add_address.html')
#------------CREATE ORDER + RAZORPAY ORDER-----------------
@app.route('/pay/<int:address_id>')
def pay(address_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id=session['user_id']

    conn=get_db_connection()
    cursor = conn.cursor()
    # get cart
    cursor.execute("""
        SELECT c.product_id,c.quantity,p.price
        FROM cart c
        JOIN products p ON c.product_id=p.product_id
        WHERE c.user_id=?
    """,(user_id,))
    cart_items=cursor.fetchall()

    if not cart_items:
        return redirect('/cart')

    total=sum(float(item['price'])*item['quantity'] for item in cart_items)


    # create order
    cursor.execute("""
        INSERT INTO orders(user_id,address_id,total_amount,payment_status)
        VALUES(?,?,?,'PENDING')
    """,(user_id,address_id,total))

    order_id=cursor.lastrowid

    # insert order items
    for item in cart_items:
        cursor.execute("""
        INSERT INTO order_items(order_id,product_id,quantity,price)
        VALUES(?,?,?,?)
        """,(order_id,item['product_id'],item['quantity'],item['price']))

    conn.commit()

    # create razorpay order
    razor_order=razorpay_client.order.create({
        "amount":int(total*100),
        "currency":"INR",
        "payment_capture":"1"
    })

    cursor.execute("""
        UPDATE orders SET razorpay_order_id=? WHERE order_id=?
    """,(razor_order['id'],order_id))

    conn.commit()
    cursor.close()
    conn.close()

    return render_template("user/payment.html",
                           razorpay_key=config.RAZORPAY_KEY_ID,
                           razorpay_order_id=razor_order['id'],
                           amount=int(total*100),
                           total=total,
                           order_db_id=order_id)

#---------PAYMENT SUCCESS------------------------
@app.route('/payment-success/<int:order_id>/<payment_id>')
def payment_success(order_id,payment_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id=session['user_id']

    conn=get_db_connection()
    cursor=conn.cursor()

    cursor.execute("""
        UPDATE orders SET payment_status='PAID'
        WHERE order_id=?
    """,(order_id,))

    # NOW clear cart
    cursor.execute("DELETE FROM cart WHERE user_id=?",(user_id,))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect(f"/order-success/{order_id}")
# ---------------------ORDER SUCCESS-------------------------
@app.route('/order-success/<int:order_id>')
def order_success(order_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    return render_template('user/order_success.html',order_id=order_id)
#-------------INVOICE DOWNLOAD---------------------------
@app.route('/invoice/<int:order_id>')
def download_invoice(order_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    # ---- Fetch Order ----
    cursor.execute("""
        SELECT o.*, u.name, u.email,
               a.full_name, a.phone, a.house, a.area, a.city, a.state, a.pincode
        FROM orders o
        JOIN users u ON o.user_id = u.user_id
        JOIN addresses a ON o.address_id = a.address_id
        WHERE o.order_id=? AND o.user_id=?
    """,(order_id,session['user_id']))
    order = cursor.fetchone()

    # ---- Fetch Items ----
    cursor.execute("""
        SELECT oi.quantity, oi.price, p.name
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id=?
    """,(order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    # -------- Create PDF --------
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    width, height = A4

    # HEADER
    pdf.setFillColorRGB(0.1,0.2,0.4)
    pdf.rect(0, height-80, width, 80, fill=1)

    pdf.setFillColor(colors.white)
    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(40, height-50, "SmartCart")

    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, height-65, "Online Shopping Invoice")

    # ORDER INFO
    pdf.setFillColor(colors.black)
    pdf.setFont("Helvetica", 11)

    pdf.drawString(400, height-50, f"Invoice #: {order_id}")
    order_date = datetime.strptime(order['created_at'], "%Y-%m-%d %H:%M:%S")
    pdf.drawString(400, height-65, f"Date: {order_date.strftime('%d-%m-%Y')}")


    # BUYER DETAILS
    y = height-120
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Buyer Details")

    pdf.setFont("Helvetica", 11)
    y -= 20
    pdf.drawString(40, y, f"Name: {order['name']}")
    y -= 15
    pdf.drawString(40, y, f"Email: {order['email']}")

    # DELIVERY ADDRESS
    y -= 30
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Delivery Address")

    pdf.setFont("Helvetica", 11)
    y -= 20
    pdf.drawString(40, y, order['full_name'])
    y -= 15
    pdf.drawString(40, y, order['house'] + ", " + order['area'])
    y -= 15
    pdf.drawString(40, y, order['city'] + ", " + order['state'] + " - " + order['pincode'])
    y -= 15
    pdf.drawString(40, y, "Phone: " + order['phone'])

    # TABLE HEADER
    y -= 40
    pdf.setFillColorRGB(0.9,0.9,0.9)
    pdf.rect(40, y, width-80, 25, fill=1)

    pdf.setFillColor(colors.black)
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(50, y+8, "Product")
    pdf.drawString(300, y+8, "Qty")
    pdf.drawString(350, y+8, "Price")
    pdf.drawString(430, y+8, "Total")

    # ITEMS
    pdf.setFont("Helvetica", 11)
    y -= 25

    grand_total = 0

    for item in items:
        total = item['quantity'] * float(item['price'])
        grand_total += total

        pdf.drawString(50, y, item['name'])
        pdf.drawString(300, y, str(item['quantity']))
        pdf.drawString(350, y, f"₹{item['price']}")
        pdf.drawString(430, y, f"₹{total}")

        y -= 20

    # TOTAL BOX
    y -= 20
    pdf.setFillColorRGB(0.8,0.95,0.8)
    pdf.rect(300, y, 200, 40, fill=1)

    pdf.setFillColor(colors.black)
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(310, y+22, "Grand Total:")
    pdf.drawString(420, y+22, f"₹{grand_total}")

    # PAYMENT DETAILS
    y -= 60
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Payment Details")

    pdf.setFont("Helvetica", 11)
    y -= 20
    pdf.drawString(40, y, "Payment Mode: Online (Razorpay)")
    y -= 15
    pdf.drawString(40, y, f"Payment Status: {order['payment_status']}")

    # FOOTER
    pdf.setFillColor(colors.grey)
    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawString(40, 60, "Thank you for shopping with SmartCart!")
    pdf.drawString(40, 45, "This is a computer generated invoice and does not require signature.")

    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f"SmartCart_Invoice_{order_id}.pdf",
                     mimetype='application/pdf')

#---------------------ORDER HISTORY--------------------------
@app.route('/my-orders')
def my_orders():

    if 'user_id' not in session:
        return redirect('/user-login')

    user_id=session['user_id']

    conn=get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM orders
        WHERE user_id=?
        ORDER BY created_at DESC
    """,(user_id,))
    orders=cursor.fetchall()
    
    orders = [dict(order) for order in orders]
    for order in orders:
        cursor.execute("""
            SELECT oi.quantity,oi.price,p.name,p.image
            FROM order_items oi
            JOIN products p ON oi.product_id=p.product_id
            WHERE oi.order_id=?
        """,(order['order_id'],))
        order['items']=cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user/orders.html',orders=orders)

if __name__ == '__main__':
    app.run(debug=True)
