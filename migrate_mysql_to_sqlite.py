import mysql.connector
import sqlite3

# -------- MYSQL CONNECTION --------
mysql_conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Siva@2002",        # your XAMPP mysql password (usually empty)
    database="smallcart"  # change if your DB name different
)

mysql_cursor = mysql_conn.cursor(dictionary=True)

# -------- SQLITE CONNECTION --------
sqlite_conn = sqlite3.connect("smartcart.db")
sqlite_conn.row_factory = sqlite3.Row
sqlite_cursor = sqlite_conn.cursor()

print("Connected to both databases")

# ---------------- ADMIN ----------------
mysql_cursor.execute("SELECT * FROM admin")
admins = mysql_cursor.fetchall()

for a in admins:
    sqlite_cursor.execute("""
        INSERT OR REPLACE INTO admin(admin_id,name,email,password,profile_image)
        VALUES(?,?,?,?,?)
    """,(a['admin_id'],a['name'],a['email'],a['password'],a['profile_image']))

print("Admin migrated")

# ---------------- USERS ----------------
mysql_cursor.execute("SELECT * FROM users")
users = mysql_cursor.fetchall()

for u in users:
    sqlite_cursor.execute("""
        INSERT OR REPLACE INTO users(user_id,name,email,password,created_at,reset_otp,otp_expiry)
        VALUES(?,?,?,?,?,?,?)
    """,(u['user_id'],u['name'],u['email'],u['password'],u['created_at'],u['reset_otp'],u['otp_expiry']))

print("Users migrated")

# ---------------- PRODUCTS ----------------
mysql_cursor.execute("SELECT * FROM products")
products = mysql_cursor.fetchall()

for p in products:
    sqlite_cursor.execute("""
        INSERT OR REPLACE INTO products(product_id,name,description,category,price,image,admin_id)
        VALUES(?,?,?,?,?,?,?)
    """,(p['product_id'],p['name'],p['description'],p['category'],float(p['price']),p['image'],p['admin_id']))

print("Products migrated")

# ---------------- CART ----------------
mysql_cursor.execute("SELECT * FROM cart")
cart_items = mysql_cursor.fetchall()

for c in cart_items:
    sqlite_cursor.execute("""
        INSERT OR REPLACE INTO cart(cart_id,user_id,product_id,quantity,added_at)
        VALUES(?,?,?,?,?)
    """,(c['cart_id'],c['user_id'],c['product_id'],c['quantity'],c['added_at']))

print("Cart migrated")

# ---------------- ADDRESSES ----------------
mysql_cursor.execute("SELECT * FROM addresses")
addresses = mysql_cursor.fetchall()

for a in addresses:
    sqlite_cursor.execute("""
        INSERT OR REPLACE INTO addresses(address_id,user_id,full_name,phone,house,area,city,state,pincode,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)
    """,(a['address_id'],a['user_id'],a['full_name'],a['phone'],a['house'],a['area'],a['city'],a['state'],a['pincode'],a['created_at']))

print("Addresses migrated")

# ---------------- ORDERS ----------------
mysql_cursor.execute("SELECT * FROM orders")
orders = mysql_cursor.fetchall()

for o in orders:
    sqlite_cursor.execute("""
        INSERT OR REPLACE INTO orders(order_id,user_id,address_id,total_amount,payment_status,razorpay_order_id,created_at)
        VALUES(?,?,?,?,?,?,?)
    """,(o['order_id'],o['user_id'],o['address_id'],float(o['total_amount']),o['payment_status'],o['razorpay_order_id'],o['created_at']))

print("Orders migrated")

# ---------------- ORDER ITEMS ----------------
mysql_cursor.execute("SELECT * FROM order_items")
items = mysql_cursor.fetchall()

for i in items:
    sqlite_cursor.execute("""
        INSERT OR REPLACE INTO order_items(item_id,order_id,product_id,quantity,price)
        VALUES(?,?,?,?,?)
    """,(i['item_id'],i['order_id'],i['product_id'],i['quantity'],float(i['price'])))

print("Order items migrated")

# -------- COMMIT --------
sqlite_conn.commit()

mysql_conn.close()
sqlite_conn.close()

print("🎉 All data migrated successfully!")
