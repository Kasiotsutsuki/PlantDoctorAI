import os
import secrets
import numpy as np
from datetime import datetime, timedelta
from flask import Flask, request, render_template, send_from_directory
from werkzeug.utils import secure_filename
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import load_img, img_to_array
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from dotenv import load_dotenv
load_dotenv()



from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to continue", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function



app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)

# ===================== AUTH CONFIG =====================
# MySQL config
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = os.getenv("MYSQL_PASSWORD")
app.config["MYSQL_DB"] = "plant_doctor"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# ===================== MAIL CONFIG =====================
app.config["MAIL_SERVER"]   = "smtp.gmail.com"
app.config["MAIL_PORT"]     = 587
app.config["MAIL_USE_TLS"]  = True
app.config["MAIL_USERNAME"] = "yourgmail@gmail.com"
app.config["MAIL_PASSWORD"] = "xxxx xxxx xxxx xxxx"
app.config["MAIL_DEFAULT_SENDER"] = "yourgmail@gmail.com"
mail = Mail(app)

# ===================== UPLOAD CONFIG =====================
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ===================== LOAD MODEL =====================
model = load_model("model_v2.h5")
print("✅ Model loaded. Visit http://127.0.0.1:5000/")

# ===================== CLASS NAMES (38 classes) =====================
# These map exactly to the dataset class indices from training
CLASS_NAMES = {
    0:  "Apple Scab",
    1:  "Apple Black Rot",
    2:  "Apple Cedar Rust",
    3:  "Apple Healthy",
    4:  "Blueberry Healthy",
    5:  "Cherry Powdery Mildew",
    6:  "Cherry Healthy",
    7:  "Corn Gray Leaf Spot",
    8:  "Corn Common Rust",
    9:  "Corn Northern Leaf Blight",
    10: "Corn Healthy",
    11: "Grape Black Rot",
    12: "Grape Esca Black Measles",
    13: "Grape Leaf Blight",
    14: "Grape Healthy",
    15: "Orange Huanglongbing",
    16: "Peach Bacterial Spot",
    17: "Peach Healthy",
    18: "Bell Pepper Bacterial Spot",
    19: "Bell Pepper Healthy",
    20: "Potato Early Blight",
    21: "Potato Late Blight",
    22: "Potato Healthy",
    23: "Raspberry Healthy",
    24: "Soybean Healthy",
    25: "Squash Powdery Mildew",
    26: "Strawberry Leaf Scorch",
    27: "Strawberry Healthy",
    28: "Tomato Bacterial Spot",
    29: "Tomato Early Blight",
    30: "Tomato Late Blight",
    31: "Tomato Leaf Mold",
    32: "Tomato Septoria Leaf Spot",
    33: "Tomato Spider Mites",
    34: "Tomato Target Spot",
    35: "Tomato Yellow Leaf Curl Virus",
    36: "Tomato Mosaic Virus",
    37: "Tomato Healthy"
}

# ===================== DISEASE INFO (38 classes) =====================
disease_info = {
    "Apple Scab": {
        "description": "Dark, olive-green to brown scab-like lesions appear on leaves and fruit, causing distortion and premature leaf drop.",
        "cure": "Apply fungicides early in the season and remove fallen infected leaves to break the disease cycle."
    },
    "Apple Black Rot": {
        "description": "Causes circular brown lesions with purple borders on leaves, and rotting of fruit starting from the blossom end.",
        "cure": "Prune dead wood, remove mummified fruit, and apply copper-based fungicides during the growing season."
    },
    "Apple Cedar Rust": {
        "description": "Bright orange-yellow spots appear on upper leaf surfaces with tube-like growths on the underside.",
        "cure": "Remove nearby cedar trees if possible, and apply protective fungicides from bud break through early summer."
    },
    "Apple Healthy": {
        "description": "The leaf shows no signs of disease, with uniform green coloration and no lesions or abnormal growth.",
        "cure": "No treatment required. Maintain regular watering, fertilization, and monitoring."
    },
    "Blueberry Healthy": {
        "description": "Leaf appears healthy with no visible spots, lesions, or discoloration.",
        "cure": "No treatment required. Continue proper care and routine monitoring."
    },
    "Cherry Powdery Mildew": {
        "description": "White powdery fungal growth appears on young leaves and shoots, causing curling and distortion.",
        "cure": "Apply sulfur-based fungicides and ensure good air circulation by pruning dense canopy areas."
    },
    "Cherry Healthy": {
        "description": "Leaf appears healthy with uniform color and no visible disease symptoms.",
        "cure": "No treatment required. Continue proper care and routine monitoring."
    },
    "Corn Gray Leaf Spot": {
        "description": "Rectangular gray to tan lesions appear parallel to leaf veins, reducing photosynthesis significantly.",
        "cure": "Apply foliar fungicides and use resistant hybrids. Practice crop rotation to reduce disease pressure."
    },
    "Corn Common Rust": {
        "description": "Small, oval, reddish-brown pustules scattered across both leaf surfaces, releasing rust-colored spores.",
        "cure": "Apply fungicides at early sign of infection and use rust-resistant corn varieties."
    },
    "Corn Northern Leaf Blight": {
        "description": "Long, cigar-shaped gray-green lesions up to 15cm, causing significant yield loss in severe cases.",
        "cure": "Use resistant hybrids, apply fungicides when lesions first appear, and rotate crops annually."
    },
    "Corn Healthy": {
        "description": "Leaf shows uniform green color with no lesions or abnormal markings.",
        "cure": "No treatment required. Maintain proper fertilization and irrigation."
    },
    "Grape Black Rot": {
        "description": "Brown circular lesions with dark borders on leaves; fruit shrivels into hard black mummies.",
        "cure": "Remove infected plant material, apply fungicides from bud break, and ensure good canopy airflow."
    },
    "Grape Esca Black Measles": {
        "description": "Tiger-stripe pattern of yellowing and browning between leaf veins; can cause sudden vine collapse.",
        "cure": "Prune infected wood during dry weather, protect pruning wounds, and avoid water stress."
    },
    "Grape Leaf Blight": {
        "description": "Irregular brown lesions on leaves that dry out and cause premature defoliation.",
        "cure": "Apply copper-based fungicides and remove infected leaves promptly."
    },
    "Grape Healthy": {
        "description": "Leaf appears healthy with no visible disease symptoms or discoloration.",
        "cure": "No treatment required. Continue proper vineyard management practices."
    },
    "Orange Huanglongbing": {
        "description": "Asymmetric yellowing of leaves (blotchy mottle), small misshapen bitter fruit. A devastating bacterial disease with no cure.",
        "cure": "Remove and destroy infected trees immediately. Control Asian citrus psyllid insects that spread the disease."
    },
    "Peach Bacterial Spot": {
        "description": "Small water-soaked spots on leaves that turn brown with yellow halos, causing defoliation in severe cases.",
        "cure": "Apply copper-based bactericides during the growing season and avoid overhead irrigation."
    },
    "Peach Healthy": {
        "description": "Leaf appears healthy with uniform green color and no disease symptoms.",
        "cure": "No treatment required. Maintain regular pruning and monitoring."
    },
    "Bell Pepper Bacterial Spot": {
        "description": "Small, water-soaked lesions that become brown with yellow borders, affecting leaves and fruit.",
        "cure": "Use copper bactericides, avoid working with wet plants, and remove infected plant debris."
    },
    "Bell Pepper Healthy": {
        "description": "Leaf appears healthy with no visible spots, lesions, or abnormal coloration.",
        "cure": "No treatment required. Continue proper watering and fertilization."
    },
    "Potato Early Blight": {
        "description": "Dark brown spots with concentric rings forming a target pattern, typically on older lower leaves first.",
        "cure": "Apply fungicides, remove infected foliage, and practice crop rotation each season."
    },
    "Potato Late Blight": {
        "description": "Water-soaked lesions that rapidly turn brown and black, with white mold on the underside in humid conditions.",
        "cure": "Apply systemic fungicides immediately, destroy severely infected plants, and avoid overhead watering."
    },
    "Potato Healthy": {
        "description": "Leaf appears healthy with uniform green color and no disease symptoms.",
        "cure": "No treatment required. Maintain proper hilling and irrigation practices."
    },
    "Raspberry Healthy": {
        "description": "Leaf appears healthy with no visible disease symptoms.",
        "cure": "No treatment required. Continue proper pruning and monitoring."
    },
    "Soybean Healthy": {
        "description": "Leaf appears healthy with uniform green color and no lesions or discoloration.",
        "cure": "No treatment required. Maintain proper fertilization and pest monitoring."
    },
    "Squash Powdery Mildew": {
        "description": "White powdery coating on leaf surfaces that causes yellowing and premature leaf death.",
        "cure": "Apply potassium bicarbonate or sulfur-based fungicides and improve air circulation around plants."
    },
    "Strawberry Leaf Scorch": {
        "description": "Small purple spots that enlarge and cause leaf edges to appear scorched and brown.",
        "cure": "Remove infected leaves, apply appropriate fungicides, and avoid overhead irrigation."
    },
    "Strawberry Healthy": {
        "description": "Leaf appears healthy with uniform green color and no disease symptoms.",
        "cure": "No treatment required. Continue proper bed management and monitoring."
    },
    "Tomato Bacterial Spot": {
        "description": "Small, water-soaked dark spots on leaves that enlarge and may have yellow halos, spreading rapidly in warm wet weather.",
        "cure": "Apply copper bactericides, avoid overhead watering, and remove infected plant debris promptly."
    },
    "Tomato Early Blight": {
        "description": "Dark brown spots with concentric rings on older leaves, causing yellowing and defoliation from the bottom up.",
        "cure": "Remove infected lower leaves, apply fungicides, and mulch around plants to prevent soil splash."
    },
    "Tomato Late Blight": {
        "description": "Rapidly spreading water-soaked lesions that turn dark brown, with white mold visible in humid conditions.",
        "cure": "Apply systemic fungicides immediately at first sign. Remove and destroy severely infected plants."
    },
    "Tomato Leaf Mold": {
        "description": "Yellow patches on upper leaf surfaces with olive-green to gray mold on the underside, common in greenhouses.",
        "cure": "Improve ventilation, reduce humidity below 85%, and apply appropriate fungicides."
    },
    "Tomato Septoria Leaf Spot": {
        "description": "Numerous small circular spots with dark borders and light centers, causing heavy defoliation.",
        "cure": "Remove infected leaves, apply fungicides regularly, and avoid wetting foliage when watering."
    },
    "Tomato Spider Mites": {
        "description": "Tiny yellow or white stippling on leaves caused by spider mite feeding, with fine webbing visible on undersides.",
        "cure": "Apply miticides or neem oil, increase humidity, and introduce predatory mites as biological control."
    },
    "Tomato Target Spot": {
        "description": "Brown circular lesions with concentric rings and yellow halos, appearing during prolonged wet conditions.",
        "cure": "Avoid overhead irrigation, improve air circulation, and apply recommended fungicides."
    },
    "Tomato Yellow Leaf Curl Virus": {
        "description": "Leaves curl upward and turn yellow, with stunted plant growth. Spread by whiteflies.",
        "cure": "Remove infected plants immediately and control whitefly populations with insecticides or sticky traps."
    },
    "Tomato Mosaic Virus": {
        "description": "Mottled light and dark green pattern on leaves with distortion and stunted growth.",
        "cure": "Remove and destroy infected plants. Control aphid vectors and disinfect tools between plants."
    },
    "Tomato Healthy": {
        "description": "Leaf appears healthy with uniform green color and no signs of disease or infection.",
        "cure": "No treatment required. Maintain proper watering, staking, and routine monitoring."
    }
}

# ===================== ROUTES =====================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cur = mysql.connection.cursor()
        cur.execute(
    "SELECT id, name, email, password_hash, picture FROM users WHERE email = %s",
    (email,)
)

        user = cur.fetchone()
        cur.close()

        if user and bcrypt.check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            session["name"] = user["name"]
            session["picture"] = user.get("picture", "")
            flash("Logged in successfully", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html")

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('google_callback', _external=True)
    nonce = secrets.token_urlsafe(16)   # generate random nonce
    session['nonce'] = nonce            # save it in session
    return google.authorize_redirect(redirect_uri, nonce=nonce)  # send to Google

@app.route('/auth/google/callback')
def google_callback():
    token = google.authorize_access_token()

    # ✅ Retrieve nonce from session and pass it to parse_id_token
    nonce = session.pop('nonce', None)
    user_info = google.parse_id_token(token, nonce=nonce)

    # Get user details from Google
    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])  # fallback if name missing
    picture = user_info.get('picture', '')

    # ✅ Check if user already exists in MySQL
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, email FROM users WHERE email = %s", (email,))
    existing_user = cur.fetchone()

    if existing_user:
        # User already exists — update picture and log them in
        user_id = existing_user['id']
        cur.execute("UPDATE users SET picture = %s WHERE id = %s", (picture, user_id))
        mysql.connection.commit()
    else:
        # New Google user — insert into DB (no password needed)
        cur.execute(
            "INSERT INTO users (name, email, password_hash, picture) VALUES (%s, %s, %s, %s)",
            (name, email, '', picture)
        )
        mysql.connection.commit()
        user_id = cur.lastrowid

    cur.close()

    # ✅ Save user info to session (same keys as normal login)
    session['user_id'] = user_id
    session['name'] = name
    session['email'] = email
    session['picture'] = picture

    flash(f"Welcome, {name}!", "success")
    return redirect(url_for('index'))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if not name or not email or not password or not confirm:
            flash("All fields are required", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters long", "warning")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            cur.close()
            flash("Email already registered", "warning")
            return redirect(url_for("register"))

        cur.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
            (name, email, hashed_password)
        )
        mysql.connection.commit()
        new_user_id = cur.lastrowid  # ✅ get ID before closing
        cur.close()

        session["user_id"] = new_user_id
        session["email"] = email
        session["name"] = name

        flash("Account created successfully", "success")
        return redirect(url_for("index"))


    return render_template("register.html")


@app.route("/learn")
def learn():
    return render_template("learn.html")

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/predict", methods=["POST"])
@login_required
def predict():

    file = request.files["file"]
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    # Image preprocessing
    img = load_img(filepath, target_size=(224, 224))
    x = img_to_array(img) / 255.0
    x = np.expand_dims(x, axis=0)

    # Model prediction
    preds = model.predict(x)[0]
    sorted_indices = np.argsort(preds)[::-1]

    top1_idx = sorted_indices[0]
    top2_idx = sorted_indices[1]

    top1_label = CLASS_NAMES[top1_idx]
    top2_label = CLASS_NAMES[top2_idx]

    top1_conf = round(float(preds[top1_idx]) * 100, 2)
    top2_conf = round(float(preds[top2_idx]) * 100, 2)

    info = disease_info[top1_label]

    # ✅ SAVE SCAN TO DATABASE (USER-SPECIFIC)
    cur = mysql.connection.cursor()
    cur.execute(
        """
        INSERT INTO scan_history (user_id, disease, confidence, image_path)
        VALUES (%s, %s, %s, %s)
        """,
        (
            session["user_id"],
            top1_label,
            top1_conf,
            "/uploads/" + filename
        )
    )
    mysql.connection.commit()
    cur.close()

    return render_template(
        "result.html",
        prediction=top1_label,
        confidence=top1_conf,
        alt_prediction=top2_label,
        alt_confidence=top2_conf,
        description=info["description"],
        cure=info["cure"],
        image_path="/uploads/" + filename
    )


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

def get_user_scan_history(user_id, limit=10):
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT disease, confidence, image_path, created_at
        FROM scan_history
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (user_id, limit)
    )
    history = cur.fetchall()
    cur.close()
    return history

@app.context_processor
def inject_scan_history():
    if "user_id" in session:
        history = get_user_scan_history(session["user_id"])
    else:
        history = []
    return dict(scan_history=history)

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


# ===================== FORGOT PASSWORD =====================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name, password_hash FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            # Block Google-only accounts (no password set)
            if not user["password_hash"]:
                flash("This email is linked to a Google account. Please sign in with Google.", "warning")
                return redirect(url_for("forgot_password"))

            # Generate token
            token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=1)

            cur.execute(
                "UPDATE users SET reset_token = %s, reset_expiry = %s WHERE id = %s",
                (token, expiry, user["id"])
            )
            mysql.connection.commit()
            cur.close()

            # Send email
            reset_url = url_for("reset_password", token=token, _external=True)
            try:
                msg = Message(
                    subject="Reset Your Plant Doctor AI Password",
                    recipients=[email],
                    html=f"""
                    <div style="font-family:Poppins,sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#f7fbf7;border-radius:14px;">
                        <h2 style="color:#2e7d32;">🌱 Plant Doctor AI</h2>
                        <p>Hi {user['name']},</p>
                        <p>You requested a password reset. Click the button below to set a new password.</p>
                        <a href="{reset_url}" style="display:inline-block;background:#2e7d32;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:600;margin:20px 0;">Reset Password</a>
                        <p style="color:#777;font-size:0.85rem;">This link expires in 1 hour. If you did not request this, ignore this email.</p>
                    </div>
                    """
                )
                mail.send(msg)
            except Exception as e:
                print(f"Mail error: {e}")

        # Always show same message (security — don't reveal if email exists)
        flash("If that email is registered, a reset link has been sent.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT id, reset_expiry FROM users WHERE reset_token = %s",
        (token,)
    )
    user = cur.fetchone()

    if not user or datetime.now() > user["reset_expiry"]:
        cur.close()
        flash("Reset link is invalid or has expired.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form["password"]
        confirm  = request.form["confirm_password"]

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "warning")
            return redirect(request.url)

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        cur.execute(
            "UPDATE users SET password_hash = %s, reset_token = NULL, reset_expiry = NULL WHERE id = %s",
            (hashed, user["id"])
        )
        mysql.connection.commit()
        cur.close()
        flash("Password reset successfully! Please log in.", "success")
        return redirect(url_for("login"))

    cur.close()
    return render_template("reset_password.html", token=token)


# ===================== RUN (LAST LINE ONLY) =====================
if __name__ == "__main__":
    app.run(debug=True)