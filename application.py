import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///hgm.db")



def is_provided(field):
    if not request.form.get(field):
        return apology(f"must provide {field}", 403)


@app.route("/")
@login_required
def index():
    rows = db.execute("""
        SELECT ROUND(AVG(morning), 1), ROUND(AVG(supper), 1)
        FROM records
        WHERE user_id = :user_id
    """, user_id=session["user_id"])


    return render_template("index.html", rows=rows)

#@app.route("/admin", methods=["GET", "POST"])
#@login_required
#def edit():
#    if request.method == "POST":
#        db.execute("""
#        join the tables based on user ids. or create an overview page I assume 
#        """, user_id=session["admin_credentials"])

#        return ("/")

#    else:
#        return ("")





@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit():
    if request.method == "POST":
        db.execute("""
            INSERT INTO records (user_id, date, morning, supper)
            VALUES (:user_id, :date, :morning, :supper)
        """, user_id=session["user_id"], date = request.form.get("date"), morning = request.form.get("morning"), supper = request.form.get("supper"))
        flash("Submitted successfully")
        return redirect("/")

    else:
        return render_template("submit.html")


@app.route("/insulin", methods=["GET", "POST"])
@login_required
def insulin():
    if request.method == "POST":
        db.execute("""
            INSERT INTO insulin (user_id, date, morning_insulin, supper_insulin, other_insulin)
            VALUES (:user_id, :date, :morning_insulin, :supper_insulin, :other_insulin)
        """, user_id=session["user_id"], date = request.form.get("date"), morning_insulin = request.form.get("morning_insulin"), supper_insulin = request.form.get("supper_insulin"), other_insulin = request.form.get("other_insulin"))
        flash("Submitted successfully")
        return redirect("/")

    else:
        return render_template("insulin.html")


@app.route("/history")
@login_required
def history():
    blood_sugar = db.execute("""
    SELECT morning, supper, date
    FROM records
    WHERE user_id=:user_id
    """, user_id=session["user_id"])

    insulin_records = db.execute("""
    SELECT morning_insulin, supper_insulin, other_insulin, date
    FROM insulin
    WHERE user_id=:user_id
    """, user_id=session["user_id"])

    return render_template("history.html", blood_sugar=blood_sugar, insulin_records=insulin_records)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username and password was submitted
        result_checks = is_provided("username") or is_provided("password")
        if result_checks is not None:
            return result_checks

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

def validate(password):
    import re
    if len(password) < 8:
        return apology("Password should be at least 8 characters")
    elif not re.search("[0-9]", password):
        return apology("Password must have at least one number")
    elif not re.search("[A-Z]", password):
        return apology("Password must contain at least one capital letter")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        result_checks = is_provided("username") or is_provided("password") or is_provided("confirmation")
        if result_checks != None:
            return result_checks

        validation_error = validate(request.form.get("password"))
        if validation_error:
            return validation_error
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must be the same!")

        try:
            prim_key = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                    username=request.form.get("username"),
                    hash=generate_password_hash(request.form.get("password")))
        except:
            return apology("Username already exists", 403)

        if prim_key == None:
            return apology("Registration Error.", 403)
        session["user_id"] = prim_key
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
