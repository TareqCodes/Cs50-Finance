import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    shares = db.execute("SELECT * FROM total WHERE user_id = ?", session["user_id"])

    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    # get the total
    total = 0
    currentPrice = {}
    for share in shares:
        temp = lookup(share["symbol"])
        currentPrice[share["symbol"]] = temp["price"]
        total += share["counter"] * currentPrice[share["symbol"]]

    if shares and user:
        return render_template("index.html", shares=shares, user=user, total=total, currentPrice=currentPrice)
    else:
        return apology("no shares", 200)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("no symbol", 400)

        if not lookup(request.form.get("symbol")):
            return apology("wrong symbol", 400)

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("shares must be a posative integer", 400)

        if not request.form.get("shares") or int(request.form.get("shares")) < 0:
            return apology("enter correct value", 400)
        stockDict = lookup(request.form.get("symbol"))  # contains values of stock
        print(stockDict)
        # chick if he has money(list of dict)
        cash = db.execute("SELECT CASH FROM users WHERE id = ?", session["user_id"])
        price = float(stockDict["price"]) * int(request.form.get("shares"))
        if cash[0]["cash"] < price:  # in html everthing is a string
            return apology("broke", 403)
        # new cash value to store
        newCash = cash[0]["cash"] - float(stockDict["price"]) * float(request.form.get("shares"))

        # ADD WHAT WE BOUGHT
        if not db.execute("SELECT *  FROM total WHERE user_id = ? AND symbol = ?", session["user_id"], request.form.get("symbol")):
            db.execute("INSERT INTO total (user_id, symbol, total, counter) VALUES (?, ?, ?, ?)",
                       session["user_id"], request.form.get("symbol"), price, int(request.form.get("shares")))
        else:
            db.execute("UPDATE total SET total = total + ? , counter = counter + ?", price, request.form.get("shares"))

        db.execute("INSERT INTO purchases (user_id, symbol, price, shares, status) VALUES (?, ?, ?, ?, ?)", session["user_id"], request.form.get(
            "symbol"), float(stockDict["price"]), float(request.form.get("shares")), "purchased")
        db.execute("UPDATE users SET cash = ? WHERE id = ?", newCash, session["user_id"])
        return redirect("/")
    else:
        return render_template("buy.html")
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    shares = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])

    return render_template("history.html", shares=shares)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted

        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("enter symbol", 400)

        quoted = lookup(request.form.get("symbol"))
        if not quoted:
            return apology("wrong", 400)
        return render_template("quoted.html", quoted=quoted)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("username dne", 400)

        name = request.form.get("username")
        if db.execute("SELECT * FROM users WHERE username = ? ", name):
            return apology("username already exists", 400)

        if not request.form.get("password") or not request.form.get("confirmation"):
            return apology("password and confirmation not provided", 400)

        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("password and confirmation don't match", 400)
        # if everything is good
        password = request.form.get("password")
        passHash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, passHash)
        return redirect("/login")
    else:
        return render_template("register.html")

    return apology("TODO")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol") or not request.form.get("shares"):
            return apology("input share", 400)

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("no negative", 400)
        # i did this because i didnt have a total table
        userShares = db.execute("SELECT * FROM total WHERE user_id = ? AND symbol = ? ",
                                session["user_id"], symbol)  # sum of num of shares
        # userShares = db.execute("SELECT SUM(shares) AS total FROM purchases WHERE status = ? ", "purchased")  # sum of num of shares
        print(userShares)
        if shares > userShares[0]["counter"]:
            return apology("u dont have enough", 400)
        currentPrice = lookup(symbol)
        total = currentPrice["price"] * shares  # total price of sold items
        # update total and substract sold shares
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total, session["user_id"])
        # update total
        db.execute("UPDATE total SET total = total - ? ,counter = counter - ? WHERE user_id = ?",
                   int(request.form.get("shares")), shares, session["user_id"])
        # add transaction to purchase table
        db.execute("INSERT INTO purchases (user_id, symbol, price, shares, status) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, currentPrice["price"], shares, "sold")

        return redirect("/")
    else:
        symbols = db.execute("SELECT DISTINCT symbol FROM purchases WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbols=symbols)


@app.route("/changePassword", methods=["GET", "POST"])
@login_required
def changePassword():
    """change password"""
    if request.method == "POST":
        if not request.form.get("oldPassword") or not request.form.get("newPassword"):
            return apology("oldPassword and newPassword not provided", 403)

        password = request.form.get("oldPassword")
       # passHash = generate_password_hash(password)
        oldPassHash = db.execute("SELECT hash FROM users WHERE id = ? ", session["user_id"])

        if not check_password_hash(oldPassHash[0]["hash"], password):
            return apology("wrong password", 403)

        newPass = request.form.get("newPassword")
        newHash = generate_password_hash(newPass)
        db.execute("UPDATE users  SET hash = ? WHERE id = ? ", newHash, session["user_id"])
        return redirect("/")
    else:
        return render_template("ChangePass.html")
