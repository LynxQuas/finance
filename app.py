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

    # all stock owned
    stocks = db.execute(
        "SELECT DISTINCT(symbol), SUM(shares) as total_shares FROM buy WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        session["user_id"],
    )
    all_stocks = []
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
        "cash"
    ]
    total_shares_value = 0
    share_value = cash

    for stock in stocks:
        stocks_lookedup = lookup(stock["symbol"])

        # looked up
        stock_info = {
            "name": stocks_lookedup["name"],
            "price": stocks_lookedup["price"],
            "symbol": stocks_lookedup["symbol"],
        }

        stock_info["shares"] = stock["total_shares"]
        # total price of shares
        stock_info["total"] = stock_info["price"] * stock_info["shares"]
        total_shares_value += stock_info["total"]
        all_stocks.append(stock_info)
        share_value = total_shares_value + cash

    return render_template(
        "index.html", all_stocks=all_stocks, share_value=share_value, cash=cash, usd=usd
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # if post
    if request.method == "POST":
        shares = request.form.get("shares")
        symbol = request.form.get("symbol").upper()
        details = lookup(symbol)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
            "cash"
        ]

        # check for valid input
        # negative number?
        if not shares or not symbol or not shares.isdigit() or not details:
            return apology("INVALID INPUTS!")

        price = details["price"]
        total_shares_cost = int(shares) * price

        if cash < total_shares_cost:
            return apology("not enough money")

        if int(shares) < 1:
            return apology("Invalid Shares!")
        elif not lookup(symbol):
            return apology("Invalid symbol")

        db.execute(
            "UPDATE users SET cash = cash - ? WHERE id = ?",
            total_shares_cost,
            session["user_id"],
        )

        # add the brought histroy to the shares table
        db.execute(
            "INSERT INTO buy (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            session["user_id"],
            symbol,
            int(shares),
            price,
        )

        flash(f"Bought {symbol} {shares} for {usd(total_shares_cost)} ")
        return redirect("/")

    # if get
    else:
        return render_template("buy.html")
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT * FROM buy WHERE user_id = ? ORDER BY timestamp", session["user_id"]
    )
    return render_template("history.html", transactions=transactions, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

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
        name = lookup(request.form.get("symbol"))
        if name:
            return render_template(
                "quoted.html",
                name=name["name"],
                price=usd(name["price"]),
                symbol=name["symbol"],
            )
        else:
            return apology("Invalid input")

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # get the data from userinputs
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        database_username = db.execute(
            "SELECT * FROM users WHERE username = ?", username.lower()
        )

        # check the possible errors
        if not username or not password or not confirmation:
            return apology("please fill the inputs")
        elif password != confirmation:
            return apology("password do not match")
        elif database_username:
            return apology("username is already taken")
        else:
            # hashed password and store in db.
            hashed_password = generate_password_hash(password, method="sha256")
            db.execute(
                "INSERT INTO users (username, hash) VALUES (? , ? )",
                username,
                hashed_password,
            )
            id = db.execute("SELECT * FROM users WHERE username = ?", username)
            session["user_id"] = id[0]["id"]
            return redirect("/")

    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    current_stock = db.execute(
        "SELECT symbol, SUM(shares) FROM buy WHERE user_id = ? AND shares > 0 GROUP BY symbol ",
        session["user_id"],
    )
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
        "cash"
    ]

    print(current_stock)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # possible errors
        if not symbol:
            return apology("Please fill the symbol")
        if not shares or not shares.isdigit() or int(shares) < 1:
            return apology("Invalid shares")
        # look up the stocks
        stocks = lookup(symbol)

        if not stocks:
            return apology("invalid stocks")

        for stock in current_stock:
            if stock["symbol"] == symbol:
                current_share = stock["SUM(shares)"]
                if current_share < int(shares):
                    return apology("not enough shares")

                price = stocks["price"]
                total_cash = cash + (price * int(shares))
                print(total_cash)
                db.execute(
                    "UPDATE users SET cash = ? WHERE id = ?",
                    total_cash,
                    session["user_id"],
                )
                db.execute(
                    "INSERT INTO buy (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                    session["user_id"],
                    symbol,
                    -int(shares),
                    price,
                )
                return redirect("/")

        print(f"current shares = {current_share}")

    else:
        return render_template("sell.html", cur_stocks=current_stock)