from flask import Flask, render_template, redirect, session, url_for, request
from dbwork import *
import bcrypt

app = Flask(__name__)
app.secret_key = "eifuwne284rih3578tuhi4"


@app.route('/')
def index():
    return render_template("login.html")


@app.route('/', methods=["POST"])
def indexlogin():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("pass")
        print(email, password)
        print("Cpass: ", request.form.get("cpass"))
        if request.form.get("cpass") == None:
            password = bytes(password, 'utf-8')
            details = find(email, password)
            print(details)
            if details != None:
                if bcrypt.checkpw(password, details['password']):
                    print("Logged in successfully..")
                    session["username"] = email
                    return redirect(url_for("home"))
                else:
                    err = "Incorrect Login Details..."
                    return render_template("login.html", err=err)
            else:
                err = "No account registered with this credentials..."
                return render_template("login.html", err=err)
        else:
            cpass = request.form.get("cpass")
            if password == cpass:
                password = bytes(password, 'utf-8')
                hashed = bcrypt.hashpw(password, bcrypt.gensalt())
                a = insert(email, hashed)
                if a == True:
                    return render_template("login.html")
                else:
                    err = "Error, an account has already been registered on this email ID!"
                    return render_template("login.html", err=err)
            else:
                err = "Error, the passwords don't match!"
                return render_template("login.html", err=err)
    else:
        return render_template("login.html")


@app.route('/home/')
def home():
    if "username" in session:
        user = session["username"]
        user = user.split("@")
        user = user[0]
        return render_template('home.html', user=user)
    else:
        return redirect(url_for("index"))

@app.route('/logout/')
def logout():
    session.pop("username", None)
    return redirect(url_for("index"))


if __name__ == '__main__':
    app.run(debug=True)
