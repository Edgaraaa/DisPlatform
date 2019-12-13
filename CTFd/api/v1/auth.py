from flask import (
    current_app as app,
    render_template,
    request,
    redirect,
    url_for,
    session,
    Blueprint,
)
from itsdangerous.exc import BadTimeSignature, SignatureExpired, BadSignature

from CTFd.models import db, Users, Teams

from CTFd.utils import get_config, get_app_config
from CTFd.utils.decorators import ratelimit
from CTFd.utils import user as current_user
from CTFd.utils import config, validators
from CTFd.utils import email
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.crypto import verify_password
from CTFd.utils.logging import log
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.config import is_teams_mode
from CTFd.utils.config.visibility import registration_visible
from CTFd.utils.modes import TEAMS_MODE
from CTFd.utils.security.signing import unserialize
from CTFd.utils.helpers import error_for, get_errors

import base64
import requests
from flask import session, request, abort
from flask_restplus import Namespace, Resource
from CTFd.models import (
    db,
    Users,
    Solves,
    Awards,
    Tracking,
    Unlocks,
    Submissions,
    Notifications,
)
from CTFd.utils.decorators import authed_only, admins_only, ratelimit
from CTFd.cache import clear_standings
from CTFd.utils.config import get_mail_provider
from CTFd.utils.email import sendmail, user_created_notification
from CTFd.utils.user import get_current_user, is_admin
from CTFd.utils.decorators.visibility import (
    check_account_visibility,
    check_score_visibility,
)

from CTFd.schemas.submissions import SubmissionSchema
from CTFd.schemas.awards import AwardSchema
from CTFd.schemas.users import UserSchema

auth_namespace = Namespace("auth",description="考虑如何登陆")

@auth_namespace.route("/login",methods=["POST","GET"])
@ratelimit(method="POST", limit=10, interval=5)
def login():
    errors = get_errors()
    if request.method == "POST":
        name = request.form["name"]

        # Check if the user submitted an email address or a team name
        if validators.validate_email(name) is True:
            user = Users.query.filter_by(email=name).first()
        else:
            user = Users.query.filter_by(name=name).first()

        if user:
            if user and verify_password(request.form["password"], user.password):
                session.regenerate()

                login_user(user)
                #log("logins", "[{date}] {ip} - {name} logged in")

                db.session.close()
                if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
                ):
                    return {
                        "success":True,
                        "next":request.args.get("next")
                    }
                return {
                    "success":True,
                    "next":"sss"
                }

            else:
                # This user exists but the password is wrong
                #log("logins", "[{date}] {ip} - submitted invalid password for {name}")
                errors.append("Your username or password is incorrect")
                db.session.close()
                return {
                    "success":False,
                    "error":errors
                }
                
        else:
            # This user just doesn't exist
            #log("logins", "[{date}] {ip} - submitted invalid account information")
            errors.append("Your username or password is incorrect")
            db.session.close()
            return {
                    "success":False,
                    "error":errors
                }
    else:
        db.session.close()
        return {
                    "success":False,
                    "error":errors
                }
