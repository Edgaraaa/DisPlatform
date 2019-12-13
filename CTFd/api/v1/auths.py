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

auths_namespace = Namespace("auths",description="考虑如何登陆")

@auths_namespace.route("/login",methods=["GET"])
def login():
    return {
        "a":"b"
    }