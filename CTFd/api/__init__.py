from flask import Blueprint, current_app
from flask_restplus import Api
from CTFd.api.v1.challenges import challenges_namespace

from CTFd.api.v1.teams import teams_namespace
from CTFd.api.v1.users import users_namespace
from CTFd.api.v1.scoreboard import scoreboard_namespace
from CTFd.api.v1.statistics import statistics_namespace
from CTFd.api.v1.submissions import submissions_namespace
from CTFd.api.v1.tags import tags_namespace
from CTFd.api.v1.awards import awards_namespace
from CTFd.api.v1.hints import hints_namespace
from CTFd.api.v1.flags import flags_namespace
from CTFd.api.v1.files import files_namespace
from CTFd.api.v1.config import configs_namespace
from CTFd.api.v1.notifications import notifications_namespace
from CTFd.api.v1.pages import pages_namespace
from CTFd.api.v1.unlocks import unlocks_namespace
from CTFd.api.v1.auths import auths_namespace

api = Blueprint("api", __name__, url_prefix="/api/v1")
CTFd_API_v1 = Api(api, version="v1", doc=current_app.config.get("SWAGGER_UI"))

CTFd_API_v1.add_namespace(challenges_namespace, "/challenges")
CTFd_API_v1.add_namespace(tags_namespace, "/tags")
CTFd_API_v1.add_namespace(awards_namespace, "/awards")
CTFd_API_v1.add_namespace(hints_namespace, "/hints")
CTFd_API_v1.add_namespace(flags_namespace, "/flags")
CTFd_API_v1.add_namespace(submissions_namespace, "/submissions")
CTFd_API_v1.add_namespace(scoreboard_namespace, "/scoreboard")
CTFd_API_v1.add_namespace(teams_namespace, "/teams")
CTFd_API_v1.add_namespace(users_namespace, "/users")
CTFd_API_v1.add_namespace(statistics_namespace, "/statistics")
CTFd_API_v1.add_namespace(files_namespace, "/files")
CTFd_API_v1.add_namespace(notifications_namespace, "/notifications")
CTFd_API_v1.add_namespace(configs_namespace, "/configs")
CTFd_API_v1.add_namespace(pages_namespace, "/pages")
CTFd_API_v1.add_namespace(unlocks_namespace, "/unlocks")
CTFd_API_v1.add_namespace(auths_namespace,"/auths")
