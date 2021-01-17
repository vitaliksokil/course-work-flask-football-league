import os
import uuid
from datetime import datetime

from alembic import op
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_admin.menu import MenuLink
from flask_login import LoginManager, login_user, UserMixin, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_admin import Admin, AdminIndexView, form
from flask_admin.contrib.sqla import ModelView

from flask_security import current_user
from markupsafe import Markup
from sqlalchemy import event
from werkzeug.utils import secure_filename

from forms import LoginForm
import feedparser

from flask_uploads import UploadSet, IMAGES, configure_uploads, \
    patch_request_class

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///football.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mysecret'

app.config['UPLOADED_IMAGES_DEST'] = imagedir = 'static/images/uploads'
app.config['UPLOADED_IMAGES_URL'] = '/static/images/uploads/'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)

images = UploadSet('images', IMAGES)
configure_uploads(app, (images))
patch_request_class(app, 16 * 1024 * 1024)


@login_manager.user_loader
def load_user(admin_id):
    return Admin.query.get(int(admin_id))


def _list_thumbnail(view, context, model, name):
    if not model.img:
        return ''

    return Markup(
        '<img src="{model.img_url}" style="width: 150px;">'.format(model=model)
    )


def _imagename_uuid1_gen(obj, file_data):
    _, ext = os.path.splitext(file_data.filename)
    uid = uuid.uuid1()
    return secure_filename('{}{}'.format(uid, ext))


def get_site_info():
    site_info = SiteInfo.query.all()
    result = {}
    for item in site_info:
        result[item.key] = item.value

    return result


class AdminView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_login'))


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_login'))


class TeamView(AdminView):
    column_list = [
        'name', 'img', 'position'
    ]
    form_excluded_columns = ['members','achievements']
    column_formatters = {
        'img': _list_thumbnail
    }

    form_extra_fields = {
        'img': form.ImageUploadField(
            'Img',
            base_path=imagedir,
            url_relative_path='images/uploads/',
            namegen=_imagename_uuid1_gen,
        )
    }


class AchievementView(AdminView):
    column_list = [
        'title', 'img', 'achieved_at', 'description', 'created_at', 'team'
    ]
    form_excluded_columns = ['created_at']
    column_formatters = {
        'img': _list_thumbnail
    }

    form_extra_fields = {
        'img': form.ImageUploadField(
            'Img',
            base_path=imagedir,
            url_relative_path='images/uploads/',
            namegen=_imagename_uuid1_gen,
        )
    }


class LogoutMenuLink(MenuLink):
    def is_accessible(self):
        return current_user.is_authenticated


admin = Admin(app, index_view=MyAdminIndexView(), name='FootballLeague')


class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), unique=True)
    password = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@event.listens_for(Admin.password, 'set', retval=True)
def hash_user_password(target, value, oldvalue, initiator):
    if value != oldvalue:
        return bcrypt.generate_password_hash(value).decode('utf-8')
    return value


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    img = db.Column(db.String(200))
    position = db.Column(db.Integer, index=True)
    members = db.relationship("TeamMember", backref="team", lazy=True)
    achievements = db.relationship("Achievements", backref="team", lazy=True)

    def __str__(self):
        return self.name

    @property
    def img_url(self):
        return images.url(self.img)

    @property
    def img_path(self):
        if self.img is None:
            return
        return images.path(self.img)


@event.listens_for(Team, 'after_delete')
def del_image(mapper, connection, target):
    if target.img_path is not None:
        try:
            os.remove(target.img_path)
        except OSError:
            pass


class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    surname = db.Column(db.String(200))
    img = db.Column(db.String(200))
    role = db.Column(db.String(200), index=True)
    bio = db.Column(db.Text())
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))

    @property
    def img_url(self):
        return images.url(self.img)

    @property
    def img_path(self):
        if self.img is None:
            return
        return '/' + images.path(self.img)


class TeamMemberView(AdminView):
    column_list = [
        'name', 'surname', 'img', 'role', 'bio', 'team'
    ]

    column_formatters = {
        'img': _list_thumbnail
    }

    form_extra_fields = {
        'img': form.ImageUploadField(
            'Img',
            base_path=imagedir,
            url_relative_path='images/uploads/',
            namegen=_imagename_uuid1_gen,
        )
    }


@event.listens_for(TeamMember, 'after_delete')
def del_image(mapper, connection, target):
    if target.img_path is not None:
        try:
            os.remove(target.img_path)
        except OSError:
            pass


class Achievements(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    img = db.Column(db.String(200))
    achieved_at = db.Column(db.DateTime)
    description = db.Column(db.Text())
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))

    @property
    def img_url(self):
        return images.url(self.img)

    @property
    def img_path(self):
        if self.img is None:
            return
        return '/' + images.path(self.img)


@event.listens_for(Achievements, 'after_delete')
def del_image(mapper, connection, target):
    if target.img_path is not None:
        try:
            os.remove(target.img_path)
        except OSError:
            pass


class SiteInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(200))
    value = db.Column(db.Text())


admin.add_view(AdminView(Admin, db.session, name='Admins', url='/admins', endpoint='admins'))
admin.add_view(TeamView(Team, db.session))
admin.add_view(TeamMemberView(TeamMember, db.session))
admin.add_view(AchievementView(Achievements, db.session))
admin.add_view(AdminView(SiteInfo, db.session))
admin.add_link(MenuLink(name='Back to Site', url='/'))
admin.add_link(LogoutMenuLink(name='Logout', url='/admin/logout'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    site_info = get_site_info()
    if current_user.is_authenticated:
        return redirect('/admin')
    form = LoginForm()
    if form.validate_on_submit():
        user = Admin.query.filter_by(username=form.username.data).first()
        print(bcrypt.check_password_hash(user.password, form.password.data))
        print(form.password.data)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect('/admin')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('pages/admin-login.html', title='Login', form=form, site_info=site_info)


@app.route("/admin/logout")
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))


@app.route('/')
def index():
    site_info = get_site_info()
    return render_template('pages/index.html', site_info=site_info)


@app.route('/teams')
def team():
    site_info = get_site_info()
    team = Team.query.order_by('position').all()
    return render_template('pages/team.html', site_info=site_info, team=team)


@app.route('/teams/<team_id>/members')
def team_members(team_id):
    site_info = get_site_info()
    team = Team.query.filter_by(id=team_id).first()
    members = team.members
    coach = next(member for member in members if member.role == 'Coach')
    return render_template('pages/team-members.html', site_info=site_info, members=members, coach=coach)



@app.route('/achievements/<team_id>')
def achievements(team_id):
    site_info = get_site_info()
    team = Team.query.filter_by(id=team_id).first()
    achievements = team.achievements
    return render_template('pages/achievements.html', site_info=site_info, achievements=achievements)


@app.route('/news')
def news():
    site_info = get_site_info()
    RSSfeeds = feedparser.parse('https://sports.inquirer.net/feed')
    feeds = RSSfeeds.entries
    return render_template('pages/news.html', site_info=site_info, feeds=feeds)


if __name__ == '__main__':
    app.run(debug=True)
