from os.path import dirname, join, realpath
from aiohttp.web import Application

from sqli import views
from sqli import admin_views

DIR_PATH = dirname(realpath(__file__))


def setup_routes(app: Application):
    app.router.add_route('GET', r'/', views.index)
    app.router.add_route('POST', r'/', views.index)

    app.router.add_route('GET', r'/students/', views.students)
    app.router.add_route('POST', r'/students/', views.students)
    app.router.add_route('GET', r'/students/{id:\d+}', views.student)

    app.router.add_route('GET', r'/courses/', views.courses)
    app.router.add_route('POST', r'/courses/', views.courses)
    app.router.add_route('GET', r'/courses/{id:\d+}', views.course)

    app.router.add_route('POST',
                         r'/students/{student_id:\d+}/evaluate/{course_id:\d+}',
                         views.evaluate)

    app.router.add_route('GET',
                         r'/courses/{course_id:\d+}/review',
                         views.review)
    app.router.add_route('POST',
                         r'/courses/{course_id:\d+}/review',
                         views.review)

    # Admin panel routes (command injection, path traversal, SSRF, deserialization)
    app.router.add_route('GET', r'/admin/', admin_views.admin_panel)
    app.router.add_route('POST', r'/admin/export', admin_views.export_data)
    app.router.add_route('GET', r'/admin/files', admin_views.read_file)
    app.router.add_route('POST', r'/admin/fetch', admin_views.fetch_url)
    app.router.add_route('POST', r'/admin/import', admin_views.import_data)

    # User profile route (IDOR)
    app.router.add_route('GET', r'/users/{id:\d+}', views.user_profile)

    # Search route (unsafe YAML deserialization)
    app.router.add_route('GET', r'/search', views.search)

    app.router.add_route('POST', r'/logout/', views.logout)
    app.router.add_static('/static', join(DIR_PATH, 'static'))
