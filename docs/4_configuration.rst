.. _configuration:

Configuration
=============

Minimal Axes configuration is done with just ``settings.py`` updates.

More advanced configuration and integrations might require updates
on source code level depending on your project implementation.


Configuring project settings
----------------------------

The following ``settings.py`` options are available for customizing Axes behaviour.

* ``AXES_ENABLED``: Enable or disable Axes plugin functionality,
  for example in test runner setup. Default: ``True``
* ``AXES_FAILURE_LIMIT``: The integer number of login attempts allowed before a
  record is created for the failed logins. This can also be a callable
  or a dotted path to callable that returns an integer and all of the following are valid:
  ``AXES_FAILURE_LIMIT = 42``,
  ``AXES_FAILURE_LIMIT = lambda *args: 42``, and
  ``AXES_FAILURE_LIMIT = 'project.app.get_login_failure_limit'``.
  Default: ``3``
* ``AXES_LOCK_OUT_AT_FAILURE``: After the number of allowed login attempts
  are exceeded, should we lock out this IP (and optional user agent)?
  Default: ``True``
* ``AXES_COOLOFF_TIME``: If set, defines a period of inactivity after which
  old failed login attempts will be cleared. Can be set to a Python
  timedelta object or an integer. If an integer, will be interpreted as a number of hours.
  Default: ``None``
* ``AXES_ONLY_ADMIN_SITE`` : If ``True``, lock is only enable for admin site,
  Default: ``False``
* ``AXES_ONLY_USER_FAILURES`` : If ``True``, only lock based on username,
  and never lock based on IP if attempts exceed the limit.
  Otherwise utilize the existing IP and user locking logic.
  Default: ``False``
* ``AXES_LOCK_OUT_BY_COMBINATION_USER_AND_IP``: If ``True``, prevent login
  from IP under a particular username if the attempt limit has been exceeded,
  otherwise lock out based on IP.
  Default: ``False``
* ``AXES_USE_USER_AGENT``: If ``True``, lock out and log based on the IP address
  and the user agent.  This means requests from different user agents but from
  the same IP are treated differently. This settings has no effect if the
  ``AXES_ONLY_USER_FAILURES`` setting is active.
  Default: ``False``
* ``AXES_LOGGER``: If set, specifies a logging mechanism for Axes to use.
  Default: ``'axes.watch_login'``
* ``AXES_HANDLER``: The path to to handler class to use.
  If set, overrides the default signal handler backend.
  Default: ``'axes.handlers.database.DatabaseHandler'``
* ``AXES_CACHE``: The name of the cache for Axes to use.
  Default: ``'default'``
* ``AXES_LOCKOUT_TEMPLATE``: If set, specifies a template to render when a
  user is locked out. Template receives ``cooloff_time`` and ``failure_limit`` as
  context variables.
  Default: ``None``
* ``AXES_LOCKOUT_URL``: If set, specifies a URL to redirect to on lockout. If both
  ``AXES_LOCKOUT_TEMPLATE`` and ``AXES_LOCKOUT_URL`` are set, the template will be used.
  Default: ``None``
* ``AXES_VERBOSE``: If ``True``, you'll see slightly more logging for Axes.
  Default: ``True``
* ``AXES_USERNAME_FORM_FIELD``: the name of the form field that contains your users usernames.
  Default: ``username``
* ``AXES_USERNAME_CALLABLE``: A callable or a string path to function that takes
  two arguments for user lookups: ``def get_username(request: HttpRequest, credentials: dict) -> str: ...``.
  This can be any callable such as ``AXES_USERNAME_CALLABLE = lambda request, credentials: 'username'``
  or a full Python module path to callable such as ``AXES_USERNAME_CALLABLE = 'example.get_username``.
  The ``request`` is a HttpRequest like object and the ``credentials`` is a dictionary like object.
  ``credentials`` are the ones that were passed to Django ``authenticate()`` in the login flow.
  If no function is supplied, Axes fetches the username from the ``credentials`` or ``request.POST``
  dictionaries based on ``AXES_USERNAME_FORM_FIELD``.
  Default: ``None``
* ``AXES_PASSWORD_FORM_FIELD``: the name of the form or credentials field that contains your users password.
  Default: ``password``
* ``AXES_NEVER_LOCKOUT_GET``: If ``True``, Axes will never lock out HTTP GET requests.
  Default: ``False``
* ``AXES_NEVER_LOCKOUT_WHITELIST``: If ``True``, users can always login from whitelisted IP addresses.
  Default: ``False``
* ``AXES_IP_WHITELIST``: A list of IP's to be whitelisted. For example: AXES_IP_WHITELIST=['0.0.0.0']. Default: []
  Default: ``False``
* ``AXES_DISABLE_ACCESS_LOG``: If ``True``, disable all access logging, so the admin interface will be empty.
* ``AXES_DISABLE_SUCCESS_ACCESS_LOG``: If ``True``, successful logins will not be logged, so the access log shown in the admin interface will only list unsuccessful login attempts.
