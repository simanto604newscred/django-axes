from functools import wraps
import logging
from socket import inet_pton, AF_INET6
from hashlib import md5

from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_lockout_response


if settings.AXES_BEHIND_REVERSE_PROXY:
    log.debug('AXES: Axes is configured to be behind reverse proxy')
    log.debug(
        'AXES: Looking for header value %s', settings.AXES_REVERSE_PROXY_HEADER
    )
    log.debug(
        'AXES: Number of proxies configured: {} '
        '(please check this if you are using a custom header)'.format(
            NUM_PROXIES
        )
    )


def get_client_str(username, ip_address, user_agent=None, path_info=None):

    if VERBOSE:
        if isinstance(path_info, tuple):
            path_info = path_info[0]
        details = "{{user: '{0}', ip: '{1}', user-agent: '{2}', path: '{3}'}}"
        return details.format(username, ip_address, user_agent, path_info)

    if AXES_ONLY_USER_FAILURES:
        client = username
    elif LOCK_OUT_BY_COMBINATION_USER_AND_IP:
        client = '{0} from {1}'.format(username, ip_address)
    else:
        client = ip_address

    if USE_USER_AGENT:
        return client + '(user-agent={0})'.format(user_agent)

    return client


def log_successful_attempt(username, ip_address,
                           user_agent=None, path_info=None):
    client = get_client_str(username, ip_address, user_agent, path_info)
    msg = 'AXES: Successful login by {0}. Creating access record.'
    log.info(msg.format(client))


def log_initial_attempt(username, ip_address, user_agent, path_info):
    client = get_client_str(username, ip_address, user_agent, path_info)
    msg = 'AXES: New login failure by {0}. Creating access record.'
    log.info(msg.format(client))


def log_repeated_attempt(username, ip_address, user_agent, path_info,
                         fail_count):
    client = get_client_str(username, ip_address, user_agent, path_info)
    fail_msg = 'AXES: Repeated login failure by {0}. Updating access record.'
    count_msg = 'Count = {0} of {1}'.format(fail_count, FAILURE_LIMIT)
    log.info('{0} {1}'.format(fail_msg.format(client), count_msg))


def log_lockout(username, ip_address, user_agent, path_info):
    client = get_client_str(username, ip_address, user_agent, path_info)
    msg = 'AXES: locked out {0} after repeated login attempts.'
    log.warn(msg.format(client))


def log_decorated_call(func, args=None, kwargs=None):
    log.info('AXES: Calling decorated function: %s' % func.__name__)
    if args:
        log.info('args: %s' % str(args))
    if kwargs:
        log.info('kwargs: %s' % kwargs)


def is_ipv6(ip):
    try:
        inet_pton(AF_INET6, ip)
    except (OSError, error):
        return False
    return True


def get_ip(request):
    """Parse IP address from REMOTE_ADDR or
    AXES_REVERSE_PROXY_HEADER if AXES_BEHIND_REVERSE_PROXY is set."""

    if BEHIND_REVERSE_PROXY:
        ip = request.META.get(REVERSE_PROXY_HEADER, '').split(',', 1)[0]
        ip = ip.strip()
        if not ip:
            raise Warning(
                'AXES: Axes is configured for operation behind a reverse '
                'proxy but could not find a suitable IP in the specified '
                'HTTP header. Check your proxy server settings to make '
                'sure correct headers are being passed to Django in '
                'AXES_REVERSE_PROXY_HEADER. '
                'Header name: {0}, value: {1}'.format(
                    REVERSE_PROXY_HEADER, ip_str
                )
            )

        return ip

    return request.META.get('REMOTE_ADDR', '')


def query2str(items, max_length=1024):
    """Turns a dictionary into an easy-to-read list of key-value pairs.

    If there's a field called "password" it will be excluded from the output.

    The length of the output is limited to max_length to avoid a DoS attack
    via excessively large payloads.
    """
    return '\n'.join([
        '%s=%s' % (k, v) for k, v in six.iteritems(items)
        if k != PASSWORD_FORM_FIELD
    ][:int(max_length / 2)])[:max_length]


def ip_in_whitelist(ip):
    if IP_WHITELIST is not None:
        return ip in IP_WHITELIST

    return False


def ip_in_blacklist(ip):
    if IP_BLACKLIST is not None:
        return ip in IP_BLACKLIST

    return False


def is_user_lockable(request):
    """Check if the user has a profile with nolockout
    If so, then return the value to see if this user is special
    and doesn't get their account locked out
    """
    if hasattr(request.user, 'nolockout'):
        return not request.user.nolockout

    if request.method != 'POST':
        return True

    try:
        field = getattr(get_user_model(), 'USERNAME_FIELD', 'username')
        kwargs = {
            field: request.POST.get(USERNAME_FORM_FIELD)
        }
        user = get_user_model().objects.get(**kwargs)

        if hasattr(user, 'nolockout'):
            # need to invert since we need to return
            # false for users that can't be blocked
            return not user.nolockout

    except get_user_model().DoesNotExist:
        # not a valid user
        return True

    # Default behavior for a user to be lockable
    return True


def _get_user_attempts(request):
    """Returns access attempt record if it exists.
    Otherwise return None.
    """
    ip = get_ip(request)
    username = request.POST.get(USERNAME_FORM_FIELD, None)

    if AXES_ONLY_USER_FAILURES:
        attempts = AccessAttempt.objects.filter(username=username)
    elif USE_USER_AGENT:
        ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
        attempts = AccessAttempt.objects.filter(
            user_agent=ua, ip_address=ip, username=username, trusted=True
        )
    else:
        attempts = AccessAttempt.objects.filter(
            ip_address=ip, username=username, trusted=True
        )
    )


def axes_dispatch(func):
    def inner(request, *args, **kwargs):
        if AxesProxyHandler.is_allowed(request):
            return func(request, *args, **kwargs)

        return get_lockout_response(request)

    return inner


def axes_form_invalid(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        if AxesProxyHandler.is_allowed(self.request):
            return func(self, *args, **kwargs)

        return get_lockout_response(self.request)

    return inner


def lockout_response(request):
    context = {
        'failure_limit': settings.AXES_FAILURE_LIMIT,
        'username': get_client_username(request) or ''
    }

    cool_off = settings.AXES_COOLOFF_TIME
    if cool_off:
        if isinstance(cool_off, (int, float)):
            cool_off = timedelta(hours=cool_off)

        context.update({
            'cooloff_time': iso8601(cool_off)
        })

    if request.is_ajax():
        return HttpResponse(
            json.dumps(context),
            content_type='application/json',
            status=403,
        )

    elif LOCKOUT_TEMPLATE:
        if COOLOFF_TIME:
            context.update({'cooloff_time': iso8601(COOLOFF_TIME)})

    if LOCKOUT_TEMPLATE:
        context.update({'cooloff_time': COOLOFF_TIME})
        template = get_template(LOCKOUT_TEMPLATE)
        content = template.render(context, request)
        return HttpResponse(content, status=403)

    if settings.AXES_LOCKOUT_URL:
        return HttpResponseRedirect(settings.AXES_LOCKOUT_URL)

    else:
        msg = get_lockout_message()

        return HttpResponse(msg, status=403)


def is_already_locked(request):
    ip = get_ip(request)

    if NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip):
        return False

    if ONLY_WHITELIST and not ip_in_whitelist(ip):
        return True

    if ip_in_blacklist(ip):
        return True

    if not is_user_lockable(request):
        return False

    cache_hash_key = get_cache_key(request)
    failures_cached = cache.get(cache_hash_key)
    if failures_cached is not None:
        return failures_cached >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE
    else:
        for attempt in get_user_attempts(request):
            if attempt.failures_since_start >= FAILURE_LIMIT and \
                    LOCK_OUT_AT_FAILURE:
                return True

    return False


def check_request(request, login_unsuccessful):
    ip_address = get_ip(request)
    username = request.POST.get(USERNAME_FORM_FIELD, None)
    user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
    failures = 0
    attempts = get_user_attempts(request)
    cache_hash_key = get_cache_key(request)
    cache_timeout = get_cache_timeout()

    failures_cached = cache.get(cache_hash_key)
    if failures_cached is not None:
        failures = failures_cached
    else:
        for attempt in attempts:
            failures = max(failures, attempt.failures_since_start)

    if login_unsuccessful:
        # add a failed attempt for this user
        failures += 1
        cache.set(cache_hash_key, failures, cache_timeout)

        # Create an AccessAttempt record if the login wasn't successful
        # has already attempted, update the info
        if len(attempts):
            for attempt in attempts:
                attempt.get_data = '%s\n---------\n%s' % (
                    attempt.get_data,
                    query2str(request.GET),
                )
                attempt.post_data = '%s\n---------\n%s' % (
                    attempt.post_data,
                    query2str(request.POST)
                )
                attempt.http_accept = \
                    request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
                attempt.path_info = path_info
                attempt.failures_since_start = failures
                attempt.attempt_time = datetime.now()
                attempt.save()

                log_repeated_attempt(username, ip_address,
                                     user_agent, path_info, failures)

        else:
            create_new_failure_records(request, failures)
    else:
        # user logged in -- forget the failed attempts
        failures = 0
        trusted_record_exists = False
        for attempt in attempts:
            if not attempt.trusted:
                attempt.delete()
                failures_cached = cache.get(cache_hash_key)
                if failures_cached is not None:
                    cache.set(cache_hash_key,
                              failures_cached - 1,
                              cache_timeout)
            else:
                trusted_record_exists = True
                attempt.failures_since_start = 0
                attempt.save()
                cache.set(cache_hash_key, 0, cache_timeout)

        if trusted_record_exists is False:
            create_new_trusted_record(request)

    if NEVER_LOCKOUT_WHITELIST and ip_in_whitelist(ip_address):
        return True

    user_lockable = is_user_lockable(request)
    # no matter what, we want to lock them out if they're past the number of
    # attempts allowed, unless the user is set to notlockable
    if failures >= FAILURE_LIMIT and LOCK_OUT_AT_FAILURE and user_lockable:
        # We log them out in case they actually managed to enter the correct
        # password
        try:
            if hasattr(request, 'user') and request.user.is_authenticated():
                logout(request)
        except TypeError:
            if hasattr(request, 'user') and request.user.is_authenticated:
                logout(request)
        log.warn('AXES: locked out %s after repeated login attempts.' %
                 (ip_address,))
        # send signal when someone is locked out.
        user_locked_out.send(
            'axes', request=request, username=username, ip_address=ip_address
        )

        # if a trusted login has violated lockout, revoke trust
        for attempt in [a for a in attempts if a.trusted]:
            attempt.delete()
            create_new_failure_records(request, failures)

        return False

    return True


def create_new_failure_records(request, failures):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    username = request.POST.get(USERNAME_FORM_FIELD, None)
    path_info = request.META.get('PATH_INFO', '<unknown>'),

    # Record failed attempt. Whether or not the IP address or user agent is
    # used in counting failures is handled elsewhere, so we just record
    # everything here.
    AccessAttempt.objects.create(
        user_agent=ua,
        ip_address=ip,
        username=username,
        get_data=query2str(request.GET),
        post_data=query2str(request.POST),
        http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
        path_info=path_info,
        failures_since_start=failures,
    )

    username = request.POST.get(USERNAME_FORM_FIELD, None)
    log_initial_attempt(username, ip, ua, path_info)


def create_new_trusted_record(request):
    ip = get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    username = request.POST.get(USERNAME_FORM_FIELD, None)

    if not username:
        return False

    AccessAttempt.objects.create(
        user_agent=ua,
        ip_address=ip,
        username=username,
        get_data=query2str(request.GET),
        post_data=query2str(request.POST),
        http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
        path_info=request.META.get('PATH_INFO', '<unknown>'),
        failures_since_start=0,
        trusted=True
    )


def get_cache_key(request_or_object):
    """
    Build cache key name from request or AccessAttempt object.
    :param  request_or_object: Request or AccessAttempt object
    :return cache-key: String, key to be used in cache system
    """
    if isinstance(request_or_object, AccessAttempt):
        ip = request_or_object.ip_address
        un = request_or_object.username
        ua = request_or_object.user_agent
    else:
        ip = get_ip(request_or_object)
        un = request_or_object.POST.get(USERNAME_FORM_FIELD, None)
        ua = request_or_object.META.get('HTTP_USER_AGENT', '<unknown>')[:255]

    ip = ip.encode('utf-8') if ip else ''.encode('utf-8')
    un = un.encode('utf-8') if un else ''.encode('utf-8')
    ua = ua.encode('utf-8') if ua else ''.encode('utf-8')

    if AXES_ONLY_USER_FAILURES:
        attributes = un
    elif LOCK_OUT_BY_COMBINATION_USER_AND_IP:
        attributes = ip+un
    else:
        attributes = ip

    if USE_USER_AGENT:
        attributes += ua

    cache_hash_key = 'axes-{}'.format(md5(attributes).hexdigest())

    return cache_hash_key


def get_cache_timeout():
    "Returns timeout according to COOLOFF_TIME."
    cache_timeout = None
    if COOLOFF_TIME:
        cache_timeout = COOLOFF_TIME.total_seconds()
    return cache_timeout
