from django.shortcuts import redirect

# URLs the middleware will never intercept — prevents redirect loops
_EXEMPT_PREFIXES = (
    '/change-password-required/',
    '/register/',
    '/logout/',
    '/login/',
    '/static/',
    '/admin/',
)


class ForcePasswordChangeMiddleware:
    """
    After every request, checks if the authenticated user has
    must_change_password=True on their profile. If so, redirects
    them to the forced password change page regardless of where
    they are trying to go.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.user.is_authenticated
            and not any(request.path.startswith(p) for p in _EXEMPT_PREFIXES)
        ):
            try:
                if request.user.profile.must_change_password:
                    return redirect('/change-password-required/')
            except Exception:
                # Profile doesn't exist yet — let the request through
                pass

        return self.get_response(request)
