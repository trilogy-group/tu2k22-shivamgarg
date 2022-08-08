from django.utils.deprecation import MiddlewareMixin


class DisableCSRF(MiddlewareMixin):
    def process_request(self, request):
        print()
        print(request.body)
        if request.headers.get("Authorization"):
            print(request.headers.get("Authorization"))
        setattr(request, '_dont_enforce_csrf_checks', True)

    def process_response(self, request, response):
        print(response.content)
        return response