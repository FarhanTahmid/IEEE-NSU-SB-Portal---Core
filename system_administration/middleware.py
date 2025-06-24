import threading

_user = threading.local()

class RequestMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            _user.value = request.user.username if request.user.is_authenticated else None
            response = self.get_response(request)
            return response
        except:
            # Ignore and forward the response
            response = self.get_response(request)
            return response
        finally:
            _user.value = None  # Clean up after the request is done

def get_current_user():
    return getattr(_user, 'value', None)