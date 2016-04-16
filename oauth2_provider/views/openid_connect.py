from braces.views import CsrfExemptMixin
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.views.generic import View
from oauthlib.oauth2 import AccessDeniedError
import json

from oauth2_provider.backends import OAuth2Backend
from oauth2_provider.models import AccessToken


class UserInfoView(CsrfExemptMixin, View):
    """
    Implements an endpoint to provide UserInfo

    The endpoint is used in the following flows:
    * OpenId Connect UserInfo
    """
    backend = OAuth2Backend()

    def get_user_info_data(self, user, request):
        # raise NotImplementedError("Subclass")

        return {
            "userid" : user.pk,
            "email" : getattr(user, 'email', None)
        }

    def get(self, request, *args, **kwargs):
        return self._handle(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self._handle(request, *args, **kwargs)

    def _handle(self, request, *args, **kwargs):

        user = self.backend.authenticate(request=request)

        if user:
            body = self.get_user_info_data(user, request)
            response = HttpResponse(content=json.dumps(body), status=200)

            return response
        else:
            raise AccessDeniedError()


