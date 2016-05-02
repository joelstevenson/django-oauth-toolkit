
def build_claims_doc(scopes, request, claims_location="userinfo"):
    """
        Build a claims document for the django app's user claims provider to use when populating either the id_token
        or the userinfo request.

        This document is an extension of the json document format that can be submitted via the claims parameter
        it includes a list of the scopes as well.  It looks like:
        {
            "scopes": {                                       # may be an empty obj
                "scope1": null,
                "scope2": null
             },
            "userinfo": {                                     # doc will have either a userinfo key
                 "given_name": {"essential": true},
                 "nickname": null,
                 "email": {"essential": true},
                 "email_verified": {"essential": true},
                 "picture": null,
                 "http://example.info/claims/groups": null
                },
           "id_token": {                                      # or an id_token key, but not both
                 "auth_time": {"essential": true},
                 "acr": {"values": ["urn:mace:incommon:iap:silver"] }
                }
        }

    :param scopes:
    :type scopes:
    :param request:
    :type request:
    :param claims_location:
    :type claims_location:
    :return:
    :rtype:
    """
    claims_doc = {
        "scopes": dict((scope,None) for scope in scopes)
    }

    if request and request.claims and request.claims.get(claims_location):
        claims_doc.update(request.claims.get(claims_location))

    return claims_doc

