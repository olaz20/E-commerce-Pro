from django.utils.encoding import force_str
from rest_framework import status
from rest_framework.renderers import JSONRenderer


class CustomResponseRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = renderer_context.get("response", None)
        status_code = response.status_code if response else status.HTTP_200_OK

        message = data.pop("message", None)
        if not message and status_code >= status.HTTP_400_BAD_REQUEST:
            message = force_str(data.get("detail", "An error occured."))
            data.pop("detail", None)

        if isinstance(data, dict) and "data" in data:
            data = data["data"]

        response_data = {
            "status": status_code,
            "message": message or "Request was successful",
            "data": data if data else None,
        }

        return super().render(response_data, accepted_media_type, renderer_context)
