from secprim import MalformedInput


class FormIntake:
    """POST /forms: the body and its field list are checked; each field is assumed."""

    def submit(self, body):
        if not isinstance(body, dict):
            raise MalformedInput("body: expected an object")
        fields = body.get("fields") or []
        if not isinstance(fields, list):
            raise MalformedInput("body.fields: expected a list")
        return {f.get("name"): f.get("value") for f in fields}     # f may be a str, int, None, list


submit = FormIntake().submit
