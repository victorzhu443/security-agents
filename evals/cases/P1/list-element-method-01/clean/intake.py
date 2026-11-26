from secprim import as_dict, as_list, as_str


class FormIntake:
    """POST /forms: every node is shape-checked; failures are MalformedInput."""

    def submit(self, body):
        body = as_dict(body, "body")
        fields = as_list(body.get("fields"), "body.fields", optional=True)
        out = {}
        for i, f in enumerate(fields):
            f = as_dict(f, f"body.fields[{i}]")
            out[as_str(f.get("name"), f"body.fields[{i}].name", max_len=64)] = f.get("value")
        return out


submit = FormIntake().submit
