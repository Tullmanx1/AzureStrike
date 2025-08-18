import logging
import azure.functions as func
from jinja2 import Template
from urllib.parse import parse_qs

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="render", methods=["GET", "POST"])
def render(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Jinja render endpoint hit, parsing payload…")

    # 1) Grab payload from GET query or POST form
    if req.method.upper() == "GET":
        payload = req.params.get("payload", "")
    else:
        try:
            body = req.get_body().decode("utf-8")
            vals = parse_qs(body)
            payload = vals.get("payload", [""])[0]
        except Exception:
            payload = ""

    # 2) Evaluate it as a Jinja template
    try:
        evaluated = Template(payload).render()
    except Exception as e:
        evaluated = f"Error evaluating template: {e}"

    # 3) Wrap raw & evaluated in a simple HTML response
    wrapper = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Jinja Test Result</title></head>
<body>
  <h2>Raw submission:</h2>
  <pre>{{ raw }}</pre>
  <hr/>
  <h2>Jinja result:</h2>
  <div>{{ evaluated }}</div>
</body>
</html>"""

    try:
        result = Template(wrapper).render(raw=payload, evaluated=evaluated)
    except Exception as e:
        result = f"<pre>Error rendering wrapper template: {e}</pre>"

    return func.HttpResponse(result, mimetype="text/html")
