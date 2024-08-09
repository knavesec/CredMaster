import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://org.okta.com   ->  gives the URL to the application
    # --content-type form/json     ->  specifies the content type of the request
    # --body "username={USER}&password={PASS}" -> specifies the body of the POST request
    #
    content_types = ["form", "json"]

    if not 'url' in pluginargs.keys() or not 'content-type' in pluginargs.keys():
        error = "Missing url or content-type, specify as --url https://target.com/endpoint/to/test.ext and --content-type (form/json)\nYou can also specify the body with --body. Ex.: --body \"username={USER}&password={PASS}\" or --body {\"username\":\"{USER}\",\"password\":\"{PASS}\"}"
        return False, error, None
    
    # Validate content-type
    if pluginargs['content-type'].lower() not in content_types:
        error = "content-type must be form or json"
        return False, error, None
    pluginargs['content-type'] = pluginargs['content-type'].lower()

    # Split URL into URI and URL
    full_url = pluginargs['url']
    pluginargs['url'] = '/'.join(full_url.split('/')[:3])
    pluginargs['uri'] = '/'.join(full_url.split('/')[3:])

    # Validate body
    if 'body' not in pluginargs.keys():
        # Use default body if not specified, based on content-type
        if pluginargs['content-type'] == "json":
            pluginargs['body'] = "{\"username\":\"{USER}\",\"password\":\"{PASS}\"}"
        else:
            pluginargs['body'] = "username={USER}&password={PASS}"
    else:
        # Check if body contains {USER} and {PASS} placeholders
        if "{USER}" not in pluginargs['body'] or "{PASS}" not in pluginargs['body']:
            error = "Body must contain {USER} and {PASS} placeholders"
            return False, error, None
        
    return True, None, pluginargs
        


def testconnect(pluginargs, args, api_dict, useragent):

    success = True
    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : utils.generate_ip(),
        "x-amzn-apigateway-api-id" : utils.generate_id(),
        "X-My-X-Amzn-Trace-Id" : utils.generate_trace_id(),
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    resp = requests.get(api_dict['proxy_url'], headers=headers)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuing"

    return success, output, pluginargs
