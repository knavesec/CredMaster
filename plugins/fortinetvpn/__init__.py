def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://domain.com    ->  gives the URL to the application
    # --domain DOMAIN              ->  Optional Input domain name
    #
    if 'url' in pluginargs.keys():
        if "https://" not in pluginargs['url'] and "http://" not in pluginargs['url']:
            error = "URL requires http:// or https:// prefix"
            return False, error, None
        return True, None, pluginargs
    else:
        error = "Missing url argument, specify as --url https://domain.com"
        return False, error, None
