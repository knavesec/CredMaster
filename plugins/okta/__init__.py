def validate(pluginargs, args):
    if 'url' in pluginargs.keys():
        if args.threads == 1 or (args.threads > 1 and 'force' in pluginargs.keys()):
            return True, None, pluginargs['url']
        else:
            error = "WARNING, threadcount > 1 will likely result in ratelimiting from Okta, to override add a --force flag"
            return False, error, None
    else:
        error = "Missing url argument, specify as --url https://org.okta.com"
        return False, error, None
