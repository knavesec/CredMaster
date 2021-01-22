def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --input1          ->  input 1 docs
    # --input2          ->  input 2 docs
    # ...

    #
    # pluginargs = {
    #    'url' = 'static_url or pluginarg_input_url' - REQUIRED
    #    'other_arg' = ....
    # }

    # Return Args
    # Bool - T/F if all plugin args are set
    # Str/None - Error message, if there are any
    # Dict - Plugin args returned, 'url' arg required
    return True, None, pluginargs
