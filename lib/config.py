"""
Methods and Classes related to configuration
"""

__all__ = [
    'load_config',
]

def load_config(config_file):
    """
    Load values from a configuration file into a dictionary. Items in
    the 'general' section of the config file will be placed as key,
    value pairs in the dictionary. Values of other sections get a key in
    the dictionary with another dictionary representing the items in
    that section.
    """
    parser = ConfigParser.ConfigParser()
    with open(config_file) as fp:
        parser.readfp(fp)
    config = {}
    for section in parser.sections():
        for k, v in parser.items(section):
            if section == 'general':
                config[k] = v
                continue
            if section not in config:
                config[section] = {k: v}
            else:
                config[section][k] = v
    parser = ConfigParser.ConfigParser()
    if 'credentials_file' in config:
        with open(config['credentials_file']) as fp:
            parser.readfp(fp)
        for section in parser.sections():
            for k, v in parser.items(section):
                if section == 'credentials':
                    if k in config:
                        raise Exception(
                            "Key {} exists in config".format(k)
                        )
                    config[k] = v
                elif section not in config:
                    config[section] = {k: v}
                else:
                    config[section][k] = v
    return config
