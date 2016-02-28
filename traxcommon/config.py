"""
Methods and Classes related to configuration
"""
import six
if six.PY2:
    from ConfigParser import ConfigParser
else:
    from configparser import ConfigParser
import logging
import os

__all__ = [
    'load_config',
]

log = logging.getLogger(__name__)


def load_config(config_file):
    """
    Parse the given config file location and return a dictionary. In
    addition, if the conifg file has an option 'credentials_file' in the
    'general' section, the file will be loaded and parsed.
    """
    config = {}
    if not os.path.exists(config_file):
        log.warn("Config file does not exists: %s", config_file)
        return config
    with open(config_file) as fp:
        config = parse_config(fp)
    if 'credentials_file' in config:
        if os.path.exists(config['credentials_file']):
            with open(config['credentials_file']) as fp:
                config.update(parse_config(fp, 'credentials'))
        else:
            log.warn("Credentials file does not exists: %s", config['credentials_file'])
    else:
        creds = "{}/credentials".format(config_file.rsplit('/', 1)[0])
        if os.path.exists(creds):
            with open(creds) as fp:
                config.update(parse_config(fp, 'credentials'))
        else:
            log.warn("Credentials file does not exists: %s", creds)
    return config

def parse_config(fp, default_section='general'):
    """
    Load values from a configuration file into a dictionary. Items in
    the 'general' section of the config file will be placed as key,
    value pairs in the dictionary. Values of other sections get a key in
    the dictionary with another dictionary representing the items in
    that section.
    """
    parser = ConfigParser.ConfigParser()
    parser.readfp(fp)
    config = {}
    for section in parser.sections():
        for k, v in parser.items(section):
            if section == default_section:
                config[k] = v
                continue
            if section not in config:
                config[section] = {k: v}
            else:
                config[section][k] = v
    return config
