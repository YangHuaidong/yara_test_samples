# Copyright (C) 2012-2014 AntiyLabs.
# This file is a part of ShadowBox.
# ShadowBox is based on Cuckoo Sandbox, thanks to Cuckoo's developers.

import os
import configparser
from sqlite3 import OperationalError

curdir = os.path.dirname(os.path.realpath(__file__))

class Dictionary(dict):
    """Cuckoo custom dict."""

    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class Config:
    """Configuration file parser."""

    def __init__(self):
        """@param cfg: configuration file path."""
        self.cfg=os.path.join(curdir,"testweb.conf")
        self.config = configparser.ConfigParser()
        self.config.read(self.cfg)
        for section in self.config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in self.config.items(section):
                try:
                    value = self.config.getboolean(section, name)
                except ValueError:
                    try:
                        value = self.config.getint(section, name)
                    except ValueError:
                        value = self.config.get(section, name)

                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise OperationalError: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:

            raise OperationalError("Option %s is not found in "
                "configuration, error: %s" % (section, e))

    def update(self,section = "",option = "", newvalue = ""):
        try:
            self.config.set(section,option,newvalue)
            self.config.write(open(self.cfg,"w"))
        except AttributeError as e:
            print(e)

            raise OperationalError("Option %s is not found in "%(e))
