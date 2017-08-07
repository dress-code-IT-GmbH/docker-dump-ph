import argparse
import configparser

class ConfigErrorException(Exception):
    def __init__(self, message=None, errors=None):
        super(ConfigErrorException, self).__init__(message)
        self.errors = errors

class CmdlineArgs(object):
    def __init__(self,config,dump=None,log=False,output=None):
        self.config = config
        self.dump = dump
        self.log = log
        self.output = output

class ConfigFile(object):
    def __init__(self,filename):
        self.filename = filename
        self.config = configparser.ConfigParser()
        files_read = self.config.read(self.filename)
        if not files_read:
            msg = "config file \"{}\" could not be processed".format(self.filename)
            raise ConfigErrorException(msg)

    def __repr__(self):
        r = []
        r.append(super(ConfigFile,self).__repr__())
        r.append("filename: {}".format(self.filename))
        return "\n".join(r)

class DumpConfig(object):
    def __init__(self,dump_name,config_file):
        self.dump_name = dump_name
        self.config_file = config_file

        self.alt_names = []
        try:
            self.host = config_file.config.get(self.dump_name, 'Host')
            self.cacertfile = config_file.config.get(self.dump_name, 'CacertFile', fallback=None)
            self.cacertpath = config_file.config.get(self.dump_name, 'CacertPath', fallback=None)
            self.alt_names_txt = config_file.config.get(self.dump_name, 'AltNames', fallback=None)
            if self.alt_names_txt:
                alt_names = self.alt_names_txt.split(',')
                for n in alt_names:
                    self.alt_names.append(n.strip())
            self.admin_user = config_file.config.get(self.dump_name, 'AdminUser')
            self.admin_pw = config_file.config.get(self.dump_name, 'AdminPw')
            self.test_target_base_dn = config_file.config.get(self.dump_name, 'BaseDn')
            self.test_target_filter = config_file.config.get(self.dump_name, 'Filter')
            self.verifyssl = config_file.config.get(self.dump_name, 'VerifySSL', fallback=True)
        except configparser.NoOptionError as e:
            raise ConfigErrorException('a option is missing: '+str(e))



    def __str__(self):
        r = []
        r.append("Host: {}".format(self.host))
        r.append("Adminuser: {}".format(self.admin_user))
        r.append("BaseDn: {}".format(self.test_target_base_dn))
        r.append("Filter: {}".format(self.test_target_user_filter))
        return ", ".join(r)


    def __repr__(self):
        r = []
        r.append(super(TestConfig,self).__repr__())
        r.append(self.__str__())
        return "\n".join(r)



class Config(object):

    def __init__(self):
        self.cmdline_args = None
        self.config_file = None
        self.dump_config = None
        self.parser = None
        self.args = None
        self.selected_dump = None
        self.__parser()
        self.__parse_args()
        self.__read_config_file()

    def __parser(self):
        self.parser = argparse.ArgumentParser(
            description="Dump entries from a MSFT AD",
            epilog="example: %(prog)s -c config.conf",
            usage='%(prog)s [options]',
            prog='dump'
        )
        self.parser.add_argument('-c', '--conf', dest='config', default='dump.conf',
                    help='test config file')
        self.parser.add_argument('-d', '--dump', dest='dump',
            help='selects the dump in case more than one dump is defined in the config file')
        self.parser.add_argument('-l', '--log', dest='log', action='store_true',
            help='write a ldap log to the file "ldap.log"')
        self.parser.add_argument('-o', '--output', dest='output', 
                                 help='output file', default='data.ldif')
        self.parser.set_defaults(log=False)
 
    def __parse_args(self):
        self.args = self.parser.parse_args()
        self.cmdline_args = CmdlineArgs(self.args.config, self.args.dump, self.args.log, self.args.output)

    def __read_config_file(self):
        self.config_file = ConfigFile(self.cmdline_args.config)
        dumps_list = self.config_file.config.sections()
        if not dumps_list:
            raise ConfigErrorException("No dump was found in this config")
        if self.cmdline_args.dump:
            if self.cmdline_args.test in dumps_list:
                self.selected_dump = self.cmdline_args.test
            else:
                raise ConfigErrorException("the dump \"{}\" was not found. Available dumps in this config: {}".format(
                    self.cmdline_args.test, ",".join(dumps_list)))
        else:
            self.selected_dump = dumps_list[0]

        self.dump_config = DumpConfig(self.selected_dump,self.config_file)

    def __repr__(self):
        r = []
        r.append(super(Config,self).__repr__())
        if not self.parser or not self.args:
            r.append("Not initialized")
        else:
            r.append(str(self.args))
            r.append(str(self.cmdline_args))
            r.append(str(self.config_file))
            r.append("selected dump: \"{}\"".format(self.selected_dump))
            r.append(str(self.dump_config))
        return "\n".join(r)

