import imp
import os
import re

from fabric.api import task, puts, env, local, sudo, run, execute, lcd
from fabric.tasks import Task
from fabric.utils import abort


try:
    import boto.ec2
    AWS_SUPPORT = True
    #import boto.ec2.elb
    #self.boto_ec2 = boto.ec2
    #self.boto_ec2_elb = boto.ec2.elb
except ImportError:
    AWS_SUPPORT = False

ip_re = re.compile('(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

env.aptitude = "sudo aptitude -q -y"


def _get_ec2_connection():
    return boto.ec2.connect_to_region(
        os.environ.get('AWS_REGION', 'eu-west-1'))


def _find_ec2_by_name(name):
    ec2 = _get_ec2_connection()
    instances = ec2.get_all_instances(
        filters={'tag:Name': name})
    if len(instances) == 0:
        return None
    elif len(instances) > 1:
        puts("Found more than one!")
        return None
    reservation = instances[0]
    return reservation.instances[0]


class BaseHost(object):

    def __init__(self, settings):
        self.settings = settings

    def get_host_user(self):
        return getattr(self.settings, 'SSH_USER', env.user)


class EC2Host(BaseHost):

    def __init__(self, *args, **kwargs):
        super(EC2Host, self).__init__(*args, **kwargs)

    def get_ip(self):
        ec2 = _find_ec2_by_name(self.settings.EC2_NAME)
        return ec2.ip_address


class VagrantHost(BaseHost):

    def __init__(self, *args, **kwargs):
        super(VagrantHost, self).__init__(*args, **kwargs)
        self.vagrant_dir = os.path.dirname(self.settings.VAGRANT_FILE)

    def get_ip(self):
        ro = re.compile(r'^\s+config.+:private_network')
        with open(self.settings.VAGRANT_FILE, 'r') as vf:
            for line in vf:
                mo = ro.search(line)
                if mo is None:
                    continue
                mo = ip_re.search(line)
                if mo is not None:
                    return mo.group('ip')
        return None


class FabTaskIt(object):
    AWS_REQUIRED_VARS = [
        'AWS_ACCESS_KEY_ID',
        'AWS_AVAILABILITY_ZONE',
        'AWS_KEYPAIR_NAME',
        'AWS_REGION',
        'AWS_SECRET_ACCESS_KEY',
    ]

    def __init__(self):
        self.fabhosts = {}
        self.fabenvdirs = {}
        self.activated_hosts = []

    def setup(self):
        fabhome = os.path.expanduser('~/.fab-task-it')

        if os.path.exists(fabhome):
            envdirshome = os.path.join(fabhome, 'envdirs')
            if os.path.exists(envdirshome):
                self.load_envdirs(envdirshome)

            hostshome = os.path.join(fabhome, 'hosts')
            if os.path.exists(hostshome):
                self.load_hosts(hostshome)

        self.setup_hosts()
        self.setup_environments()

    def load_envdirs(self, envdir):
        for envroot, envdirs, envfiles in os.walk(envdir):
            for d in envdirs:
                fabenvdir = {
                    'name': d,
                    'path': os.path.join(envdir, d),
                }
                fabenvdir['vars'] = self._get_env_vars(fabenvdir['path'])
                self.fabenvdirs[d] = fabenvdir

    def _get_env_vars(self, path):
        env_vars = {}
        for root, dirs, files in os.walk(path):
            for filename in files:
                with open(os.path.join(path, filename)) as f:
                    env_vars[filename] = f.readline().rstrip("\n")
        return env_vars

    def load_hosts(self, hostsdir):
        for root, dirs, files in os.walk(hostsdir):
            for filename in files:
                if filename[-3:] != '.py' or filename == '__init__.py':
                    continue
                modname = filename[:-3]
                fabhost = {'name': modname}
                try:
                    fabhost['settings'] = imp.load_source(
                        'fabhosts.{}'.format(modname),
                        os.path.join(hostsdir, filename)
                    )
                    self.fabhosts[fabhost['name']] = fabhost
                    if fabhost['settings'].HOST_TYPE == 'EC2':
                        fabhost['helper'] = EC2Host(fabhost['settings'])
                    elif fabhost['settings'].HOST_TYPE == 'VAGRANT':
                        fabhost['helper'] = VagrantHost(fabhost['settings'])
                except ImportError:
                    puts("host [{}] initialization failed.".format(filename))

    def load_environment(self, fabenv):
        envdir = self.fabenvdirs.get(fabenv, None)
        if envdir is None:
            puts('WARNING: {} environment not found!'.format(fabenv))
            return
        for k, v in envdir['vars'].items():
            os.environ[k] = v

    def load_host_environments(self, fabhost):
        for host_env in fabhost['settings'].ENVIRONMENTS:
            self.load_environment(host_env)
        env.user = self.get_host_user(fabhost['name'])

    def get_host_port(self, hostname=None):
        if hostname is None:
            hostname = self.activated_hosts[0]
        return getattr(self.fabhosts[hostname]['settings'], 'SSH_PORT', 22)

    def get_host_user(self, hostname=None):
        if hostname is None:
            hostname = self.activated_hosts[0]
        return self.fabhosts[hostname]['helper'].get_host_user()

    def activate_host(self, host):
        fabhost = self.fabhosts[host]
        self.load_host_environments(fabhost)
        env.hosts.append(fabhost['helper'].get_ip())
        self.activated_hosts.append(fabhost['name'])

    def get_activate_host_func(self, host):
        def f():
            return self.activate_host(host)
        return f

    def setup_hosts(self):
        for i, host in enumerate(self.fabhosts.keys()):
            globals()['host_{}'.format(i)] = SimpleTask(
                self.get_activate_host_func(host),
                name=host
            )

    def activate_environment(self, fabenv):
        self.load_environment(fabenv)

    def get_activate_env_function(self, env):
        def f():
            return self.activate_environment(env)
        return f

    def setup_environments(self):
        for i, env in enumerate(self.fabenvdirs.keys()):
            globals()['env_{}'.format(i)] = SimpleTask(
                self.get_activate_env_function(env),
                name='env_{}'.format(self.fabenvdirs[env]['name']),
            )

    def get_available_files(self, *filenames):
        result = []
        for filename in filenames:
            pth = os.path.expanduser(filename)
            if os.path.exists(pth):
                result.append(pth)
        return result

    def get_ssh_private_key_files(self):
        return self.get_available_files('~/.ssh/id_dsa', '~/.ssh/id_rsa')

    def get_ssh_public_key_files(self):
        return self.get_available_files('~/.ssh/id_dsa.pub',
                                        '~/.ssh/id_rsa.pub')

    def get_ssh_command(self):
        port = self.get_host_port()
        user = self.get_host_user()
        host = env.hosts[0]
        return 'ssh -p {port} -l {user} {host}'.format(
            host=host,
            port=port,
            user=user,
        )

    def get_active_host_helper(self, hostname=None):
        if hostname is None:
            hostname = self.activated_hosts[0]
        return self.fabhosts[hostname]['helper']


class SimpleTask(Task):
    def __init__(self, func, *args, **kwargs):
        super(SimpleTask, self).__init__(*args, **kwargs)
        self.func = func

    def run(self, *args, **kwargs):
        return self.func(*args, **kwargs)


class AWSTask(Task):
    def __init__(self, func, *args, **kwargs):
        super(AWSTask, self).__init__(*args, **kwargs)
        self.func = func

    def run(self, *args, **kwargs):
        if not AWS_SUPPORT:
            abort('No aws support! Install boto.')
        for envvar in fabtaskit.AWS_REQUIRED_VARS:
            if envvar not in os.environ:
                abort('AWS environment not configured properly!')
        return self.func(*args, **kwargs)


fabtaskit = FabTaskIt()
fabtaskit.setup()


def print_ec2(ec2):
    title = "Name: {}".format(ec2.tags['Name'])
    puts(title)
    puts("=" * len(title))
    puts("ID: {}".format(ec2.id))
    puts("Name: {}".format(ec2.tags['Name']))
    puts("State: {}".format(ec2.state))
    puts("Type: {}".format(ec2.instance_type))
    puts("Public DNS: {}".format(ec2.dns_name))
    puts("Public IP: {}".format(ec2.ip_address))
    puts("Private DNS: {}".format(ec2.private_dns_name))
    puts("Private IP: {}".format(ec2.private_ip_address))
    # http://docs.pythonboto.org/en/latest/ref/ec2.html \
    #   #boto.ec2.instance.Instance.get_attribute
    ia = ec2.get_attribute('disableApiTermination')
    puts("Termination Protection: {}".format(ia['disableApiTermination']))
    ia = ec2.get_attribute('instanceInitiatedShutdownBehavior')
    puts("Shutdown Behavior: {}".format(
        ia['instanceInitiatedShutdownBehavior']))
    puts("")


@task
def test_hostname():
    puts(fabtaskit.activated_hosts)


@task
def test_environment():
    puts(os.environ)


@task(task_class=AWSTask)
def find_ec2_by_name(name):
    ec2 = _find_ec2_by_name(name)
    if ec2 is None:
        abort("Couldn't find '{}'".format(name))
    print_ec2(ec2)


@task
def login():
    local(fabtaskit.get_ssh_command())


@task
def list_all_ec2():
    ec2 = _get_ec2_connection()
    instances = ec2.get_all_instances()
    for reservation in instances:
        print_ec2(reservation.instances[0])


@task
def supervisor_restart(service):
    sudo('supervisorctl restart {0}'.format(service))


@task
def supervisor_status():
    sudo('supervisorctl status')


@task
def tailf(filepath):
    env.output_prefix = False
    sudo('tail -f {0}'.format(filepath))
    env.output_prefix = True


@task
def copy_ssh_pub_keys():
    keys = []

    for filename in fabtaskit.get_ssh_public_key_files():
        try:
            with open(filename, 'r') as f:
                keys.append(f.readline().rstrip("\n"))
        except IOError:
            pass

    puts('Got {} keys'.format(len(keys)))

    ssh_cmd = fabtaskit.get_ssh_command()

    result = local(
        "{ssh_cmd} 'cat .ssh/authorized_keys'".format(ssh_cmd=ssh_cmd),
        capture=True,
    )
    for key in keys:
        if result.find(key) < 0:
            puts('not found key:')
            puts(key)
            local("""{ssh_cmd} 'echo "{key}" >> .ssh/authorized_keys'"""
                  .format(ssh_cmd=ssh_cmd, key=key))


@task
def aptitude_update():
    run("{0} update".format(env.aptitude), quiet=True)


@task
def aptitude_safe_upgrade():
    execute(aptitude_update)
    run("{0} safe-upgrade".format(env.aptitude))


@task
def vagrant_up():
    vagrant = fabtaskit.get_active_host_helper()
    with lcd(vagrant.vagrant_dir):
        local('vagrant up')


@task
def vagrant_halt():
    vagrant = fabtaskit.get_active_host_helper()
    with lcd(vagrant.vagrant_dir):
        local('vagrant halt')


@task(task_class=AWSTask)
def ec2_terminate(name):
    ec2 = _find_ec2_by_name(name)
    if ec2 is None:
        abort("Couldn't find '{}'".format(name))
    try:
        ec2.terminate()
    except boto.exception.EC2ResponseError as ex:
        puts("[{}] {}".format(ex.error_code, ex.message))
