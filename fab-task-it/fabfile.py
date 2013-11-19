import imp
import os

from fabric.api import task, puts, env, local
from fabric.tasks import Task
from fabric.utils import abort


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
        self.AWS_SUPPORT = True

        try:
            import boto.ec2
            #import boto.ec2.elb
            self.boto_ec2 = boto.ec2
            #self.boto_ec2_elb = boto.ec2.elb
        except ImportError:
            self.AWS_SUPPORT = True

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

    def get_host_port(self, hostname=None):
        if hostname is None:
            hostname = self.activated_hosts[0]
        return getattr(self.fabhosts[hostname]['settings'], 'SSH_PORT', 22)

    def activate_host(self, host):
        fabhost = self.fabhosts[host]
        self.load_host_environments(fabhost)
        if fabhost['settings'].HOST_TYPE == 'EC2':
            ec2 = self.find_ec2_by_name(fabhost['settings'].EC2_NAME)
            env.hosts.append(ec2.ip_address)

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

    def get_ec2_connection(self):
        assert(self.AWS_SUPPORT)
        region = os.environ.get('AWS_REGION', 'eu-west-1')
        ec2 = self.boto_ec2.connect_to_region(region)
        #self.boto_ec2_elb.connect_to_region(region)
        return ec2

    def find_ec2_by_name(self, name):
        ec2 = self.get_ec2_connection()
        instances = ec2.get_all_instances(
            filters={'tag:Name': name})
        if len(instances) == 0:
            return None
        elif len(instances) > 1:
            puts("Found more than one!")
            return None
        reservation = instances[0]
        return reservation.instances[0]


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
        if not fabtaskit.AWS_SUPPORT:
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
    puts("")


@task
def test_hostname():
    puts(fabtaskit.activated_hosts)


@task
def test_environment():
    puts(os.environ)


@task(task_class=AWSTask)
def find_ec2_by_name(name):
    ec2 = fabtaskit.find_ec2_by_name(name)
    if ec2 is None:
        abort("Couldn't find '{}'".format(name))
    print_ec2(ec2)


@task
def login():
    port = fabtaskit.get_host_port()
    host = env.hosts[0]
    local('ssh -p {port} {host}'.format(host=host, port=port))


@task
def list_all_ec2():
    ec2 = fabtaskit.get_ec2_connection()
    instances = ec2.get_all_instances()
    for reservation in instances:
        print_ec2(reservation.instances[0])
