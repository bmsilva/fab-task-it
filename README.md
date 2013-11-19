fab-task-it
===========

Fantastic [Fabric](https://github.com/fabric/fabric) Tasks

You can have 2 types of configuration, `envdirs` and `fabhosts`.
* `envdirs` are used to configure environment variables that you might need.
* `fabhosts` is where we can set specific configurations for a given host.

Let's see how it works
----------------------

Create `$HOME/.fab-task-it/envdirs` and `$HOME/.fab-task-it/hosts` folders.

First let's start by configure an environment to use Amazon Web Services with
name `amazon`.

<pre>
$ mkdir $HOME/.fab-task-it/envdirs/amazon
</pre>

And now just create the environment variables. Example:

<pre>
$ echo 'eu-west-1b' > \
> HOME/.fab-task-it/envdirs/amazon/AWS_AVAILABILITY_ZONE
$ echo 'mykeypairname' > \
> $HOME/.fab-task-it/envdirs/amazon/AWS_KEYPAIR_NAME
$ echo 'eu-west-1' > \
> $HOME/.fab-task-it/envdirs/amazon/AWS_REGION
$ echo 'XXXXXXXXXXXXXXXXXXXX' > \
> $HOME/.fab-task-it/envdirs/amazon/AWS_ACCESS_KEY_ID
$ echo 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' > \
> $HOME/.fab-task-it/envdirs/amazon/AWS_SECRET_ACCESS_KEY
</pre>

All set! Now you can use the command `fab env_amazon list_all_ec2` to list all
your EC2 instances.

To configure a EC2 host you start to create a `myhostname.py` in
`$HOME/.fab-task-it/hosts`. Example:

<pre>
ENVIRONMENTS = ['amazon']
HOST_TYPE = 'EC2'
EC2_NAME = 'myhostname'
SSH_PORT = 22
</pre>

Because we specified that is a EC2 instance, the command `fab myhostname login`
searches Amazon EC2 to find the hostname with the Tag Name = `myhostname` to
get the ip address and then executes `ssh`.
