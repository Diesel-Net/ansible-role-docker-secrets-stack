#!/usr/bin/env python3

'''
This script is used to solve an issue we have with docker configs/secrets.
It's basically just a glorified version of a similiar script with extra 
stuff thrown in which is a little more specific to our docker-compose file:

https://blog.viktoradam.net/2018/02/28/swarm-secrets-made-easy/

The basic idea is that docker configs/secrets will complain about a name clash 
if you change the contents of a config/secret file and try to run 
`docker stack deploy` again. You would think that docker would assume a file 
change meant that you wanted to update/rotate the config/secret for the service
where it is defined, but that was not the case at the time of this writing.

In a nutshell, this script simply renames specially crafted docker 
configs/secrets in a docker-compose file by setting their md5 hashes to their 
respective environment variables which get expanded automatically when invoking 
`docker stack deploy`. By nature, this solves a few important issues we have 
when using docker stack commands in a ci/cd pipeline. Below is an example 
docker config definiton from our compose file.

docker-compose.yaml
>------------------------------------------------------------<
>
>configs:
>  proxy_config:
>    file: /some/path/to/a/config.file
>    name: ${DOCKER_STACK}_proxy_config_${HASH_PROXY_CONFIG}
>
>------------------------------------------------------------<

Here are the benfits of appending the hash to the docker config/secret names:
- makes secret/config management for docker easy/mindless
- guarantees uniqueness of the docker config/secret
  - if hash doesn't change, docker won't try to update the stack with a 
    new non-unique config/secret
- guarantees that docker will attempt to reuse pre-existing configs/secrets
  - this helps with rolling back your service's configs/secrets if needed

'''

import os
import yaml
import hashlib
from subprocess import Popen, PIPE
from sys import argv, stdout, stderr
import re
import fcntl


USAGE = "usage: python " + __file__ + " compose_file"
COMMAND_ERROR = "Error: Command returned nonzero exit code."
HASH_PREFIX = "HASH_"
ASCII_COLOR = False
PRE_REQUIRED_VARS = [
    "DOCKER_REGISTRY",
    "DOCKER_REGISTRY_USER",
    "DOCKER_REGISTRY_PASSWORD",
    "DOCKER_STACK",
]
LOCK_FILENAME = "docker_commands.lock"
LOCK_FILE = open(LOCK_FILENAME, 'w')

def main():
    if len(argv) < 2:
        print(USAGE)
        return 1
    
    compose_file = argv[1]
    with open(compose_file) as file:
        stack_yaml = yaml.safe_load(file.read())
        file.seek(0)
        required_vars = gather_required_vars(file.read()) + PRE_REQUIRED_VARS

    unset_vars = [var for var in required_vars if not os.environ.get(var)]
    if unset_vars:
        print_ascii(
            "Error: required environment variables are not set.",
            0, 
            31, 
            40, 
            file_stream=stderr,
        )
        for var in unset_vars:
            print_ascii(var, 0, 31, 40, file_stream=stderr)
        return 1

    print_ascii("[Generating md5's...]", 0, 36, 40)
    hashes = {}
    for key, value in iter_docker_hashes(stack_yaml):
        hashes[key] = value
        stdout.write("%32s <-- %s \n" % (value, key.lower()[len(HASH_PREFIX):]))

    env_vars = {**{var: os.environ.get(var) for var in required_vars}, **hashes}

    print_ascii("[Logging into docker registry...]", 0, 36, 40)
    error = docker_login(env_vars)
    if error:
        print_ascii(COMMAND_ERROR, 0, 31, 40, file_stream=stderr)
        return error

    print_ascii("[Deploying stack...]", 0, 36, 40)
    error = docker_stack_deploy(compose_file, env_vars)
    if error:
        print_ascii(COMMAND_ERROR, 0, 31, 40, file_stream=stderr)
    return error

def gather_required_vars(compose_file):
    regex = r"\$\{(?!"+HASH_PREFIX+r")\w+\}"
    matches = re.findall(regex, compose_file)
    required = set()
    for match in matches:
        required.add(match[2:-1])
    return list(required)

def print_ascii(string, style, fg_color, bg_color, file_stream=stdout):
    if ASCII_COLOR:
        file_stream.write("\033["+str(style)+";"+str(fg_color)+";"+str(bg_color)+"m")
        file_stream.write(string)
        file_stream.write("\033[0;0;0m")
        file_stream.write("\n")
    else:
        file_stream.write(string)
        file_stream.write("\n")

def iter_docker_hashes(stack_yaml):
    for key, config in {**stack_yaml.get("secrets", {}), **stack_yaml.get("configs", {})}.items():
        path = config.get("file")
        name = config.get("name")
        if not path or not name:
            continue

        path = os.path.normpath(path)
        if os.path.exists(path):
            with open(path, "rb") as secret_file:
                md5_hash = hashlib.md5(secret_file.read()).hexdigest()

            var_name = HASH_PREFIX + key.upper()

            yield var_name, md5_hash
        else:
            print_ascii("Warning: Cannot find "+path, 0, 33, 40, file_stream=stderr)

def docker_login(env_vars):
    command = (
        "docker login " + env_vars["DOCKER_REGISTRY"]
        + " -u"+ env_vars["DOCKER_REGISTRY_USER"]
        + " --password-stdin"
    )

    print_ascii(command, 0, 33, 40)
    with Popen(
        [command],
        stdout=PIPE,
        stderr=PIPE,
        stdin=PIPE,
        shell=True,
        env=env_vars,
    ) as proc:
        proc.stdin.write(env_vars["DOCKER_REGISTRY_PASSWORD"].encode())
        output, error = proc.communicate()
        stderr.write(error.decode())
        stdout.write(output.decode())
    
    return proc.returncode

def docker_stack_deploy(compose_file, env_vars):
    command = (
        "docker stack deploy --with-registry-auth --prune -c "
        + compose_file + " " + env_vars["DOCKER_STACK"]
    )

    print_ascii(command, 0, 33, 40)
    with Popen(
        [command], 
        stdout=PIPE, 
        stderr=PIPE, 
        shell=True, 
        env=env_vars,
    ) as proc:
        stderr.write(proc.stderr.read().decode())
        stdout.write(proc.stdout.read().decode())

    return proc.returncode

if __name__ == "__main__":
    # Grab the mutex
    fcntl.lockf(LOCK_FILE, fcntl.LOCK_EX)

    # Run the critical section
    exit_code = main()
    
    # The below line is not necessary, due to cleanup routines,
    # but is arguably more clear to leave it in.
    fcntl.lockf(LOCK_FILE, fcntl.LOCK_UN)

    # Return any error codes to the caller (e.g. ansible)
    exit(exit_code)
