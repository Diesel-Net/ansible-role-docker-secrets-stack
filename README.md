# ansible-role-docker-stack

A very fancy call to "docker stack deploy" which makes docker configs and secrets management almost mindless. See below for an example playbook. The key to this role is in [deploy.py](files/deploy.py)

_docker_stack_deploy.yaml_
```yaml
# ansible-playbook docker_stack_deploy.yaml -i inventories/dev/hosts --vault-id ~/.tokens/master_id

# 1. Copy requirements.txt
# 2. Copy deploy.py
# 3. Build venv
# 4. Set environment variables on remote host
# 5. Execute deploy.py on remote host

- hosts: swarm_leader
  strategy: linear
  roles:
    - docker_stack

  environment:
    DOCKER_STACK: "{{ docker_stack }}"
    DOCKER_REGISTRY: "{{ docker_registry }}"
    DOCKER_REGISTRY_USER: "{{ docker_registry_user }}"
    DOCKER_REGISTRY_PASSWORD: "{{ docker_registry_password }}"

  tasks:

    - name: Run `docker stack deploy` command
      include_role:
        name: docker_secrets_stack
        tasks_from: deploy

```
