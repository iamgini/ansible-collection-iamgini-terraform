# Ansible Collection - iamgini.terraform

Documentation for the collection.


## Sample inventory source variables

```yaml
---
plugin: iamgini.terraform.tfe_state
hostname: terraform-server.awesome.com
organization: infra
workspace: nginx-api-infra
# token_env: TF_TOKEN_terraform_server_awesome_com
verify_ssl: false
compose:
  ansible_host: private_ip
keyed_groups:
  - key: tags.Environment
    prefix: env
resource_types:
  - aws_instance

search_child_modules: true
hostnames:
  # in case your Name tags are not proper
  - { prefix: "tag:Name", name: "id", separator: "__" }
  - private_dns
  - id

compose:
  ansible_host: private_ip   # or public_ip
```