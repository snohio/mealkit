# Steps Required to Provision the Environment

> For what it is worth, this document describes how to provision the Mealkit environment, some of which requires the corresponding **mealkit** Terraform Plan that is private to Progress Chef Employees. That said, you can kind of do this on your own, but you will need to provision a functioning Automate server with a corresponding workstation and then up to 20 nodes that can be used as lab environments.
>The TL;DR is that unless you work for Chef, this probably is going to be too difficult to do on your own.

## Provision the Automate and Workstation servers

This will provision your lab on Azure as that is what Terraform script is built to do.

* Using the SA-DEMO-CORE Terraform plan for Azure, update the `terraform.tfvars` with the necessary items and then `terraform init` `terraform apply`.
* You can start with `linux_node_count = 2` and just the base. When you get further along and are closer to the time to go, you can then change it to `linux_node_count = 20`
* Validate by opening the [Automate UI](https://mealkit.azure.chef-demo.com) Log into it with "admin" and the password set in your `terraform.tfvars` file.

## Create Lab Users and Orgs

You can do this with any number of users and orgs, it ends up being one org per "student".

* Log on to the *Workstation* with the IP that is in your `terraform output`
* From there `ssh -i .ssh/sys_admin.pem ubuntu@10.10.2.5` (or 10.10.2.4 whatever your Automate IP is.)
* `sudo su` to make life easy
* `chef-automate status` for an Automate health check
* `pwd` and make sure you are in `/home/ubuntu`
* `git clone https://ghp_YoUrPAtTokenGoesHere@github.com/snohio/mealkit.git`
* `cd mealkit/nothingtoseehere/scripts` We are going to replace all of the tokens here. There is a .pem and _validator.pem for every user / org.
* `rm *.pem` as these will be needed on the workstation and the users machines later.
* run `bash ./chef-user-org-create.sh` to create all of the users orgs
* commit the changes with `git add *` `git commit -am "new pems"` `git push origin`

You should now have all of the users and orgs created and the pem files are now back in Github. We'll pull those down onto the Workstation when we bootstrap nodes to their respective mealkits.

## Create the Users, Roles, Policies and Projects in Automate

All of the below can be done by running `bash ~/mealkit/nothingtoseehere/scripts/automate-acl.sh`. Before running it, you will need to edit that and find / replace the api-token with the one that is created which you can find in Automate.

* Create the Role that we need to assign to the Policies. You'll need to update the header token from Automate.

```bash
curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/roles' \
--header 'Content-Type: application/json' \
--header 'api-token: gEtthiSadm1ntokenFromAutomate=' \
--data '{
    "id": "mealkit-owner",
    "name": "Mealkit Owner",
    "actions": [
        "reportmanager:*",
        "event:*:get",
        "event:*:list",
        "infra:nodes:get",
        "infra:nodes:list",
        "infra:infraServers:list",
        "infra:infraServers:get",
        "infra:infraServers:update",
        "compliance:*:get",
        "compliance:*:list"
    ],
    "projects": []
}'
```

* Create the Users for each of the Mealkits

```bash
curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{
  "id": "tandori",
  "name": "Tandori",
  "password": "Cod3Can!"
}'
```

* Create the Project

```bash
curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{
  "id": "tandori",
  "name": "Tandori Project",
  "skip_policies": true
}'
```

* Create the Rule for the Project

```bash
curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/tandori/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "tandori"
      ]
    }
  ],
  "id": "tandori-rule",
  "name": "Tandori Org Rule",
  "type": "NODE"
}'
```

* Run the update after creating all of the Projects and Rules

```bash
curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/apply-rules' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{
}'
```

* Finally create the Policy

```bash
curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{
    "name": "Tandori Project Owners",
    "id": "tandori-project-owners",
    "members": [
        "user:local:tandori"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "tandori"
            ]
        }
    ],
    "projects": [
        "tandori"
    ]
}'
```

* Add the Org to the Infra Servers and tie it to a project

```bash
curl --location --request POST 'https://mealkit.azure.chef-demo.com/api/v0/infra/servers' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{ 
    "id": "mealkit",
    "name": "Mealkit Workshop",
    "fqdn": "mealkit.azure.chef-demo.com"
}'
```

* Add the Org to the Infra Servers and tie it to a project

> THIS IS STILL A WORK IN PROGRESS. THIS NEEDS TO BE DONE MANUALLY FOR NOW UNTIL I LEARN HOW TO GET THE KEY IN THE SCRIPT

```bash
curl --location --request POST 'https://mealkit.azure.chef-demo.com/api/v0/infra/servers/mealkit/orgs' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{
    "id": "tandori",
    "name": "tandori",
    "admin_user": "tandori",
    "admin_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1rVICfTtfIV70FFOw9QnRkD5yUzGOcHAoHkwteKkwq7lzY6G/6JO+5oHFDPzLcZuHbcWjkr13DQx9d3FyYH9xcZ4DB9d/iZsFCSElFt6jQ3ibEVy\n2OJV3SU1sw1j1MQdeHmdXsatStiiqIHPLYt3b1rkqpgMHiHxfqLswiteNWbUcYZ8\nSytGgWcA7AVl4sxJwHadz+jwQX/Xk8HhN2xTIN/lNJ6NR5yZdH0gIX+pjnxzYKIH\n21pxwKk7KaKFfd38nWFi7+uYCs0QUdFluscuwINTyz6AWeh9v9hDMzp31JJIvWlG\nm75ubNnQOGE2W2Zy449WqxzY8OqYC0rJCeFPgwIDAQABAoIBAQDWG80M8Mxq4ooH\nwS00p7nKmzz8eq0qJ4a6AGCM4MjAw7yycbE591egG4d3pB6axUhGJbA+kY3/26T+\ns/tq6VByC2rnW9hVe2dH5uq3L0pUo0XqBo9yrLJHZ7XXKkElibSB0XUXcDSbcNE0\nDM7Xcj7WMuPZIurimaLDUCGdt7WotV+/e4Zk5u3gMZtPw9Ctm2MuEHeyEhnBrWsZ\npdHo0+db01C9o8Q84F64zc5ACnNzyWwFJ9d9hGYMewLIy4T8a2+URLDOVkYOOilX\nmigXH+Vp/yP8QcdqvvwZX9trdBrVgopaTBoujshGaAqrv+ltb/+W626Fog6njWyP\nF79zJKbhAoGBAPyFTnca8qW4iia0VHGjY/UFY6g+9b7pUY0yl7zr86p312RnyPdO\nGXuFyeJ4fjaFh0EcFdtKoIbD1UeyWGkFiD8aq/MOUS0UYir62mOdg9Lq2EXxe1Gn\nJp0hYr5optgHRHIQf9Uiu4iYVPGTiw3nbWo866G7WPekPde69ebA/Ny5AoGBANmq\nmhkJ6BC7U789I7Nh3sQk1H9mZyX0Thw5SN6VQ06LPKVN1MmHhXgBkB+j0Q8js1Wj\nHYtEsfnGdj2ULFeGYU27iZGej6zu0UaOUNxNGWFzxOY+NNPRn2tGrSeM+k6D5kcw\nEDqRUTaszlHI5zdnQJB6SScd4BUP3XDRTEOdMkgbAoGAFpkzeXM+7dfC/U28FONj\naaUO0xq3UVt+Ad3aOH0BNGs/KmwjTwZ9P1GszIit+uEeRpRl3FckYIscBiuOv+9P\nzx3q73iDiT4+vsvuSWXqSzDbI/9FYvxLd1pqhNHGxKR52p9hYUiXcdT4HRpwIlFo\nuE41ZCbpAlh/dFP1962js3kCgYEAvpx+i7S4K4bQJOV2kQ0A1oVmLRbQ91TE3kRw\nArN1mJ+oAR5yW/U4tUmxG3QKjJZ34mOQaLhEnvXj77MFTbRZG4hCRWo0aX1NeNsC\nBpnhwwxtfi81ddTZJUlkMwFq5TzueKKnY5KEKzwTBV3I1SSvTpY333BzHh6hjb1L\nat6K/McCgYA4xVfQ55qvNgyzfHDFkvcPSKv2ICypreDBPecZkz8mRBEOAluxxgCd\n9ejvOzwMGTq4cUMc1CYaf9CUhtbWUi/CtbqX8n0A5wgUSpQ1PKJo12JTkaHCC9gr\n8ga48WzQiqAqZDStbggggJZjOBivxOgMPzNkP2RTcoZeI2BlO87/KA==\n-----END RSA PRIVATE KEY-----",

    "server_id": "mealkit",
    "projects": [
        "tandori"
            ]
}'
```

## Re-bootstrap all of the nodes

### Pre Work

* `git clone https://ghp_YoUrPAtTokenGoesHere@github.com/snohio/mealkit.git`
* Create a hosts file with all of the nodes and their IP addresses on the Workstation
* Move the old credentials file `mv ~/.chef/credentials ~/.chef/credentials.orig`
* Put the credentials file that is in the `cp ~/mealkit/nothingtoseehere/credentials ~/.chefcat /credentials`
* You actually need to merge those two together. Default should be the it_devops org.
* Test with `export CHEF_PROFILE=default` `knife client list`

### Remove the nodes from the default it_devops org

* Set the profile to default with `export CHEF_PROFILE=default`
* Role through the list to do a `knife node delete node-linux-xx`.
* Also do a `knife client delete node-linux-xx`

> You can run `bash ~/mealkit/nothingtoseehere/scripts/node-delete.sh` and it will remove all of the nodes. Make sure you have it_devops org in your credentials named [default]

### Re-bootstrap with knife bootstrap commands

* From the workstation, you can rebootstrap all of the nodes.

```bash
export CHEF_PROFILE=tandori
knife bootstrap node-linux-03 -N node-linux-03 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo
knife bootstrap node-linux-04 -N node-linux-04 -x ubuntu -i ~/.ssh/sys_admin.pem --sudo
knife client list
```

> You can run `bash ~/mealkit/nothingtoseehere/scripts/rebootstrap.sh` assuming your credentials file is all good and you have your hosts file up to date.
