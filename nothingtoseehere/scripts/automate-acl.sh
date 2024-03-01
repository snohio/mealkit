curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/roles' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
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
curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "tandori",
  "name": "Tandori",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "pizza",
  "name": "Pizza",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "potpie",
  "name": "Potpie",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "meatloaf",
  "name": "Meatloaf",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "quesadilla",
  "name": "Quesadilla",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "chili",
  "name": "Chili",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "casserole",
  "name": "Casserole",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "sloppyjoe",
  "name": "Sloppy Joe",
  "password": "Cod3Can!"
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/users' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "potroast",
  "name": "Pot Roast",
  "password": "Cod3Can!"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "tandori",
  "name": "Tandori Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "pizza",
  "name": "pizza Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "potpie",
  "name": "Potpie Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "meatloaf",
  "name": "Meatloaf Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "quesadilla",
  "name": "Quesadilla Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "chili",
  "name": "Chili Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "casserole",
  "name": "Casserole Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "sloppyjoe",
  "name": "Sloppy Joe Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "id": "potroast",
  "name": "Potroast Project",
  "skip_policies": true
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/tandori/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
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

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/pizza/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "pizza"
      ]
    }
  ],
  "id": "pizza-rule",
  "name": "Pizza Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/potpie/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "potpie"
      ]
    }
  ],
  "id": "potpie-rule",
  "name": "potpie Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/meatloaf/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "meatloaf"
      ]
    }
  ],
  "id": "meatloaf-rule",
  "name": "meatloaf Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/quesadilla/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "quesadilla"
      ]
    }
  ],
  "id": "quesadilla-rule",
  "name": "quesadilla Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/chili/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "chili"
      ]
    }
  ],
  "id": "chili-rule",
  "name": "chili Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/casserole/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "casserole"
      ]
    }
  ],
  "id": "casserole-rule",
  "name": "casserole Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/sloppyjoe/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "sloppyjoe"
      ]
    }
  ],
  "id": "sloppyjoe-rule",
  "name": "sloppyjoe Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/projects/potroast/rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
  "conditions": [
    {
      "attribute": "CHEF_ORGANIZATION",
      "operator": "MEMBER_OF",
      "values": [
        "potroast"
      ]
    }
  ],
  "id": "potroast-rule",
  "name": "potroast Org Rule",
  "type": "NODE"
}'

curl --location 'https://mealkit.azure.chef-demo.com/apis/iam/v2/apply-rules' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
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

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "pizza Project Owners",
    "id": "pizza-project-owners",
    "members": [
        "user:local:pizza"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "pizza"
            ]
        }
    ],
    "projects": [
        "pizza"
    ]
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "potpie Project Owners",
    "id": "potpie-project-owners",
    "members": [
        "user:local:potpie"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "potpie"
            ]
        }
    ],
    "projects": [
        "potpie"
    ]
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "meatloaf Project Owners",
    "id": "meatloaf-project-owners",
    "members": [
        "user:local:meatloaf"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "meatloaf"
            ]
        }
    ],
    "projects": [
        "meatloaf"
    ]
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "quesadilla Project Owners",
    "id": "quesadilla-project-owners",
    "members": [
        "user:local:quesadilla"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "quesadilla"
            ]
        }
    ],
    "projects": [
        "quesadilla"
    ]
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "chili Project Owners",
    "id": "chili-project-owners",
    "members": [
        "user:local:chili"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "chili"
            ]
        }
    ],
    "projects": [
        "chili"
    ]
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "casserole Project Owners",
    "id": "casserole-project-owners",
    "members": [
        "user:local:casserole"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "casserole"
            ]
        }
    ],
    "projects": [
        "casserole"
    ]
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "sloppyjoe Project Owners",
    "id": "sloppyjoe-project-owners",
    "members": [
        "user:local:sloppyjoe"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "sloppyjoe"
            ]
        }
    ],
    "projects": [
        "sloppyjoe"
    ]
}'

curl --location --request POST 'https://mealkit.azure.chef-demo.com/apis/iam/v2/policies' \
--header 'Content-Type: application/json' \
--header 'api-token: 5KCZeGdLVI6AMk2a7TuHD7cNQA4=' \
--data '{
    "name": "potroast Project Owners",
    "id": "potroast-project-owners",
    "members": [
        "user:local:potroast"
    ],
    "statements": [
        {
            "effect": "ALLOW",
            "actions": [],
            "role": "mealkit-owner",
            "projects": [
                "potroast"
            ]
        }
    ],
    "projects": [
        "potroast"
    ]
}'
