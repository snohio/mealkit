curl --location --insecure --request POST 'https://mealkit.azure.chef-demo.com/api/v0/infra/servers/mealkit/orgs' \
--header 'Content-Type: application/json' \
--header 'api-token: eHss7Yf-nby8n65HnVBqNvTxgoQ=' \
--data '{
        "id": "tandori",
        "name": "tandori",
        "admin_user": "tandori",
        "admin_key": "$token"
        "server_id": "mealkit",
        "projects": [
            "tandori"
        ]
}'
