# rehearsal-realm
This is an exported realm from keycloak.

## Users and Roles

| user                      | pass      | roles                                   |
|---------------------------|-----------|-----------------------------------------|
| reader@pia-team.com       | reader    | read                                    |
| writer@pia-team.com       | writer    | write                                   |
| gokhan.demir@pia-team.com | Ankara20. | ENTERPRISE-GUI/ADMIN_ALL, camunda-admin |


## Obtain Access Token

| Name                     | Value                            |
|--------------------------|----------------------------------|
| Basic Auth client_id     | backend_clients                  |
| Basic Auth client_secret | GNkhosQwnEi8CBSNRlvpRX7K0vCIRoTq |
| grant_type               | password                         |
| scope                    | openid                           |

## Sample Curl
curl --location 'http://localhost:8000/realms/rehearsal-realm/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic YmFja2VuZF9jbGllbnRzOkdOa2hvc1F3bkVpOENCU05SbHZwUlg3SzB2Q0lSb1Rx' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'scope=openid' \
--data-urlencode 'username=reader@pia-team.com' \
--data-urlencode 'password=reader'