#!/bin/bash

# Function to base64 encode input
base64_encode() {
  echo -n "$1" | base64 | tr -d '\n=' | tr -- '+/' '-_' | tr -d '\n'
}

USER_NAME=$(whoami)
IAT_TIMESTAMP=$(date +%s)
EXP_TIMESTAMP=$((IAT_TIMESTAMP+3600))
# Input payload (replace with your JSON data)
payload='{"sub":"'$USER_NAME'", "fullName":"'$USER_NAME'",  "email":"'$USER_NAME'@yahooinc.com", "exp":'$EXP_TIMESTAMP', "iat":'$IAT_TIMESTAMP' , "aud":"oms-microservice", "roles": [ "DEVELOPER" ] }'


# Encode the header and payload
encoded_header=$(base64_encode '{"alg":"HS256","typ":"JWT"}')
encoded_payload=$(base64_encode "$payload")

# Create the signature (replace 'your_secret_key' with your secret key)
header_payload="${encoded_header}.${encoded_payload}"

DUMMY_SECRET=$(date +%s)
signature=$(echo -n "$header_payload" | openssl dgst -binary -sha256 -hmac "$DUMMY_SECRET" | base64 | tr -d '\n=' | tr -- '+/' '-_' | tr -d '\n')

# Combine all parts into a JWT token
jwt_token="${header_payload}.${signature}"

# Output the JWT token
echo "Bearer $jwt_token"
