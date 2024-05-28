#!/usr/bin/env bash

for test in empty_list simple_ldap full_ldap; do
    # echo "Testing $test"

    # 1. First ensure loginIdentityProviders.provider is always a list (as it is not correctly infered in case the list
    #  contains 0 or 1 entry).
    # 2. Replace username and password in the JSON
    # 3. Convert back to xml
    yq -p xml -o json '.loginIdentityProviders.provider |= ([] + .)' ${test}.xml \
    | yq -p json -o json '(.loginIdentityProviders.provider[]? | select(.identifier=="login-identity-provider").property[]? | select(.+@name=="Manager DN")).+content = "my-user"' \
    | yq -p json -o json '(.loginIdentityProviders.provider[]? | select(.identifier=="login-identity-provider").property[]? | select(.+@name=="Manager Password")).+content = "my-password"' \
    | yq -p json -o xml \
    > ${test}_output.xml

    if cmp -s ${test}_output.xml ${test}_expected.xml; then
        echo "[OK     ] The file ${test}_output.xml is the same as ${test}_expected.xml"
    else
        echo "[FAILED ] The file ${test}_output.xml differed from ${test}_expected.xml"
    fi
done
