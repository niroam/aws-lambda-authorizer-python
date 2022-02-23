import re
import json
import os
import boto3
import time
import logging
from jose import jwk, jwt
from jose.utils import base64url_decode
import auth_manager

region = os.environ['AWS_REGION']
jwk_set = json.loads(os.environ['JWKS_STRING'])['keys']
valid_issuers = json.loads(os.environ['VALID_ISSUERS'])
sts_client = boto3.client("sts", region_name=region)

def lambda_handler(event, context):
    
    # Basic token validation - must be Bearer token#
    token = event['authorizationToken'].split(" ")
    if (token[0] != 'Bearer'):
        raise Exception('Authorization header should have a format Bearer <JWT> Token')
    
    jwt_bearer_token = token[1]
    logging.info("Method ARN: " + event['methodArn'])
    
    # get the kid from the headers prior to verification
    kid = getKidFromHeader(jwt_bearer_token)

    # search for the kid in the downloaded public keys
    public_key = findKidInJwkList(kid)
    
    # decode and validate the token / claims
    verified_claims = decodeAndValidateToken(jwt_bearer_token, public_key)

    # At this point assume toke verfication was succesfull as we throw errors during validation

    tmp = event['methodArn'].split(':')
    api_gateway_arn_tmp = tmp[5].split('/')
    aws_account_id = tmp[4]    
    
    principal_id = "User|" + verified_claims["custom:tenantId"]
    tenant_id = verified_claims["custom:tenantId"]

    tenant_iam_policy = auth_manager.getPolicyForUser(auth_manager.UserRoles.TENANT_USER, tenant_id, region, aws_account_id)
    
    assume_role_arn = f"arn:aws:iam::{aws_account_id}:role/blueprint-python-api-authorizer-access"

    tenant_session_credentials = getTenantSessionCredentials(tenant_iam_policy, assume_role_arn, "tenant-aware-session")

    policy = AuthPolicy(principal_id, aws_account_id)
    policy.restApiId = api_gateway_arn_tmp[0]
    policy.region = tmp[3]
    policy.stage = api_gateway_arn_tmp[1]

    #roles are not fine-grained enough to allow selectively
    policy.allowAllMethods()        
    
    authResponse = policy.build()

    #pass sts credentials to lambda
    context = {
        "userName": verified_claims["cognito:username"],
        "tenantId": tenant_id,
        'accesskey': tenant_session_credentials['AccessKeyId'],
        'secretkey' : tenant_session_credentials['SecretAccessKey'],
        'sessiontoken' : tenant_session_credentials["SessionToken"],
    }
    
    authResponse['context'] = context
    
    return authResponse
    
def getTenantSessionCredentials(iam_policy, role_arn, session_name):
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        Policy=iam_policy,
    )

    return assumed_role["Credentials"]

def getKidFromHeader(jwt_bearer_token: str):
    # get the kid from the headers prior to verification
    try:
        headers = jwt.get_unverified_headers(jwt_bearer_token)

        kid = headers.get('kid')

        if kid:
            return kid
        else:
            raise Exception('Token should have a kid in header')
    
    except Exception as e:
        raise Exception(f"Error parsing header {e}")


def findKidInJwkList(kid: str):
    try:
        key_index = -1
        for i in range(len(jwk_set)):
            if kid == jwk_set[i]['kid']:
                key_index = i
                break
        if key_index == -1:
            raise Exception('Matching key not found in JWK list')
        
        return jwk.construct(jwk_set[key_index])
    except Exception as e:
        raise Exception(f"Error finding kid in jwk list {e}")

def decodeAndValidateToken(jwt_token: str, public_key):
    try:
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(jwt_token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        # verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise Exception('Signature verification failed')

        # since we passed the verification, we can now safely
        # use the unverified claims
        claims = jwt.get_unverified_claims(jwt_token)

        if time.time() > claims['exp']:
            raise Exception('Token is expired')
        # and the Audience  (use claims['client_id'] if verifying an access token)
        if claims['iss'] not in valid_issuers:
            raise Exception('Token has invalid issuer')

        return claims
    except Exception as e:
        raise Exception(f"Error decoding and validating token {e}")


class HttpVerb:
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    PATCH   = "PATCH"
    HEAD    = "HEAD"
    DELETE  = "DELETE"
    OPTIONS = "OPTIONS"
    ALL     = "*"

class AuthPolicy(object):
    awsAccountId = ""
    """The AWS account id the policy will be generated for. This is used to create the method ARNs."""
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""

    """these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the approriate
    statements for the final policy"""
    allowMethods = []
    denyMethods = []

    restApiId = "*"
    """The API Gateway API id. By default this is set to '*'"""
    region = "*"
    """The region where the API is deployed. By default this is set to '*'"""
    stage = "*"
    """The name of the stage used in the policy. By default this is set to '*'"""

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = ("arn:aws:execute-api:" +
            self.region + ":" +
            self.awsAccountId + ":" +
            self.restApiId + "/" +
            self.stage + "/" +
            verb + "/" +
            resource)

        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            statements.append(statement)

        return statements

    def allowAllMethods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId' : self.principalId,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Deny", self.denyMethods))

        return policy