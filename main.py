# Web-services classes

# Import external modules
from google.appengine.ext import ndb
import jinja2
import json
import logging
import os
import re
import time
import urlparse
import webapp2
# Import application modules
import application
from configOpenVoterId import const as conf
import globalRecord
from secretsOpenVoterId import const as secrets
import security
import voter
import voterRecord



JINJA_ENVIRONMENT = jinja2.Environment(
    loader = jinja2.FileSystemLoader( os.path.dirname(__file__) ),
    extensions = ['jinja2.ext.autoescape'],
    autoescape = True
)



class AdminPage( webapp2.RequestHandler ):

    def get(self):  self.post()

    def post(self):
    
        templateFile = 'admin.html'

        # Collect inputs
        requestLogId = os.environ.get( conf.REQUEST_LOG_ID )
        responseData = { 'success':False, 'requestLogId':requestLogId }
        inputData = urlparse.parse_qs( self.request.body )
        if conf.isDev: logging.debug( 'AdminPage.post() inputData=' + str(inputData) )

        adminSecret = getPostParam(inputData, 'adminSecret')
        operation = getPostParam(inputData, 'operation')
        if conf.isDev: logging.debug( 'AdminPage.post() operation=' + str(operation) )
        
        hasAdminPassword = globalRecord.hasAdminPassword()
        responseData['hasAdminPassword'] = hasAdminPassword
        responseData['setAdminPasswordDisabled'] = 'disabled' if hasAdminPassword  else ''

        # Check operation
        if not operation:
            return outputPage( templateFile, responseData, self.response, errorMessage='No operation' )

        # Check admin key
        # Crumb not required, because there is no verification-cookie, admin-passwords must always be provided
        if (adminSecret != secrets.adminSecret):
            return outputPage( templateFile, responseData, self.response, errorMessage='Admin key invalid' )

        # Set or check admin password stored in datastore
        if operation == 'setAdminPassword':

            newPassword = getPostParam( inputData, 'adminPassword' )
            success = globalRecord.setAdminPassword( newPassword )
            if not success:
                return outputPage( templateFile, responseData, self.response, errorMessage='Cannot set admin password' )

            responseData['hasAdminPassword'] = True
            responseData['setAdminPasswordDisabled'] = 'disabled'
            return outputPage( templateFile , responseData, self.response, successMessage='Set admin password' )

        else:
            if not hasAdminPassword:
                return outputPage( templateFile, responseData, self.response, errorMessage='Admin password not set' )
            inputPassword = getPostParam( inputData, 'adminPassword' )
            if not globalRecord.checkAdminPassword( inputPassword ):
                return outputPage( templateFile, responseData, self.response, errorMessage='Admin password invalid' )

        # New application
        if operation == 'newApplication':
        
            returnUrl = application.standardizeReturnUrl( getPostParam(inputData, 'returnUrl') )
            if not returnUrl:  return outputPage( templateFile, responseData, self.response, errorMessage='returnUrl invalid' )
            
            # Create application record
            applicationId = security.randomStringWithLength( 30 )
            requestSigningSecret = security.randomStringWithLength( 300 )
            responseSigningSecret = security.randomStringWithLength( 300 )
            applicationRecord = application.ApplicationRecord(
                id=applicationId , returnUrl=returnUrl ,
                requestSigningSecret=requestSigningSecret , 
                responseSigningSecret=responseSigningSecret
            )
            applicationRecord.put()

            responseData['applicationId'] = applicationId
            responseData['requestSigningSecret'] = requestSigningSecret
            responseData['responseSigningSecret'] = responseSigningSecret
            return outputPage( 'newApplication.html' , responseData, self.response, successMessage='Created application' )

        # Update application
        elif operation == 'updateApplication':
        
            applicationId = getPostParam(inputData, 'applicationId')
            returnUrl = application.standardizeReturnUrl( getPostParam(inputData, 'returnUrl') )
            if not returnUrl:  return outputPage( templateFile, responseData, self.response, errorMessage='returnUrl invalid' )
            
            applicationRecord = application.ApplicationRecord.get_by_id( applicationId )
            if not applicationRecord:  return outputPage( templateFile, responseData, self.response, errorMessage='applicationId=' + str(applicationId) + ' not found' )
            
            # Update application record
            applicationRecord.returnUrl = returnUrl
            applicationRecord.put()

            return outputPage( templateFile , responseData, self.response, successMessage='Updated application' )

        else:
            return outputPage( templateFile, responseData, self.response, errorMessage='unhandled operation' )



# Upload voters: identity, city, verification salts & hashes
class SetVoters( webapp2.RequestHandler ):

    def post(self):
    
        # Collect inputs
        requestLogId = os.environ.get( conf.REQUEST_LOG_ID )
        responseData = { 'success':False, 'requestLogId':requestLogId }
        inputData = json.loads( self.request.body )
        if conf.isDev: logging.debug( 'SetVoters.post() inputData=' + str(inputData) )

        # Check admin key
        # Crumb not required, because there is no verification-cookie, admin-passwords must always be provided
        adminSecret = inputData.get( 'adminSecret', None )
        if (adminSecret != secrets.adminSecret):  return outputJsonError( 'Admin key invalid', self.response )

        # Check request signature
        signatureInput = inputData.get( 'signature', None )
        if not security.isValidHashForSignature( signatureInput ):  return outputJsonError( 'Signature invalid', self.response )
        signatureData = inputData.copy()
        signatureData.pop( 'signature', None )
        signatureComputed = security.postVoterSignSignature( signatureData )
        if (signatureInput != signatureComputed):  return outputJsonError( 'signatureInput != signatureComputed', self.response )

        # Check admin password from datastore
        hasAdminPassword = globalRecord.hasAdminPassword()
        if not hasAdminPassword:
            return outputJsonError( 'Admin password not set', self.response )
        inputPassword = inputData.get( 'adminPassword', None )
        if not globalRecord.checkAdminPassword( inputPassword ):
            return outputJsonError( 'Admin password invalid', self.response )

        # For each voter-record...
        for record in inputData.get( 'records', [] ):
        
            # Check identity, city, verification salts & hashes
            identity = record.get( 'identity', None )
            if not voter.isValidIdentityHash( identity ):  return outputJsonError( 'Invalid identity', self.response )

            city = voter.standardizeCity( record.get( 'city', None ) )
            if not city:  return outputJsonError( 'Invalid city', self.response )
            
            saltPhone = record.get( 'saltPhone', None )
            if saltPhone and ( not voter.isValidVerificationSalt(saltPhone) ):  return outputJsonError( 'Invalid saltPhone', self.response )
            
            saltSocialSec = record.get( 'saltSocialSec', None )
            if saltSocialSec and ( not voter.isValidVerificationSalt(saltSocialSec) ):  return outputJsonError( 'Invalid saltSocialSec', self.response )
            
            saltBirthdate = record.get( 'saltBirthdate', None )
            if saltBirthdate and ( not voter.isValidVerificationSalt(saltBirthdate) ):  return outputJsonError( 'Invalid saltBirthdate', self.response )
            
            saltMailedCode = record.get( 'saltMailedCode', None )
            if not voter.isValidVerificationSalt( saltMailedCode ):  return outputJsonError( 'Invalid saltMailedCode', self.response )
            
            verificationHashes = record.get( 'verificationHashes', None )
            if not verificationHashes:  return outputJsonError( 'Empty verificationHashes', self.response )
            if ( 4 < len(verificationHashes) ):  return outputJsonError( 'Length of verificationHashes = ' + len(verificationHashes), self.response )
            for v in verificationHashes:
                if not voter.isValidVerifyHash( v ):  return outputJsonError( 'Invalid verificationHash', self.response )

            # Store voter record
            idRecord = voterRecord.IdRecord( id=identity, city=city, 
                saltPhone=saltPhone, saltSocialSec=saltSocialSec, saltBirthdate=saltBirthdate, saltMailedCode=saltMailedCode, 
                verificationHashes=verificationHashes )
            if not idRecord:  return outputJsonError( 'idRecord is null', self.response )
            idRecord.put()

        outputJson( {'success':True}, self.response )




class LoginPage( webapp2.RequestHandler ):

    def post(self):

        templateFile = 'login.html'

        # Collect inputs
        requestLogId = os.environ.get( conf.REQUEST_LOG_ID )
        responseData = { 'success':False, 'requestLogId':requestLogId, 'errorMessage':'' }
        inputData = urlparse.parse_qs( self.request.body )
        if conf.isDev: logging.debug( 'LoginPage.post() inputData=' + str(inputData) )

        browserFingerprint = getPostParam( inputData, 'fingerprint' )
        applicationId = getPostParam(inputData, 'applicationId')
        requestId = getPostParam(inputData, 'requestId')
        inputSignature = getPostParam(inputData, 'inputSignature')

        name = voter.standardizeName( getPostParam(inputData, 'name') )
        address1 = voter.standardizeAddress1( getPostParam(inputData, 'address1') )
        address2, city = voter.standardizeAddress2( getPostParam(inputData, 'address2') )

        verificationType = getPostParam( inputData, 'verificationType' )
        verificationValue = getPostParam( inputData, 'verificationValue' )

        if not voterRecord.isValidBrowserFingerprint( browserFingerprint ):  browserFingerprint = ''
        responseData['fingerprint'] = browserFingerprint

        if conf.isDev:
            logging.debug( 'LoginPage.post() browserFingerprint=' + str(browserFingerprint) )
            logging.debug( 'LoginPage.post() applicationId=' + str(applicationId) )
            logging.debug( 'LoginPage.post() inputSignature=' + str(inputSignature) )
            logging.debug( 'LoginPage.post() requestId=' + str(requestId) )
            logging.debug( 'LoginPage.post() name=' + str(name) )
            logging.debug( 'LoginPage.post() address1=' + str(address1) )
            logging.debug( 'LoginPage.post() address2=' + str(address2) )
            logging.debug( 'LoginPage.post() verificationType=' + str(verificationType) )
            logging.debug( 'LoginPage.post() verificationValue=' + str(verificationValue) )

        # If input is empty... re-display login page without retrieving records
        responseData.update( {
            'applicationId': nullToEmptyString(applicationId) , 
            'requestId': nullToEmptyString(requestId) , 
            'inputSignature': nullToEmptyString(inputSignature) , 
            'name': nullToEmptyString(name) ,
            'address1': nullToEmptyString(address1) , 
            'address2': nullToEmptyString(address2) , 
            'verificationType': nullToEmptyString(verificationType),
            'verificationValue': nullToEmptyString(verificationValue)
        } )
        if (not name) or (not address1) or (not address2):
            return outputPage( templateFile, responseData, self.response )
        if (not verificationType) or (not verificationValue):
            return outputPage( templateFile, responseData, self.response )

        # Crumb not required, because there is no verification-cookie, verification-data must always be provided

        # Check that requestId is alpha-numeric, not too long... if invalid... login will never succeed
        if (not requestId):  return outputError( 'requestId is null' , self.response )
        if re.search( r'[^A-z0-9\-]' , requestId ):  return outputError( 'requestId has invalid characters' , self.response )
        if len(requestId) > conf.requestIdLengthMax:  return outputError( 'requestId has invalid length=' + str(len(requestId)) , self.response )

        # Retrieve application record
        applicationRecord = application.ApplicationRecord.get_by_id( applicationId )
        if conf.isDev: logging.debug( 'LoginPage.post() applicationRecord=' + str(applicationRecord) )
        if not applicationRecord:  return outputError( 'applicationRecord not found' , self.response )
        if conf.isDev: logging.debug( 'LoginPage.post() applicationRecord.requestSigningSecret=' + str(applicationRecord.requestSigningSecret) )

        # Check input signature... if invalid... login will never succeed
        expectedSignature = security.loginRequestSignature( applicationRecord.requestSigningSecret, requestId, applicationRecord.key.id() )
        if conf.isDev: logging.debug( 'LoginPage.post() expectedSignature=' + str(expectedSignature) )
        if not expectedSignature:  return outputError('expectedSignature is null', self.response)
        if ( inputSignature != expectedSignature ):  return outputError('inputSignature does not match', self.response)

        # Get voter record
        voterIdHash = voter.identityHash( name, address1, address2 )
        if conf.isDev: logging.debug( 'LoginPage.post() voterIdHash=' + str(voterIdHash) )

        voterIdRecord = voterRecord.IdRecord.get_by_id( voterIdHash ) if voterIdHash  else None
        if conf.isDev: logging.debug( 'LoginPage.post() voterIdRecord=' + str(voterIdRecord) )

        # Check client-machine rate-limit
        clientIp = voter.standardizeIpAddress( self.request.remote_addr )
        if conf.isDev: logging.debug( 'LoginPage.post() clientIp=' + str(clientIp) )

        if not clientIp:  return outputError('no clientIp', self.response)
        clientRateRecord = voterRecord.retrieveClientRateLimit( clientIp )
        if conf.isDev: logging.debug( 'LoginPage.post() clientRateRecord=' + str(clientRateRecord) )

        # Update client failure rate for:
        #   incorrect voter identity, to prevent identity hunting
        #   incorrect non-empty verification
        # Do not increase failure rate for rate-limit-denied attempts:
        #   Not necessary to prevent key-cracking
        #   Does not prevent denial-of-service, infinite attempts still possible
        now = int( time.time() )
        if not voterRecord.allowed( clientRateRecord, now, browserFingerprint, voterIdRecord ):
            return outputError('too many login failures', self.response)

        # Retrieve voterRateRecord check voter rate-limit
        voterRateRecord = voterRecord.retrieveVoterRateLimit( voterIdHash ) if voterIdHash  else None
        if not voterRecord.allowed( voterRateRecord, now, browserFingerprint, voterIdRecord ):
            return outputError('too many login failures', self.response)
        if conf.isDev: logging.debug( 'LoginPage.post() voterRateRecord=' + str(voterRateRecord) )

        # If invalid voter identity... update failure rates, re-display login-page
        if not voterIdRecord:
            self.updateRateLimits( False, now, voterIdHash, clientIp, voterRateRecord, clientRateRecord )
            responseData['errorMessage'] = 'No registered voter for this name and address.'
            return outputPage( templateFile, responseData, self.response )

        # Check that voter verification data is a match
        verifyHash = voter.verificationTypeToHash( verificationType, verificationValue, voterIdRecord )
        if conf.isDev: logging.debug( 'LoginPage.post() verifyHash=' + str(verifyHash) )
        verified = ( verifyHash in voterIdRecord.verificationHashes )
        self.updateRateLimits( verified, now, voterIdHash, clientIp, voterRateRecord, clientRateRecord )
        if verified:
            voterRecord.updateSuccessfulBrowser( voterIdRecord, browserFingerprint, now )
            # Display successful response
            # Redirect to application result service, with POST parameters, using javascript or user submit-click
            # (Do not use http code=307, because it sends login input parameters, not login result data.)
            redirectUrl = applicationRecord.returnUrl
            responseData = { 'requestId':requestId , 'redirectUrl':redirectUrl }
            # Derive app-specific voterId from global voterId
            voterAppId = voter.voterAppId( voterIdHash, applicationId )
            responseData['voterId'] = voterAppId
            responseData['requestId'] = requestId
            responseData['city'] = voterIdRecord.city
            responseData['responseSignature'] = security.loginResponseSignature(
                applicationRecord.responseSigningSecret, requestId, applicationId, voterAppId, str(voterIdRecord.city) )
            return outputPage( 'return.html' , responseData , self.response )
        else:
            # Display failure
            responseData['errorMessage'] = 'No verification for registered voter at this name and address.'
            return outputPage( templateFile, responseData, self.response )


    # Modifies and stores voterRateRecord, clientRateRecord
    def updateRateLimits( self, verified, now, voterIdHash, clientIp, voterRateRecord, clientRateRecord ):

        if conf.isDev:
            logging.debug( 'LoginPage.updateRateLimits() verified=' + str(verified) )
            logging.debug( 'LoginPage.updateRateLimits() now=' + str(now) )
            logging.debug( 'LoginPage.updateRateLimits() voterIdHash=' + str(voterIdHash) )
            logging.debug( 'LoginPage.updateRateLimits() clientIp=' + str(clientIp) )
            logging.debug( 'LoginPage.updateRateLimits() voterRateRecord=' + str(voterRateRecord) )
            logging.debug( 'LoginPage.updateRateLimits() clientRateRecord=' + str(clientRateRecord) )

        # Store rate-limit records even for invalid voter-identities, 
        # to prevent bot-net hunting for identities that do rate-limiting.

        voterRateRecord = voterRecord.updateVoterLoginRate( now, verified, voterIdHash, voterRateRecord )
        clientRateRecord = voterRecord.updateClientLoginRate( now, verified, clientIp, clientRateRecord )
        if conf.isDev: logging.debug( 'LoginPage.updateRateLimits() voterRateRecord=' + str(voterRateRecord) )
        if conf.isDev: logging.debug( 'LoginPage.updateRateLimits() clientRateRecord=' + str(clientRateRecord) )
        



class AboutPage( webapp2.RequestHandler ):
    def get(self):
        outputPage( 'about.html', {}, self.response )




def getPostParam( parameters, paramName ):
    return parameters.get( paramName, [None] )[0]

def nullToEmptyString( value ):
    return value if value  else ''



# Modifies httpResponse, then returns null so this function can be returned by http handlers
def outputPage( templateFile, templateValues, httpResponse, errorMessage=None, successMessage=None ):
    if templateValues:
        if errorMessage:  templateValues['errorMessage'] = errorMessage
        if successMessage:  templateValues['successMessage'] = successMessage
    if conf.isDev: logging.debug( 'outputPage() templateFile=' + templateFile )
    if conf.isDev: logging.debug( 'outputPage() templateValues=' + str(templateValues) )

    __setStandardHeaders( httpResponse )
    template = JINJA_ENVIRONMENT.get_template( templateFile )
    html = template.render( templateValues )
    httpResponse.write( html )
    return None

# Modifies httpResponse, then returns null so this function can be returned by http handlers
def outputJsonError( message, httpResponse ):
    return outputJson( {'success':False, 'message':message} , httpResponse )

# Modifies httpResponse, then returns null so this function can be returned by http handlers
def outputJson( data, httpResponse ):
    logging.debug( 'outputJson() data=' + str(data) )
    __setStandardHeaders( httpResponse )
    httpResponse.write( json.dumps(data) )
    return None

# Modifies httpResponse, then returns null so this function can be returned by http handlers
def outputError( message, httpResponse ):
    logging.debug( 'outputError() message=' + message )
    __setStandardHeaders( httpResponse )
    httpResponse.out.write( message )
    return None

def __setStandardHeaders( httpResponse ):
    httpResponse.headers['X-Frame-Options'] = 'deny' 
    httpResponse.headers['Content-Security-Policy'] = "frame-ancestors 'none'"




# Route URLs to page generators
app = webapp2.WSGIApplication(
    [
        ('/admin', AdminPage),
        ('/setVoters', SetVoters),
        ('/login', LoginPage),
        ('/about', AboutPage),
    ],
    debug=True
)

