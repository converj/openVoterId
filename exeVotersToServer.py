# Executable to send voter data to server


# Import external modules
import argparse
import getpass
import json
import logging
import requests
import sys
import urllib
import urlparse
# Initialize logger before any logging calls
logging.basicConfig( stream=sys.stdout, level=logging.DEBUG, format='%(filename)s %(funcName)s():  %(message)s' )
# Import application modules
from configOpenVoterId import const as conf
from secretsOpenVoterId import const as secrets
import security
import voter




# Handle command-line arguments.
parser = argparse.ArgumentParser()
parser.add_argument( '--file' , help='Path to file containing voter records as tab-separated-values', required=True )
parser.add_argument( '--public' , help='Send to public server' , action='store_true' )
args = parser.parse_args()


batchSize = 5
domainUrl = 'https://openvoterid.net'  if args.public  else 'http://localhost:8081'
domainUrlFields = urlparse.urlparse( domainUrl )



class Verification( object ):
    def __init__( self, data=None, salt=None, hash=None ):  self.data = data;  self.salt = salt;  self.hash = hash;



def main():

    logging.debug( '\n' )
    logging.debug( 'domainUrl=' + str(domainUrl) )
    logging.debug( '\n' )

    # Read admin password from input stream
    passwordInput = getpass.getpass('Admin password')

    with open( args.file ) as inStream:
        # Read headers, print headers
        schemaLine = inStream.readline()
        schema = schemaLine.strip('\n\r').split('\t')
        fieldNameToIndex = { schema[i]:i  for i in range(len(schema)) }
        logging.debug( 'fieldNameToIndex=' + str(fieldNameToIndex) )

        # For each record...
        batch = []
        for line in inStream:
            lineFields = line.strip('\n\r').split('\t')
            logging.debug( '' )
            logging.debug( 'lineFields=' + str(lineFields) )

            # Standardize fields
            name = voter.standardizeName( lineFields[ fieldNameToIndex['name'] ] )
            addressStreet = voter.standardizeAddress1( lineFields[ fieldNameToIndex['addressStreet'] ] )
            addressCity, city = voter.standardizeAddress2( lineFields[ fieldNameToIndex['addressCity'] ] )
            phone = voter.standardizePhone( lineFields[ fieldNameToIndex['phone'] ] )
            ssn = voter.standardizeSsn( lineFields[ fieldNameToIndex['socialSecurity'] ] )
            birthdate = voter.standardizeDate( lineFields[ fieldNameToIndex['birthDate'] ] )
            mailedCode = voter.standardizeMailedCode( lineFields[ fieldNameToIndex['code'] ] )

            logging.debug( 'name=' + str(name) )
            logging.debug( 'addressStreet=' + str(addressStreet) )
            logging.debug( 'addressCity=' + str(addressCity) )
            logging.debug( 'city=' + str(city) )
            logging.debug( 'phone=' + str(phone) )
            logging.debug( 'ssn=' + str(ssn) )
            logging.debug( 'birthdate=' + str(birthdate) )
            logging.debug( 'mailedCode=' + str(mailedCode) )

            # For each validation-data, generate salt and hash
            # For public site, for now, only use mailed-code for verification
            identity = voter.identityHash( name, addressStreet, addressCity )
            verifyPhone     = Verification() if args.public  else Verification( data=phone )
            verifySocialSec = Verification() if args.public  else Verification( data=ssn )
            verifyBirthdate = Verification() if args.public  else Verification( data=birthdate )
            verifyMailedCode = Verification( data=mailedCode )
            for v in [ verifyPhone, verifySocialSec, verifyBirthdate, verifyMailedCode ]:
                if (not v.data):  continue
                v.salt = security.randomStringWithLength( conf.saltVerificationLength )
                v.hash = voter.verifyHash( v.salt, identity, v.data )

            voterRecord = { 
                'identity': identity, 
                'city': city, 

                'saltPhone': verifyPhone.salt,
                'saltSocialSec': verifySocialSec.salt,
                'saltBirthdate': verifyBirthdate.salt,
                'saltMailedCode': verifyMailedCode.salt,

                'verificationHashes': [ v.hash  for v in [verifyPhone, verifySocialSec, verifyBirthdate, verifyMailedCode]  if v.hash ]
            }

            # Collect records for batch-sending to server
            batch.append( voterRecord )
            # Send full batch to server
            if ( len(batch) >= batchSize ):
                batch = sendBatch( batch, passwordInput )


    # Send remaining records to server
    if ( len(batch) > 0 ):
        batch = sendBatch( batch, passwordInput )



def sendBatch( batch, passwordInput ):
    sendData = { 'records':batch, 'adminSecret':secrets.adminSecret, 'adminPassword':passwordInput }
    sendData['signature'] = security.postVoterSignSignature( sendData )

    resultData = postRequest( sendData, domainUrl + '/setVoters' )
    if not resultData.get( 'success', False ):
        logging.debug( 'not resultData.success' )
        exit(-1)
    
    return []


# Send data, return result data
def postRequest( data, url ):
    logging.debug( 'postRequest() data=' + str(data) )
    postDataStr = json.dumps( data )
    httpReq = requests.post( url, data=postDataStr )
    logging.debug( 'httpReq.status_code=' + str(httpReq.status_code) )
    logging.debug( 'httpReq.reason=' + str(httpReq.reason) )
    logging.debug( 'httpReq.text=' + str(httpReq.text) )
    if httpReq.status_code != 200:
        logging.debug( 'httpReq.status_code=' + str(httpReq.status_code) )
        exit(-1)
    resultData = json.loads( httpReq.text )
    logging.debug( 'resultData=' + str(resultData) )
    return resultData


main()

