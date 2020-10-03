# Data-store record

# Import external modules
import logging
import re
import urlparse
# Import app modules
from configOpenVoterId import const as conf
from secretsOpenVoterId import const as secrets
import security


conf.saltVerificationLength = 100

def verificationTypeToHash( verificationType, verificationValue, voterIdRecord ):
    voterId = voterIdRecord.key.id()
    if ( verificationType == 'phone' ):
        return verifyHash( voterIdRecord.saltPhone, voterId, standardizePhone(verificationValue) )
    elif ( verificationType == 'socialSecurity' ):
        return verifyHash( voterIdRecord.saltSocialSec, voterId, standardizeSsn(verificationValue) )
    elif ( verificationType == 'birthdate' ):
        return verifyHash( voterIdRecord.saltBirthdate, voterId, standardizeDate(verificationValue) )
    elif ( verificationType == 'mailedCode' ):
        return verifyHash( voterIdRecord.saltMailedCode, voterId, standardizeMailedCode(verificationValue) )
    return None



####################################################################################
# Voter-ID functions

def newVerificationSalt( ):
    return security.randomStringWithLength( conf.saltVerificationLength )

def isValidVerificationSalt( salt ):
    return salt  and  ( len(salt) == conf.saltVerificationLength ) and  re.match( r'\A[A-z0-9~.]+=?=?\Z' , salt )


def identityHash( name, address1, address2 ):
    if (not name) or (not address1) or (not address2):  return None
    return security.hashForSignature( secrets.voterIdSalt , name + address1 + address2 )

def isValidIdentityHash( identity ):
    return identity  and  security.isValidHashForSignature( identity )


def verifyHash( voterSalt, voterId, verifyInfo ):
    if not voterSalt:  return None
    if not voterId:  return None
    if not verifyInfo:  return None
    return security.hashForPassword( secrets.voterVerifySalt + voterSalt , voterId + verifyInfo )

def isValidVerifyHash( h ):
    return h  and  security.isValidHashForPassword( h )

# Voter identity per application
def voterAppId( voterId, applicationId ):
    return security.hash( secrets.voterAppIdSalt + voterId + applicationId )




####################################################################################
# Standardizing voter info

def standardizeIpAddress( ipAddress ):  return ipAddress

def standardizeName( name ):  return standardizeText( name )


def standardizeAddress1( address ):
    address = standardizeText( address )
    if not address:  return None
    address = re.sub( r' avenue(|\d+)' ,    r' ave\1' , address )  # Match street full name and unit number
    address = re.sub( r' boulevard(|\d+)' , r' blvd\1' , address )
    address = re.sub( r' circle(|\d+)' ,    r' cir\1' , address )
    address = re.sub( r' court(|\d+)' ,     r' ct\1' , address )
    address = re.sub( r' drive(|\d+)' ,     r' dr\1' , address )
    address = re.sub( r' expressway(|\d+)' , r' expy\1' , address )
    address = re.sub( r' freeway(|\d+)' ,   r' fwy\1' , address )
    address = re.sub( r' highway(|\d+)' ,   r' hwy\1' , address )
    address = re.sub( r' lane(|\d+)' ,      r' ln\1' , address )
    address = re.sub( r' parkway(|\d+)' ,   r' pkwy\1' , address )
    address = re.sub( r' road(|\d+)' ,      r' rd\1' , address )
    address = re.sub( r' route(|\d+)' ,     r' rte\1' , address )
    address = re.sub( r' street(|\d+)' ,    r' st\1' , address )
    return address

def standardizeAddress2( address ):
    address = standardizeText( address )
    if not address:  return None, None
    matches = re.search( r'([a-z ]+ [a-z][a-z]) \d+$' , address )
    city = matches.group(1) if matches  else None
    return address, city

def standardizeCity( city ):  return standardizeText( city )


def standardizeText( text ):
    if not text:  return None
    text = re.sub( r'[\'\-]' , '' , text )  # Remove apostrophe and dash
    text = re.sub( r'[^A-z0-9]' , ' ' , text )  # All non-alpha-numeric to space
    text = text.strip()
    text = re.sub( r'  +' , ' ' , text )  # Compress whitespace
    text = text.lower()
    return text


def standardizeDate( date ):  return standardizeInteger( date )

def standardizeSsn( ssn ):  return standardizeInteger( ssn )

def standardizePhone( phone ):
    phone = standardizeInteger( phone )
    if not phone:  return None
    phone = re.sub( r'^1' , '' , phone )  # Remove leading 1
    return phone

def standardizeInteger( text ):
    return re.sub( r'[^0-9]' , '' , text ) if text  else None

def standardizeMailedCode( text ):
    return re.sub( r'[^0-9A-z]' , '' , text ) if text  else None



#################################################################################
# Unit test

import unittest
import sys

class TestVoter( unittest.TestCase ):

    def testStandardize( self ):

        self.assertEqual( '234567890', standardizePhone('123-456-7890') )
        self.assertEqual( '987657890', standardizeSsn('987-65-7890') )
        self.assertEqual( '19600101', standardizeDate('1960-01-01') )
    
        text = standardizeText( "I am John O'Connor of Isle De-Something" )
        self.assertEqual( "i am john oconnor of isle desomething", text )

        self.assertEqual( '123 some st 34', standardizeAddress1('123 Some street #34') )
        self.assertEqual( '111 central expy', standardizeAddress1('111 Central expressway') )
        
        address2, city = standardizeAddress2( 'st. Louis IL 12345-67890' )
        self.assertEqual( 'st louis il 1234567890', address2 )
        self.assertEqual( 'st louis il', city )


    def testSalt( self ):
        for i in range(1000):
            self.assertTrue(  isValidVerificationSalt( newVerificationSalt() )  )


    def testIdentity( self ):
        for i in range(1000):
            name = 'name'
            address1 = str(i) + ' main street'
            address2 = 'city ST 12345'
            self.assertTrue(  isValidIdentityHash( identityHash(name, address1, address2) )  )

    def test_verifyHash( self ):
        for i in range(10):
            voterSalt = str(i)
            voterId = 'blah'
            verifyInfo = 'whatever'
            self.assertTrue(  isValidVerifyHash( verifyHash(voterSalt, voterId, verifyInfo) )  )
        

if __name__ == '__main__':
    logging.basicConfig( stream=sys.stdout, level=logging.DEBUG )
    unittest.main()

