# Import external modules
import base64
import hmac
import hashlib
import json
import logging
import os
import random
import re
import time
import urlparse
# Import app modules
from configOpenVoterId import const as conf
from secretsOpenVoterId import const as secrets


systemRandom = random.SystemRandom()

def newVoterCode( ):
    codeCharacters = '0123456789abcdefghijklmnopqrstuvwxyz'
    codeLength = 6
    code = ''.join(  [ systemRandom.choice(codeCharacters) for r in range(codeLength) ]  )
    return code
    

# Require 4096-bit secret-keys
# 10+26+26+2=64 characters = 6 bits
# 4096 bits = (64 characters) * 683
def randomStringWithLength( length ):
    return toBase64( os.urandom((length * 6) / 8) )  # Adjust length by 6-bit-base-64 / 8-bit-bytes

def toBase64( bytes ):
    # After alpha-numeric, need another 2 typeable ascii-7 characters, not delimiters and not URI-reserved: ~. or -_
    # No trailing "=" so long as bytes and base-64-characters co-terminate
    return base64.b64encode( bytes, '~.' )

def isValidRandomString( s ):
    return  s  and  re.match( r'^[A-Za-z0-9~.]+$' , s )



def hash( value ):
    hasher = hashlib.sha512()
    hasher.update( value )
    return base64.b32encode( hasher.digest() )



def postVoterSignSignature( data ):
    if not data:  return None
    return hashForSignature( secrets.postVoterSignSecret, json.dumps(data, sort_keys=True) )

def loginRequestSignature( applicationRequestSigningSecret, requestId, applicationId ):
    if (not requestId) or (not applicationId) or (not applicationRequestSigningSecret):  return None
    return hashForSignature( applicationRequestSigningSecret , requestId + applicationId )

def loginResponseSignature( applicationResponseSigningSecret, requestId, applicationId, voterId, city ):
    if (not requestId) or (not applicationId) or (not voterId) or (not city) or (not applicationResponseSigningSecret):
        return None
    return hashForSignature( applicationResponseSigningSecret , requestId + applicationId + voterId + city )



def hashForSignature( secret, data ):
    return base64.b32encode( hmac.new(secret, data, digestmod=hashlib.sha512).digest() )

def isValidHashForSignature( h ):
    # (512 bits) = (64 bytes) = (103 base-32-characters) + (1 padding-character)
    return  h  and  ( len(h) == 104 )  and  isValidBase32( h )

def isValidBase32( text ):
    # "0" and "1" not allowed by default, because of visual ambiguity
    return  text  and  re.match( r'\A[A-Z2-9]+=*\Z' , text )



def hashForPassword( salt, password ):
    # Scrypt / bcrypt would be better, but not available in python 2.7
    iterations = 30000   # Ideally 100000, but that is slow
    salt = str( salt )
    password = str( password )
    numBytes = 128
    h = hashlib.pbkdf2_hmac( 'sha256', password.encode('utf-8'), salt, iterations, dklen=numBytes )
    h = base64.b32encode( h )
    return h

def isValidHashForPassword( h ):
    return  h  and  isValidBase32( h )  and  (len(h) == 208)




#################################################################################
# Unit test

import unittest

class TestSecurity( unittest.TestCase ):

    def test_randomStringWithLength( self ):
    
        targetLength = 10000
        r = randomStringWithLength( targetLength )
        self.assertEqual( len(r), targetLength )
        self.assertTrue( re.match( r'[a-zA-Z0-9~.]' , r ) )

        for i in range(1000):
            self.assertTrue(  isValidRandomString( randomStringWithLength(100) )  )


    def test_hash( self ):
        h = hash( 'the quick orange fox jumped over the lazy brown dog' )
        self.assertEqual( len(h), 104 )  # 64-bytes = 103-base-32-characters + 1-padding-character
        self.assertTrue( isValidBase32(h) )


    def test_hashForSignature( self ):
    
        data = 'the lazy fox'
        secret = 'quick brown dog'
        h = hashForSignature( secret, data )
        self.assertTrue( isValidHashForSignature(h) )

        for i in range(1000):
            self.assertTrue(  isValidHashForSignature( hashForSignature(str(i), data) )  )


    def test_hashForPassword( self ):
        for i in range(10):
            self.assertTrue(  isValidHashForPassword( hashForPassword(str(i), 'password') )  )


if __name__ == '__main__':
    unittest.main()

