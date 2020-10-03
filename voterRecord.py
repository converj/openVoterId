# Data-store record for voter


# Import external modules
import logging
import re
import urlparse
# Import app modules
from configOpenVoterId import const as conf
from secretsOpenVoterId import const as secrets
import security
import voter


# If not unit testing... include gCloud code
if __name__ != '__main__':

    from google.appengine.ext import ndb

    # Parent key: none
    # Key: identityHash: long alpha-numeric string
    class IdRecord( ndb.Model ):
        saltPhone = ndb.StringProperty( indexed=False )
        saltSocialSec = ndb.StringProperty( indexed=False )
        saltBirthdate = ndb.StringProperty( indexed=False )
        saltMailedCode = ndb.StringProperty( indexed=False )
        city = ndb.StringProperty( indexed=False )
        verificationHashes = ndb.TextProperty( indexed=False, repeated=True )
        successfulBrowserFingerprints = ndb.JsonProperty( indexed=False, default={} )   # map[ fingerprint -> time ]


    # Parent key: none
    # Key: string: client/voter type + identity
    class RateRecord( ndb.Model ):
        loginFailuresSinceSuccess = ndb.IntegerProperty( default=0 )
        nextAttemptTime = ndb.IntegerProperty( default=0 )  # Needed to know when wait ends
        resetFailuresOnNextAttempt = ndb.BooleanProperty( default=False )
        
        def allowed( self, now ):

            logging.debug( 'RateRecord.allowed() now=' + str(now) + ' nextAttemptTime=' + str(self.nextAttemptTime) 
                + ' nextAttemptTime-now = ' + str(self.nextAttemptTime - now)
                + ' loginFailuresSinceSuccess=' + str(self.loginFailuresSinceSuccess) )

            return (self.nextAttemptTime <= now)


####################################################################################
# Rate-limit functions

def allowed( rateRecord, now, browserFingerprint, voterRecord ):
    if voterRecord  and  ( browserFingerprint in voterRecord.successfulBrowserFingerprints ):  return True
    if not rateRecord:  return True
    return rateRecord.allowed( now )

def updateSuccessfulBrowser( voterIdRecord, browserFingerprint, now ):
    if not isValidBrowserFingerprint( browserFingerprint ):  return
    if not voterIdRecord:  return
    if not now:  return
    voterIdRecord.successfulBrowserFingerprints = { f:t  for f,t in voterIdRecord.successfulBrowserFingerprints.iteritems()  if isValidBrowserFingerprint(f) }
    updateRecent( voterIdRecord.successfulBrowserFingerprints, browserFingerprint, now, 10 )
    if conf.isDev:  logging.debug( 'voterIdRecord.updateSuccessfulBrowser() voterIdRecord=' + str(voterIdRecord) )
    voterIdRecord.put()

def isValidBrowserFingerprint( fingerprint ):
    return fingerprint  and  re.match( r'\A-?\d+\Z' , fingerprint )

# Modifies valueToTime:map[value -> time]
def updateRecent( valueToTime, newValue, newTime, maxValues ):
    # add new value 
    valueToTime[ newValue ] = newTime
    # while we have too many values...
    while len(valueToTime.keys()) > maxValues:
        # remove oldest value
        minTimeValue = min( valueToTime, key=lambda v:__toInt(valueToTime[v], default=0) )
        del valueToTime[ minTimeValue ]

def __toInt( value, default=0 ):
    try:  return int( value )
    except ValueError:  return default



conf.rateRecordTypeClient = 'client'
conf.rateRecordTypeVoter = 'voter'

conf.rateUseDatastore = False  # Turn off persistent storage, and expire records via memcache expiration
conf.rateUseMemcache = True
conf.rateMemcacheTimeout = conf.oneDaySec

# Continuing to login and failing will not keep memcache record alive longer than memcache-expiration, 
# because rate-check only reads memcache, and only memcache-writes update expiration-time


def retrieveClientRateLimit( clientIp ):
    recordId = toRateRecordId( conf.rateRecordTypeClient, clientIp )
    if conf.isDev: logging.debug( 'retrieveClientRateLimit() recordId=' + str(recordId) )
    return RateRecord.get_by_id( recordId, use_datastore=conf.rateUseDatastore, use_memcache=conf.rateUseMemcache, memcache_timeout=conf.rateMemcacheTimeout )

def retrieveVoterRateLimit( voterId ):
    recordId = toRateRecordId( conf.rateRecordTypeVoter, voterId )
    if conf.isDev: logging.debug( 'retrieveVoterRateLimit() recordId=' + str(recordId) )
    return RateRecord.get_by_id( recordId, use_datastore=conf.rateUseDatastore, use_memcache=conf.rateUseMemcache, memcache_timeout=conf.rateMemcacheTimeout )


# Modifies/creates and returns rateRecord
def updateClientLoginRate( now, success, clientIp, rateRecord ):
    return updateLoginRate( now, success, clientIp, conf.rateRecordTypeClient, rateRecord )

def updateVoterLoginRate( now, success, voterId, rateRecord ):
    return updateLoginRate( now, success, voterId, conf.rateRecordTypeVoter, rateRecord )

def updateLoginRate( now, success, recordId, recordType, rateRecord ):

    if not rateRecord and ( recordId and recordType ):
        rateRecord = RateRecord( id=toRateRecordId(recordType, recordId) )

    if not rateRecord:  return None
        
    if success  or rateRecord.resetFailuresOnNextAttempt:
        rateRecord.loginFailuresSinceSuccess = 0
        rateRecord.nextAttemptTime = now
        rateRecord.resetFailuresOnNextAttempt = False
    else:
        # Wait-time proportional to number of failures since last login, until wait > 1day ... then reset fail-count
        failuresSinceSuccess = rateRecord.loginFailuresSinceSuccess
        if (not failuresSinceSuccess) or (failuresSinceSuccess < 0):  failuresSinceSuccess = 0
        rateRecord.loginFailuresSinceSuccess = failuresSinceSuccess + 1

        waitSec = (2 << failuresSinceSuccess)
        if ( waitSec > conf.oneDaySec ):
            rateRecord.nextAttemptTime = now + conf.oneDaySec
            rateRecord.resetFailuresOnNextAttempt = True
        else:
            rateRecord.nextAttemptTime = now + waitSec
            rateRecord.resetFailuresOnNextAttempt = False
    
    # Store record synchronously, because async fails
    if rateRecord:  rateRecord.put( use_datastore=conf.rateUseDatastore, use_memcache=conf.rateUseMemcache, memcache_timeout=conf.rateMemcacheTimeout )
    return rateRecord


def toRateRecordId( recordType, recordId ):
    return '{}_{}'.format( recordType, recordId )



#################################################################################
# Unit test

import unittest

class TestText(unittest.TestCase):

    def testRateLimit( self ):

        class FakeRateRecord:
            def __init__( self, failures=0 ):
                self.loginFailuresSinceSuccess = failures
                self.nextAttemptTime = 0
                self.resetFailuresOnNextAttempt = False

            def put( self, use_datastore=None, use_memcache=None, memcache_timeout=None, use_cache=None ):  pass

        now = 100
        rateRecord = FakeRateRecord( failures=0 )
        success = True
        recordId = 'recordId'
        recordType = 'recordType'
        rateRecord = updateLoginRate( now, success, recordId, recordType, rateRecord )
        self.assertEqual( rateRecord.loginFailuresSinceSuccess, 0 )
        self.assertEqual( rateRecord.nextAttemptTime, now )
        self.assertFalse( rateRecord.resetFailuresOnNextAttempt )

        success = False
        rateRecord = updateLoginRate( now, success, recordId, recordType, rateRecord )
        self.assertEqual( rateRecord.loginFailuresSinceSuccess, 1 )
        self.assertEqual( rateRecord.nextAttemptTime, now+2 )
        self.assertFalse( rateRecord.resetFailuresOnNextAttempt )

        rateRecord = FakeRateRecord( failures=50 )
        success = False
        rateRecord = updateLoginRate( now, success, recordId, recordType, rateRecord )
        self.assertEqual( rateRecord.loginFailuresSinceSuccess, 51 )
        self.assertEqual( rateRecord.nextAttemptTime, now + conf.oneDaySec )
        self.assertTrue( rateRecord.resetFailuresOnNextAttempt )

        success = False
        rateRecord = updateLoginRate( now, success, recordId, recordType, rateRecord )
        self.assertEqual( rateRecord.loginFailuresSinceSuccess, 0 )
        self.assertEqual( rateRecord.nextAttemptTime, now )
        self.assertFalse( rateRecord.resetFailuresOnNextAttempt )

    def testRecentValuesUpdate( self ):
        valueToTime = { '0':0, '1':1, '2':2 }
        maxValues = 5
        updateRecent( valueToTime, '3', 3, maxValues )
        updateRecent( valueToTime, '4', 4, maxValues )
        updateRecent( valueToTime, '5', 5, maxValues )
        updateRecent( valueToTime, '6', 'x', maxValues )
        self.assertEqual( valueToTime, {'1':1, '2':2, '3':3, '4':4, '5':5} )
        self.assertEqual( maxValues, len(valueToTime) )
        self.assertNotIn( 0, valueToTime )


if __name__ == '__main__':
    unittest.main()


