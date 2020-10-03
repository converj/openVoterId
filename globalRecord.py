# Single data-store record for global settings


# Import external modules
from google.appengine.ext import ndb
import logging
# Import app modules
from configOpenVoterId import const as conf
from secretsOpenVoterId import const as secrets
import security


conf.GLOBAL_RECORD_KEY = 'GLOBAL'



class GlobalRecord( ndb.Model ):
    adminPassword = ndb.StringProperty( indexed=False )



def hasAdminPassword( ):
    record = GlobalRecord.get_by_id( conf.GLOBAL_RECORD_KEY )
    if conf.isDev:  logging.debug( 'hasAdminPassword() record=' + str(record) )
    return bool( record  and  record.adminPassword )


def setAdminPassword( newPassword ):
    if conf.isDev:  logging.debug( 'setAdminPassword() newPassword=' + str(newPassword) )
    if not newPassword:  return False

    record = GlobalRecord.get_by_id( conf.GLOBAL_RECORD_KEY )
    if conf.isDev:  logging.debug( 'setAdminPassword() record=' + str(record) )
    if record  and  record.adminPassword:  return False

    newPasswordHash = security.hashForPassword( secrets.adminPasswordSalt, newPassword )
    if conf.isDev:  logging.debug( 'setAdminPassword() newPasswordHash=' + str(newPasswordHash) )
    if conf.isDev:  logging.debug( 'setAdminPassword() isValidHashForPassword(newPasswordHash)=' + str(security.isValidHashForPassword(newPasswordHash)) )
    if not security.isValidHashForPassword( newPasswordHash ):  return False

    if not record:
        record = GlobalRecord( id=conf.GLOBAL_RECORD_KEY )
    record.adminPassword = newPasswordHash
    if conf.isDev:  logging.debug( 'setAdminPassword() record=' + str(record) )
    recordKey = record.put()
    if conf.isDev:  logging.debug( 'setAdminPassword() recordKey=' + str(recordKey) )

    return recordKey


def checkAdminPassword( inputPassword ):
    if conf.isDev:  logging.debug( 'checkAdminPassword() inputPassword=' + str(inputPassword) )

    record = GlobalRecord.get_by_id( conf.GLOBAL_RECORD_KEY )
    if conf.isDev:  logging.debug( 'checkAdminPassword() record=' + str(record) )
    if not record:  return False
    if not record.adminPassword:  return False

    inputPasswordHash = security.hashForPassword( secrets.adminPasswordSalt, inputPassword )
    if conf.isDev:  logging.debug( 'checkAdminPassword() inputPasswordHash=' + str(inputPasswordHash) )
    if not security.isValidHashForPassword( inputPasswordHash ):  return False
    return ( inputPasswordHash == record.adminPassword )

