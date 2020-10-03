# Import standard modules
import logging
import os



class Constants:
    def __setattr__(self, name, value):
        if not self.__dict__.has_key(name):  self.__dict__[name] = value  # Do not allow value overwrite

const = Constants()

const.clientMaxLoginFailsPerDay = 10
const.voterMaxLoginFailsPerDay = 10
const.oneDaySec = 86400
const.hundredDaysSec = 8640000

const.inputVotersLengthMax = 100
const.requestIdLengthMax = 100

# Environment variable names
const.REQUEST_LOG_ID = 'REQUEST_LOG_ID'

const.isDev = os.path.isfile('devInstance.txt')
logging.debug( 'isDev={}'.format(const.isDev) )

