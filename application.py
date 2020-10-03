# Data-store record for applications using the login system


# Import external modules
import logging
import re
import urlparse
# Import app modules
from configOpenVoterId import const as conf


# If unit testing... exclude gCloud code
if __name__ != '__main__':
    from google.appengine.ext import ndb

    # Parent key: none
    # Key: applicationId: long random alpha-numeric string
    class ApplicationRecord( ndb.Model ):
        returnUrl = ndb.StringProperty()
        requestSigningSecret = ndb.StringProperty()
        responseSigningSecret = ndb.StringProperty()



def standardizeReturnUrl( urlArg ):
    if not urlArg:  return None
    urlFields = urlparse.urlparse( urlArg )
    scheme = 'http' if (urlFields.scheme == 'http') and re.match('localhost(:\d+)?$' , urlFields.netloc)  else 'https'
    urlStandard = ''.join( [scheme, '://', urlFields.netloc, urlFields.path] )
    return urlStandard;



#################################################################################
# Unit test

import unittest

class TestText(unittest.TestCase):

    def test(self):
    
        url = standardizeReturnUrl( 'http://host:8080/path/path2?k=v&k=v' )
        self.assertEqual( 'https://host:8080/path/path2' , url )

        url = standardizeReturnUrl( 'http://localhost:8080/path/path2?k=v&k=v' )
        self.assertEqual( 'http://localhost:8080/path/path2' , url )
        
        url = standardizeReturnUrl( 'http://localhost/path/path2?k=v&k=v' )
        self.assertEqual( 'http://localhost/path/path2' , url )
        

if __name__ == '__main__':
    unittest.main()

