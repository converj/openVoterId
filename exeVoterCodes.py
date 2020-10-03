# Executable to append voter-codes to voter records


# Import external modules
import argparse
import random
# Import app modules
import security



# Handle command-line arguments.
parser = argparse.ArgumentParser()
parser.add_argument( '--file', help='Path to file containing voter records as tab-separated-values', required=True )
args = parser.parse_args()

with open( args.file ) as inStream:
    # Read headers, print headers
    schemaLine = inStream.readline()
    schema = schemaLine.strip('\n\r').split('\t')
    print( '\t'.join( schema + ['code'] ) )

    # For each record...
    for line in inStream:
        line = line.strip('\n\r')
        # Print line plus code
        code = security.newVoterCode()
        print( line + '\t' + code )



