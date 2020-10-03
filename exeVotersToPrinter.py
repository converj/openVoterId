# Executable to clean voter data for postcard printer
# Remove private data, and separate voter's first name


# Import external modules
import argparse


# Handle command-line arguments.
parser = argparse.ArgumentParser()
parser.add_argument( '--file', help='Path to file containing voter records as tab-separated-values', required=True )
args = parser.parse_args()

keepFieldNames = ['name', 'addressStreet', 'addressCity', 'code']

with open( args.file ) as inStream:
    # Read headers, print headers
    schemaLine = inStream.readline()
    schema = schemaLine.strip('\n\r').split('\t')
    print( '\t'.join( keepFieldNames + ['nameFirst'] ) )

    # Collect indices of fields to keep
    fieldNameToIndex = { schema[i]:i  for i in range(len(schema)) }
    keepFieldIndices = [ fieldNameToIndex[n]  for n in keepFieldNames ]

    # For each record...
    for line in inStream:
        lineFields = line.strip('\n\r').split('\t')
        # Print kept fields, first-name
        keepFields = [ lineFields[i]  for i in keepFieldIndices ]
        names = lineFields[ fieldNameToIndex['name'] ].split(' ')
        print(  '\t'.join( keepFields + [names[0]] )  )



