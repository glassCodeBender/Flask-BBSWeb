import CleanMFT
from flask import Flask
from flask_restful import regparse, abort, Api, Resource
# import graphlab

"""
@author j. Alexander
@data 7-9-2017
@version 1.0

This program is a side project. Most of my free time is being spent developing a machine
learning model for determining whether or not a computer has been breached. 

Program Purpose: It's taking a long time to learn how to write an API with Lagom in Scala 
so I decided to write a quick API with Flask. This program will be used
as a prototype for BigBrainSecurity which is written with Apache Spark in Scala. 
"""
# put the data we want to use in JSON format and store it in variable here.

MFTDATA = {
    'result1': {'task': 'build an API'},
    'port_number': {'task': '58434'} # returns a port number that will be used to set up socket.
}

def abort_if_mft_doesnt_exist(mft_id):
    if mft_id not in MFTData:
        abort(404, message="Filtered MFT {} doesn't exist".format(mft_id))

parser = regparse.RequestParser()
parser.add_argument('task')

class MFT(Resource):
    def get(self, mft_id):
        abort_if_mft_doesnt_exist(mft_id)
        return MFTDATA[mft_id]

    def delete(self, mft_id):
        abort_if_mft_doesnt_exist(mft_id)
        del MFTDATA[mft_id]
        return '', 204

    def put(self, mft_id):
        args = parser.parse_args()
        task = {'task': args['task']}
        MFTDATA[mft_id] = task
        return task, 201

# MFTList
# Shows a list of all MFTs, and lets you POST to add new data

class MFTList(Resource):
    def get(self):
        return MFTDATA

    def post(self):
        args = parser.parse_args()
        mft_id = int(max(MFTDATA.keys()).lstrip('mft')) + 1
        mft_id = 'mft%i' % mft_id
        MFTDATA[mft_id] = {'task': args['task']}
        return MFTDATA[mft_id], 201

##
## Actually setup the Api resource routing here
##
api.add_resource(MFTList, '/mft')
api.add_resource(MFT, '/mft/<mft_id>')

if __name__ == '__main__':
    app.run(debug=True)
