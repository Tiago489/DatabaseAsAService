#imports Flask (runs the app on an instance of the Flask object), jsonify and request handle the requests made as a json format file for mongo
from flask import Flask, jsonify, request
#imports from flask_restful the Api and Resource (creates a class for the services used by the app)
from flask_restful import Api, Resource
#pymongo and mongoClient both provides aditional functionality on how to connect to mongo
from pymongo import MongoClient
#import bcrypt for hashing passwords
import bcrypt

#define the application
app = Flask(__name__)
#initiates the Api services, which needs to be initiated alongside the application
api = Api(app)
#connects to mongo and runs it at its default port
client = MongoClient("mongodb://db:27017")
db = client.SentencesDatabase
users = db["Users"]

def verifyPw(username, password):
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def countTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]

    return tokens

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Sentence": "",
            "Tokens": 10
        })

        retJson = {
            "status":200,
            "message":"You have successfully registered to use the API"
        }

        return jsonify(retJson)

class Store(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        sentence = postedData["sentence"]

        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
            "status": 302,
            "message": "Incorrect Password"
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)

        if num_tokens <= 0:
            retJson = {
                "status:": 303,
                "message": "You are out of tokens"
            }
            return jsonify(retJson)


        users.update({
            "Username": username
        }, {
            "$set":{
                "Sentence": sentence,
                "Tokens": num_tokens - 1
            }
        })

        retJson = {
            "status": 200,
            "message": "Sentence stored successfully"
        }
        return jsonify(retJson)


class Get(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status": 302,
                "message": "Incorrect Password"
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)

        if num_tokens <= 0:
            retJson = {
                "status:": 303,
                "message": "You are out of tokens"
            }
            return jsonify(retJson)

        users.update({
            "Username": username
        }, {
            "$set":{
                "Tokens": num_tokens - 1
            }
        })

        sentence = users.find({
            "Username": username
        })[0]["Sentence"]

        retJson = {
            "status": 200,
            "sentence": sentence
        }

        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Store, '/store')
api.add_resource(Get, '/get')

if __name__=="__main__":
    app.run(host='0.0.0.0')
