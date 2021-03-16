from tomcat import mongo
from bson.objectid import ObjectId

cln_sessions = mongo.db.sessions

class SessionsDao():
  @classmethod
  def get(cls, status, client):
    filters = {
      'status': 'active',
      'client': client
    }
    return cln_sessions.find_one(filters)

  @classmethod
  def get_by_id(cls, get_id):
    return cln_sessions.find_one({'_id': ObjectId(get_id)})

  @classmethod
  def get_all(cls):
  	return [i for i in cln_sessions.find()]

  @classmethod
  def add(cls, data):
  	return cln_sessions.insert_one(data).inserted_id

  @classmethod
  def update(cls, update_id, update_data):
    return cln_sessions.update({'_id': ObjectId(update_id)}, {'$set': update_data})

  @classmethod
  def delete(cls, delete_id):
    return cln_sessions.remove({'_id': ObjectId(delete_id)})