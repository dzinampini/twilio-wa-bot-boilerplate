from tomcat import mongo

cln_users = mongo.db.users

class UserDao():

  @classmethod
  def get_all_users(cls):
    return [i for i in cln_users.find({})]

  @classmethod
  def users_by_role(cls, role):
    return [i for i in cln_users.find({'roles':role})]
