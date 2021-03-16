from tomcat import mongo

cln_tokens = mongo.db.revoked_tokens

class RevokedTokenDao():
    
  @classmethod
  def is_jti_blacklisted(jti):
    query = cln_tokens.find_one({'jti': jti})
    return bool(query) 