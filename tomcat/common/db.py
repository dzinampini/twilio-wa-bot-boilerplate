from bson.objectid import ObjectId

def search_by_id(collection, search_id):
	return collection.find_one({'_id': ObjectId(search_id)})

def search_all(collection):
	return [i for i in collection.find({})]

def search_with_filter(collection, filter, return_fields=None):
	if return_fields is None:
		res = collection.find(filter)
	else:
		res = collection.find(filter, return_fields)
	return [item for item in res]

def insert_one(collection, data):
	result = collection.insert_one(data)
	return result.inserted_id

def get_distinct(collection, field_name):
	return [i for i in collection.distinct(field_name)]