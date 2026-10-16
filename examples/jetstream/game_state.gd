extends Node

# Sampled posts, carried from the loading scene into the guessing scene.
# posts_by_did: DID -> Array[String] of non-empty post texts.
# names_by_did: DID -> profile displayName (DID itself when unavailable).
var posts_by_did: Dictionary = {}
var names_by_did: Dictionary = {}


func authors() -> Array[String]:
	var result: Array[String] = []
	for did in posts_by_did:
		result.append(did)
	return result


func display_name(did: String) -> String:
	return names_by_did.get(did, did)
