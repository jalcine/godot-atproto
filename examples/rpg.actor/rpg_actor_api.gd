extends Node
## Wraps the public rpg.actor REST API: https://rpg.actor/dev-guide
##
## Ported from the RpgActor autoload in TechTastic/godot-rpg-actor
## (https://github.com/TechTastic/godot-rpg-actor, MIT License, Copyright (c)
## 2026 TechTastic). Only the RpgActor logic is kept here; that project's
## ATProto/ATProtoOAuth/XRPC autoloads are not needed because every endpoint
## below is an unauthenticated call to rpg.actor's own aggregator API, not an
## AT Protocol XRPC call to a PDS. Login, records, and signed XRPC calls in
## this repo go through the AtprotoClient GDExtension class instead.

const MAX_BODY_SIZE: int = 10 * 1024 * 1024 ## 10 MB
const MAX_REDIRECTS: int = 3

var base_api: String:
	get: return ProjectSettings.get_setting("rpg_actor/api", "https://rpg.actor/api")

var _sprite_cache: Dictionary = {}

## Returns all actors, or full cached data if [param full] is true.
## [br][br]
## [code lang=text]GET /api/actors[/code]
## [br]
## [code lang=text]GET /api/actors/full[/code]
func get_actors(full: bool = false) -> Dictionary:
	var endpoint := "actors"
	if full:
		endpoint += "/full"
	return await _http_request("%s/%s" % [base_api, endpoint])

## Searches actors by handle or display name (min 2 chars, max 10 results).
## [br][br]
## [code lang=text]GET /api/search?q=...[/code]
func search_actors(query: String) -> Array:
	if query == null or query.is_empty():
		return []
	if query.length() < 2:
		push_error("Query must be atleast 2 characters in length!")
		return []
	return await _http_request("%s/%s%s" % [base_api, "search?q=", query.uri_encode()])

## Registry summary: actor count, system count, master authority count.
## [br][br]
## [code lang=text]GET /api/stats[/code]
func metrics() -> Dictionary:
	return await _http_request("%s/%s" % [base_api, "stats"])

## Service health, actor/master counts, and uptime.
## [br][br]
## [code lang=text]GET /api/health[/code]
func health() -> Dictionary:
	return await _http_request("%s/%s" % [base_api, "health"])

## Master validations for a player (add &verify=true to check live).
## [br][br]
## [code lang=text]GET /api/masters?player=did:...[/code]
func get_masters_for_player(player_did: String) -> Dictionary:
	if not validate_did(player_did): return {}
	return await _http_request("%s/%s%s" % [base_api, "masters?player=", player_did.uri_encode()])

## All players validated by a specific master/GM.
## [br][br]
## [code lang=text]GET /api/masters/by-authority?authority=did:...[/code]
func get_masters_by_authority(authority_did: String) -> Dictionary:
	if not validate_did(authority_did): return {}
	return await _http_request("%s/%s%s" % [base_api, "masters/by-authority?authority=", authority_did.uri_encode()])

## Standard 144x192 PNG sprite sheet for any actor.
## [br][br]
## [color=gold]Warning[/color]: rpg.actor allows custom sprites of any size which may produce inaccurate spritesheets.
## [br][br]
## [code lang=text]GET /api/sprite/normalized?did=...[/code]
func get_sprite(did: String) -> PackedByteArray:
	if not validate_did(did): return PackedByteArray()
	var data = await _http_request("%s/%s%s" % [base_api, "sprite/normalized?did=", did.uri_encode()])
	return _sprite_cache.get_or_add(did, data)

## Generated 1200x630 Open Graph card image.
## [br][br]
## [code lang=text]GET /api/og/image?id=...[/code]
func get_open_graphic_card(did: String) -> PackedByteArray:
	if not validate_did(did): return PackedByteArray()
	return await _http_request("%s/%s%s" % [base_api, "og/image?id=", did.uri_encode()])

## Equipment index summary.
## [br][br]
## [code lang=text]GET /api/equipment[/code]
func get_equipment() -> Dictionary:
	return await _http_request("%s/%s" % [base_api, "equipment"])

## All items and gives for a player.
## [br][br]
## [code lang=text]GET /api/equipment?player=did:...[/code]
func get_equipment_by_player(did: String) -> Dictionary:
	if not validate_did(did): return {}
	return await _http_request("%s/%s%s" % [base_api, "equipment?player=", did.uri_encode()])

## All gives issued by a provider.
## [br][br]
## [code lang=text]GET /api/equipment?provider=did:...[/code]
func get_equipment_by_provider(did: String) -> Dictionary:
	if not validate_did(did): return {}
	return await _http_request("%s/%s%s" % [base_api, "equipment?provider=", did.uri_encode()])

## Current pricing tiers and PDS status.
## [br][br]
## [code lang=text]GET /api/creator/pricing[/code]
func get_creator_pricing() -> Dictionary:
	return await _http_request("%s/%s" % [base_api, "creator/pricing"])

## Checks if a DID is a registered creator.
## [br][br]
## [code lang=text]GET /api/creator/check?did=...[/code]
func check_creator(did: String) -> bool:
	if not validate_did(did): return false
	var data = await _http_request("%s/%s%s" % [base_api, "creator/check?did=", did.uri_encode()])
	return data.get("isCreator", false)

## Triggers an immediate cache refresh after a stat/sprite mutation.
## [br][br]
## [code lang=text]POST /api/refresh-actor[/code]
## @experimental
func refresh_actor(did: String) -> Variant:
	if not validate_did(did): return null
	var data = await _http_request("%s/%s" % [base_api, "refresh-actor"], HTTPClient.METHOD_POST, [
		"Content-Type: application/json"
	], {
		"did": did
	})
	if data is Dictionary and data.get("status") == "ok":
		_sprite_cache.erase(did)
	return data

## Validates an AT Protocol handle (at least 2 dot-separated segments, alphanumeric + . -).
func validate_handle(handle: String) -> bool:
	var parts := handle.split(".")
	if parts.size() < 2:
		push_error("Provided handle %s is not a valid AT protocol handle!" % [handle])
		return false
	var valid_chars := RegEx.new()
	valid_chars.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*$")
	if not valid_chars.search(handle):
		push_error("Provided handle %s contains invalid characters!" % [handle])
		return false
	return true

## Validates an AT Protocol DID (did:plc or did:web).
func validate_did(did: String) -> bool:
	var parts := did.split(":")
	if parts.size() < 3 or parts[0] != "did":
		push_error("Provided DID %s is not a valid AT protocol DID string!" % [did])
		return false
	if parts[1] != "plc" and parts[1] != "web":
		push_error("Provided DID %s uses unsupported method '%s' (expected plc or web)" % [did, parts[1]])
		return false
	return true

## Minimal HTTP+JSON helper for rpg.actor's REST API. Trimmed from the
## upstream XRPC autoload: no DPoP/OAuth forwarding, since none of the calls
## above touch a user's PDS.
func _http_request(url: String, method: HTTPClient.Method = HTTPClient.METHOD_GET, headers: PackedStringArray = [], body: Dictionary = {}) -> Variant:
	if not url.begins_with("https://"):
		push_error("RpgActor: Refusing non-HTTPS URL: %s" % [url])
		return {}

	var raw_body := PackedByteArray()
	if !body.is_empty():
		raw_body = JSON.stringify(body).to_utf8_buffer()

	var req := HTTPRequest.new()
	req.download_chunk_size = 65536
	req.max_redirects = MAX_REDIRECTS
	req.body_size_limit = MAX_BODY_SIZE
	add_child(req)
	await get_tree().process_frame
	req.request_raw(url, headers, method, raw_body)
	var result = await req.request_completed
	req.queue_free()

	var status: int = result[0]
	var code: int = result[1]
	var response_headers: PackedStringArray = result[2]
	var response_body: PackedByteArray = result[3]

	if status != HTTPRequest.RESULT_SUCCESS:
		push_warning("RpgActor/HTTP: Request to %s failed with status %d" % [url, status])
		return {}

	# Return raw bytes for image responses (sprites, OG cards)
	for header: String in response_headers:
		if header.to_lower().contains("content-type: image/"):
			return response_body

	var body_text := response_body.get_string_from_utf8()
	if body_text.is_empty():
		if code >= 200 and code < 300:
			return {}
		push_warning("RpgActor/HTTP: %s returned HTTP %d with empty body" % [url, code])
		return {}

	var res = JSON.parse_string(body_text)
	if res == null:
		push_warning("RpgActor/HTTP: Failed to parse JSON from %s" % [url])
		return {}

	if code < 200 or code >= 300:
		var warning := "RpgActor/HTTP: %s returned HTTP Response Code %d" % [url, code]
		if res is Dictionary:
			var error_msg: String = res.get("error", "")
			if not error_msg.is_empty():
				warning += " with error message: %s" % [error_msg]
		push_warning(warning)
		return {}

	return res
